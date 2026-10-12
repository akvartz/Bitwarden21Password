package providercrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	// MaxBitwardenEnvelopeBytes bounds envelope strings before any decoding or KDF.
	// The caller must also bound the original JSON, including structural overhead.
	MaxBitwardenEnvelopeBytes   = 32 << 20
	MaxBitwardenPlaintextBytes  = 32 << 20
	maxBitwardenPasswordBytes   = 1 << 20
	maxBitwardenSaltBytes       = 1024
	maxBitwardenValidationBytes = 4096
	minPBKDF2Iterations         = 5000
	maxPBKDF2Iterations         = 2_000_000
	minArgon2Iterations         = 2
	maxArgon2Iterations         = 10
	minArgon2MemoryMiB          = 16
	maxArgon2MemoryMiB          = 256
	maxArgon2Parallelism        = 16
	maxArgon2MemoryPassesMiB    = 768
)

// BitwardenEnvelope is the password-protected JSON envelope. JSON parsing and
// duplicate-key checks belong to the caller's strict source parser.
type BitwardenEnvelope struct {
	Encrypted         bool
	PasswordProtected bool
	Salt              string
	KDFType           int
	KDFIterations     int
	KDFMemory         int
	KDFParallelism    int
	Validation        string
	Data              string
}

// UnlockBitwarden unlocks type-2 AES-256-CBC/HMAC-SHA256 password-protected
// exports using PBKDF2-SHA256 or Argon2id v1.3. It authenticates both records
// before decrypting either and returns no plaintext on failure. Password bytes
// are interpreted as exact UTF-8, with no whitespace or Unicode normalization.
// The caller owns the password and returned plaintext and must clear them when
// no longer needed. Go does not guarantee erasure of every internal copy.
func UnlockBitwarden(envelope BitwardenEnvelope, password []byte) ([]byte, error) {
	if len(password) > maxBitwardenPasswordBytes || len(envelope.Salt) > maxBitwardenSaltBytes ||
		len(envelope.Validation) > maxBitwardenValidationBytes ||
		len(envelope.Data) > MaxBitwardenEnvelopeBytes ||
		len(envelope.Salt)+len(envelope.Validation)+len(envelope.Data) > MaxBitwardenEnvelopeBytes {
		return nil, &Error{Code: "input_limit"}
	}
	if !envelope.Encrypted || !envelope.PasswordProtected {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	if envelope.Salt == "" || !utf8.ValidString(envelope.Salt) {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if !utf8.Valid(password) {
		return nil, &Error{Code: "authentication_failed"}
	}
	if err := validateBitwardenKDF(envelope); err != nil {
		return nil, err
	}
	validation, err := parseBitwardenRecord(envelope.Validation)
	if err != nil {
		return nil, err
	}
	data, err := parseBitwardenRecord(envelope.Data)
	if err != nil {
		return nil, err
	}
	key, err := deriveBitwardenKey(envelope, password)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	// Authenticate both complete ciphertexts before any CBC decryption.
	validationOK := validation.authenticated(key[32:])
	dataOK := data.authenticated(key[32:])
	if !validationOK || !dataOK {
		return nil, &Error{Code: "authentication_failed"}
	}
	token, err := validation.decrypt(key[:32])
	if err != nil {
		return nil, err
	}
	clear(token)
	return data.decrypt(key[:32])
}

func validateBitwardenKDF(e BitwardenEnvelope) error {
	switch e.KDFType {
	case 0:
		if e.KDFMemory != 0 || e.KDFParallelism != 0 {
			return &Error{Code: "unsupported_kdf"}
		}
		if e.KDFIterations < minPBKDF2Iterations || e.KDFIterations > maxPBKDF2Iterations {
			return &Error{Code: "kdf_limit"}
		}
	case 1:
		// Check all bounds before multiplication and conversion to uint32/uint8.
		if e.KDFIterations < minArgon2Iterations || e.KDFIterations > maxArgon2Iterations ||
			e.KDFMemory < minArgon2MemoryMiB || e.KDFMemory > maxArgon2MemoryMiB ||
			e.KDFParallelism < 1 || e.KDFParallelism > maxArgon2Parallelism {
			return &Error{Code: "kdf_limit"}
		}
		if e.KDFMemory*e.KDFIterations > maxArgon2MemoryPassesMiB {
			return &Error{Code: "kdf_limit"}
		}
	default:
		return &Error{Code: "unsupported_kdf"}
	}
	return nil
}

func deriveBitwardenKey(e BitwardenEnvelope, password []byte) ([]byte, error) {
	var material []byte
	switch e.KDFType {
	case 0:
		var err error
		material, err = pbkdf2.Key(sha256.New, string(password), []byte(e.Salt), e.KDFIterations, 32)
		if err != nil {
			return nil, &Error{Code: "unsupported_kdf"}
		}
	case 1:
		saltHash := sha256.Sum256([]byte(e.Salt))
		material = argon2.IDKey(password, saltHash[:], uint32(e.KDFIterations), uint32(e.KDFMemory)*1024, uint8(e.KDFParallelism), 32)
		clear(saltHash[:])
	}
	defer clear(material)
	enc, err := hkdf.Expand(sha256.New, material, "enc", 32)
	if err != nil {
		return nil, &Error{Code: "unsupported_kdf"}
	}
	defer clear(enc)
	mac, err := hkdf.Expand(sha256.New, material, "mac", 32)
	if err != nil {
		return nil, &Error{Code: "unsupported_kdf"}
	}
	defer clear(mac)
	key := make([]byte, 64)
	copy(key, enc)
	copy(key[32:], mac)
	return key, nil
}

type bitwardenRecord struct {
	iv         []byte
	ciphertext []byte
	mac        []byte
}

func parseBitwardenRecord(s string) (bitwardenRecord, error) {
	var empty bitwardenRecord
	if len(s) < 2 || s[1] != '.' {
		return empty, &Error{Code: "invalid_encrypted"}
	}
	if s[0] != '2' {
		return empty, &Error{Code: "unsupported_encrypted"}
	}
	parts := strings.SplitN(s[2:], "|", 4)
	if len(parts) != 3 || len(parts[0]) != 24 || len(parts[2]) != 44 ||
		len(parts[1]) == 0 || len(parts[1])%4 != 0 || strings.ContainsAny(s, "\r\n") {
		return empty, &Error{Code: "invalid_encrypted"}
	}
	strict := base64.StdEncoding.Strict()
	iv, err := strict.DecodeString(parts[0])
	if err != nil || len(iv) != aes.BlockSize {
		return empty, &Error{Code: "invalid_encrypted"}
	}
	mac, err := strict.DecodeString(parts[2])
	if err != nil || len(mac) != sha256.Size {
		return empty, &Error{Code: "invalid_encrypted"}
	}
	ciphertext, err := strict.DecodeString(parts[1])
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return empty, &Error{Code: "invalid_encrypted"}
	}
	if len(ciphertext) > MaxBitwardenPlaintextBytes {
		return empty, &Error{Code: "input_limit"}
	}
	return bitwardenRecord{iv: iv, ciphertext: ciphertext, mac: mac}, nil
}

func (r bitwardenRecord) authenticated(macKey []byte) bool {
	mac := hmac.New(sha256.New, macKey)
	mac.Write(r.iv)
	mac.Write(r.ciphertext)
	return hmac.Equal(mac.Sum(nil), r.mac)
}

func (r bitwardenRecord) decrypt(encKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	plain := make([]byte, len(r.ciphertext))
	cipher.NewCBCDecrypter(block, r.iv).CryptBlocks(plain, r.ciphertext)
	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > aes.BlockSize {
		clear(plain)
		return nil, &Error{Code: "authentication_failed"}
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			clear(plain)
			return nil, &Error{Code: "authentication_failed"}
		}
	}
	data := plain[:len(plain)-padding]
	if !utf8.Valid(data) {
		clear(plain)
		return nil, &Error{Code: "invalid_encrypted"}
	}
	// Clear padding and exclude it from the returned slice capacity.
	clear(plain[len(data):])
	return data[:len(data):len(data)], nil
}
