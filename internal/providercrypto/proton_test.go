package providercrypto_test

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/akvartz/Bitwarden21Password/internal/providercrypto"
)

func protonBinary(t *testing.T, armored string) []byte {
	t.Helper()
	block, err := armor.Decode(bytes.NewBufferString(armored))
	if err != nil {
		t.Fatal("synthetic fixture armor failed")
	}
	data, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal("synthetic fixture decode failed")
	}
	return data
}

func protonError(t *testing.T, ciphertext, password []byte, codes ...string) {
	t.Helper()
	plain, err := providercrypto.UnlockProton(ciphertext, password)
	if plain != nil || err == nil {
		t.Fatal("failed unlock returned plaintext or success")
	}
	var safe *providercrypto.Error
	if !errors.As(err, &safe) {
		t.Fatal("unlock exposed a non-safe error")
	}
	for _, code := range codes {
		if safe.Code == code && err.Error() == code {
			return
		}
	}
	t.Fatalf("unexpected fixed error code %q", safe.Code)
}

func TestProtonIndependentVectors(t *testing.T) {
	for _, vector := range protonIndependentVectors {
		t.Run(vector.name, func(t *testing.T) {
			for _, ciphertext := range [][]byte{[]byte(vector.armored), protonBinary(t, vector.armored)} {
				password := []byte(protonVectorPassword)
				beforeCipher, beforePassword := bytes.Clone(ciphertext), bytes.Clone(password)
				plain, err := providercrypto.UnlockProton(ciphertext, password)
				if err != nil || !bytes.Equal(plain, []byte(protonVectorPlaintext)) {
					t.Fatal("independent vector did not unlock exactly")
				}
				if !bytes.Equal(ciphertext, beforeCipher) || !bytes.Equal(password, beforePassword) {
					t.Fatal("caller inputs were changed")
				}
				protonError(t, ciphertext, []byte("wrong synthetic password"), "authentication_failed")
				protonError(t, ciphertext, []byte("synthetic-🔐-password"), "authentication_failed")
				protonError(t, ciphertext, nil, "authentication_failed")
			}
		})
	}
}

func TestProtonNoPlaintextOnTamperingOrTruncation(t *testing.T) {
	data := protonBinary(t, protonIndependentVectors[0].armored)
	password := []byte(protonVectorPassword)
	for _, n := range []int{0, 1, 3, 10, len(data) / 2, len(data) - 1} {
		protonError(t, data[:n], password, "invalid_encrypted", "authentication_failed")
	}
	for _, n := range []int{len(data) - 1, len(data) - 8, len(data) / 2} {
		changed := bytes.Clone(data)
		changed[n] ^= 1
		protonError(t, changed, password, "authentication_failed", "invalid_encrypted")
	}
	protonError(t, append(bytes.Clone(data), 0), password, "invalid_encrypted")
	protonError(t, append(bytes.Clone(data), data...), password, "invalid_encrypted")
}

func protonPacket(tag byte, body []byte) []byte {
	p := make([]byte, 6+len(body))
	p[0], p[1] = 0xc0|tag, 255
	binary.BigEndian.PutUint32(p[2:6], uint32(len(body)))
	copy(p[6:], body)
	return p
}

func protonFakeMessage(sk []byte, tag byte, body []byte) []byte {
	return append(protonPacket(3, sk), protonPacket(tag, body)...)
}

func TestProtonRejectsUnsupportedKDFAndUnauthenticatedFrames(t *testing.T) {
	sk := []byte{4, 9, 3, 8, 1, 2, 3, 4, 5, 6, 7, 8, 255}
	seipd := append([]byte{1}, make([]byte, 64)...)
	for _, tc := range []struct {
		name string
		sk   []byte
		tag  byte
		body []byte
		code string
	}{
		{"unauthenticated", sk, 9, seipd, "unsupported_encrypted"},
		{"aead-tag", sk, 20, seipd, "unsupported_encrypted"},
		{"seipd-v2", sk, 18, append([]byte{2}, seipd[1:]...), "unsupported_encrypted"},
		{"skesk-v6", append([]byte{6}, sk[1:]...), 18, seipd, "unsupported_encrypted"},
		{"old-cipher", append([]byte{4, 3}, sk[2:]...), 18, seipd, "unsupported_encrypted"},
		{"simple-s2k", append([]byte{4, 9, 0}, sk[3:]...), 18, seipd, "unsupported_kdf"},
		{"salt-only-s2k", append([]byte{4, 9, 1}, sk[3:]...), 18, seipd, "unsupported_kdf"},
		{"argon2-hostile", append([]byte{4, 9, 4}, bytes.Repeat([]byte{255}, 30)...), 18, seipd, "unsupported_kdf"},
		{"old-hash", append([]byte{4, 9, 3, 2}, sk[4:]...), 18, seipd, "unsupported_kdf"},
		{"long-skesk", append(bytes.Clone(sk), make([]byte, 64)...), 18, seipd, "invalid_encrypted"},
		{"short-skesk", sk[:12], 18, seipd, "invalid_encrypted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			protonError(t, protonFakeMessage(tc.sk, tc.tag, tc.body), []byte("synthetic"), tc.code)
		})
	}
	protonError(t, append(protonPacket(3, sk), protonFakeMessage(sk, 18, seipd)...), []byte("synthetic"), "invalid_encrypted")
	protonError(t, protonPacket(18, seipd), []byte("synthetic"), "unsupported_encrypted")
	// Old-format indeterminate and unfinished partial packet lengths are unsafe.
	protonError(t, []byte{0x8f, 4, 9, 3, 8}, nil, "invalid_encrypted")
	protonError(t, []byte{0xc3, 254, 4, 9, 3, 8}, nil, "invalid_encrypted")
	// Huge declared lengths must not allocate attacker-controlled buffers.
	protonError(t, []byte{0xc3, 255, 255, 255, 255, 255}, nil, "invalid_encrypted")
}

func TestProtonArmorRequiresExactlyOneCompleteMessage(t *testing.T) {
	valid := protonIndependentVectors[0].armored
	for _, invalid := range []string{
		"junk\n" + valid,
		valid + "junk\n",
		valid + valid,
		string(bytes.Replace([]byte(valid), []byte("-----END PGP MESSAGE-----"), nil, 1)),
		string(bytes.Replace([]byte(valid), []byte("-----END PGP MESSAGE-----"), []byte("-----END PGP SIGNATURE-----"), 1)),
		string(bytes.Replace([]byte(valid), []byte("-----BEGIN PGP MESSAGE-----"), []byte("-----BEGIN PGP SIGNATURE-----"), 1)),
	} {
		protonError(t, []byte(invalid), []byte(protonVectorPassword), "invalid_encrypted")
	}
}

func TestProtonByteAndPasswordLimits(t *testing.T) {
	protonError(t, make([]byte, 32*1024*1024+1), nil, "input_limit")
	protonError(t, []byte(protonIndependentVectors[0].armored), make([]byte, 1024*1024+1), "input_limit")
}

// Library-generated hostile authenticated messages test our packet boundary;
// their acceptance does not establish interoperability or provider acceptance.
func protonEncryptRaw(t *testing.T, raw []byte, password []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	config := &packet.Config{DefaultCipher: packet.CipherAES256, S2KConfig: &s2k.Config{S2KMode: s2k.IteratedSaltedS2K, Hash: crypto.SHA256, S2KCount: 65536}}
	key, err := packet.SerializeSymmetricKeyEncrypted(&output, password, config)
	if err != nil {
		t.Fatal("synthetic key generation failed")
	}
	defer clear(key)
	writer, err := packet.SerializeSymmetricallyEncrypted(&output, packet.CipherAES256, false, packet.CipherSuite{}, key, config)
	if err != nil {
		t.Fatal("synthetic encryption failed")
	}
	if _, err = writer.Write(raw); err != nil {
		t.Fatal("synthetic encryption write failed")
	}
	if err = writer.Close(); err != nil {
		t.Fatal("synthetic encryption close failed")
	}
	return output.Bytes()
}

func protonCompressed(t *testing.T, raw []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zlib.NewWriter(&output)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal("synthetic compression failed")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("synthetic compression close failed")
	}
	return protonPacket(8, append([]byte{2}, output.Bytes()...))
}

func TestProtonAuthenticatedInnerMessageBounds(t *testing.T) {
	password := []byte("synthetic-inner-password")
	literal := protonPacket(11, append([]byte{'b', 0, 0, 0, 0, 0}, []byte("exact synthetic payload\x00\r\n")...))
	for _, raw := range [][]byte{literal, protonCompressed(t, literal)} {
		plain, err := providercrypto.UnlockProton(protonEncryptRaw(t, raw, password), password)
		if err != nil || !bytes.Equal(plain, []byte("exact synthetic payload\x00\r\n")) {
			t.Fatal("bounded synthetic literal failed")
		}
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		code string
	}{
		{"multiple-literals", append(bytes.Clone(literal), literal...), "invalid_encrypted"},
		{"signature-before-literal", append(protonPacket(4, make([]byte, 13)), literal...), "invalid_encrypted"},
		{"nested-compression", protonCompressed(t, protonCompressed(t, literal)), "unsupported_encrypted"},
		{"text-literal", protonPacket(11, []byte{'u', 0, 0, 0, 0, 0, 'x'}), "unsupported_encrypted"},
		{"short-literal", protonPacket(11, []byte{'b'}), "invalid_encrypted"},
		{"truncated-filename", protonPacket(11, []byte{'b', 255, 0, 0, 0, 0}), "invalid_encrypted"},
		{"huge-literal-length", []byte{0xcb, 255, 255, 255, 255, 255}, "invalid_encrypted"},
		{"unknown-compression", protonPacket(8, []byte{3, 0}), "unsupported_encrypted"},
		{"corrupted-compression", protonPacket(8, []byte{2, 0, 1, 2}), "invalid_encrypted"},
		{"indeterminate-literal", []byte{0xaf, 'b', 0, 0, 0, 0, 0, 'x'}, "invalid_encrypted"},
	} {
		t.Run(tc.name, func(t *testing.T) { protonError(t, protonEncryptRaw(t, tc.raw, password), password, tc.code) })
	}
	// The authenticated compressed packet stays small; expansion is bounded
	// before parsing a literal or returning any prefix of its payload.
	bomb := protonCompressed(t, bytes.Repeat([]byte{'x'}, 32*1024*1024+1))
	protonError(t, protonEncryptRaw(t, bomb, password), password, "input_limit")
}

func TestProtonPartialPacketLengths(t *testing.T) {
	password := []byte("synthetic-partial-password")
	payload := bytes.Repeat([]byte{'x'}, 4096)
	body := append([]byte{'b', 0, 0, 0, 0, 0}, payload...)
	// One 512-byte partial chunk, followed by a final definite-length chunk.
	literal := append([]byte{0xcb, 233}, body[:512]...)
	last := protonPacket(11, body[512:])
	literal = append(literal, last[1:]...)
	message := protonEncryptRaw(t, literal, password)
	plain, err := providercrypto.UnlockProton(message, password)
	if err != nil || !bytes.Equal(plain, payload) {
		t.Fatal("bounded partial packet failed")
	}
	// Missing final-length frames and impossible partial body lengths fail.
	protonError(t, protonEncryptRaw(t, literal[:513], password), password, "invalid_encrypted")
	protonError(t, protonEncryptRaw(t, []byte{0xcb, 254, 'b'}, password), password, "invalid_encrypted")
}

func FuzzProtonUnlock(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xc3, 255, 255, 255, 255, 255})
	f.Add([]byte{0x8f, 4, 9, 4, 255, 255, 255})
	f.Add([]byte("-----BEGIN PGP MESSAGE-----\n\nAAAA\n-----END PGP MESSAGE-----\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 64*1024 {
			t.Skip()
		}
		plain, err := providercrypto.UnlockProton(data, []byte("synthetic-fuzz-password"))
		if err == nil {
			if plain == nil || len(plain) > 32*1024*1024 {
				t.Fatal("invalid successful plaintext boundary")
			}
			return
		}
		if plain != nil {
			t.Fatal("failure returned plaintext")
		}
		var safe *providercrypto.Error
		if !errors.As(err, &safe) {
			t.Fatal("unsafe error type")
		}
		switch safe.Code {
		case "invalid_encrypted", "unsupported_encrypted", "unsupported_kdf", "authentication_failed", "input_limit":
			if err.Error() != safe.Code {
				t.Fatal("unsafe error text")
			}
		default:
			t.Fatal("unknown error code")
		}
	})
}
