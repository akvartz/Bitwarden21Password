package providercrypto

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
)

const protonByteLimit = 32 * 1024 * 1024
const protonPasswordLimit = 1024 * 1024

// UnlockProton unlocks the bounded password-based OpenPGP profile used by the
// reviewed Proton Pass exporter. It accepts one v4 AES SKESK with iterated,
// salted SHA-256/384/512 S2K and one v1 SEIPD packet. The complete decrypted
// packet stream is MDC-authenticated before parsing or releasing plaintext.
// Argon2, AEAD, unauthenticated encryption and signed messages are unsupported.
func UnlockProton(ciphertext, password []byte) ([]byte, error) {
	if len(ciphertext) > protonByteLimit || len(password) > protonPasswordLimit {
		return nil, &Error{Code: "input_limit"}
	}
	data := ciphertext
	if bytes.HasPrefix(data, []byte("-----")) {
		var err error
		data, err = protonUnarmor(data)
		if err != nil {
			return nil, err
		}
	}
	sk, err := protonReadFrame(data, false)
	if err != nil {
		return nil, err
	}
	if sk.tag != 3 {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	if sk.partial || len(sk.body) < 4 {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if sk.body[0] != 4 || !protonAES(sk.body[1]) {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	if sk.body[2] != 3 || (sk.body[3] != 8 && sk.body[3] != 9 && sk.body[3] != 10) {
		return nil, &Error{Code: "unsupported_kdf"}
	}
	// The S2K descriptor is exactly 11 bytes. An optional wrapped AES key is
	// 17/25/33 bytes, including its cipher byte. One SKESK bounds S2K work:
	// count-byte255 is 65,011,712 hash-input bytes, at most one hash pass for
	// any allowed hash/AES combination. All count bytes are within that cap.
	if n := len(sk.body); n != 13 && n != 30 && n != 38 && n != 46 {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	enc, err := protonReadFrame(data[sk.end:], false)
	if err != nil {
		return nil, err
	}
	if sk.end+enc.end != len(data) {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if enc.tag != 18 {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	if len(enc.body) == 0 {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if enc.body[0] != 1 {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	// Version + AES prefix + MDC trailer. Reject impossible sizes before KDF.
	if len(enc.body) < 1+18+22 {
		return nil, &Error{Code: "invalid_encrypted"}
	}

	ownedPassword := make([]byte, len(password))
	copy(ownedPassword, password)
	defer clear(ownedPassword)
	decryptor, err := pgp.PGP().Decryption().Password(ownedPassword).New()
	if err != nil {
		return nil, &Error{Code: "authentication_failed"}
	}
	defer decryptor.ClearPrivateParams()
	key, err := decryptor.DecryptSessionKey(data[:sk.end])
	if err != nil {
		return nil, &Error{Code: "authentication_failed"}
	}
	defer key.Clear()
	cipher, err := key.GetCipherFunc()
	if err != nil || !protonAES(byte(cipher)) {
		return nil, &Error{Code: "authentication_failed"}
	}
	// Using the maintained low-level reader avoids constructing unbounded
	// signature arrays before the authenticated inner stream is inspected.
	se := &packet.SymmetricallyEncrypted{
		Version: 1, IntegrityProtected: true, Contents: bytes.NewReader(enc.body[1:]),
	}
	decrypted, err := se.Decrypt(cipher, key.Key)
	if err != nil {
		return nil, &Error{Code: "authentication_failed"}
	}
	raw, err := io.ReadAll(io.LimitReader(decrypted, protonByteLimit+1))
	defer clear(raw)
	if err != nil {
		return nil, &Error{Code: "authentication_failed"}
	}
	if len(raw) > protonByteLimit {
		return nil, &Error{Code: "input_limit"}
	}
	// Close performs the MDC verification; EOF alone does not authenticate.
	if err := decrypted.Close(); err != nil {
		return nil, &Error{Code: "authentication_failed"}
	}
	return protonLiteral(raw)
}

func protonAES(cipher byte) bool { return cipher >= 7 && cipher <= 9 }

type protonFrame struct {
	tag     byte
	body    []byte
	end     int
	partial bool
}

// protonReadFrame validates framing and actual remaining bytes before allocating
// a partial-body buffer. Only authenticated, terminal compressed wrappers may
// use the old indeterminate length encoding.
func protonReadFrame(data []byte, allowCompressedIndeterminate bool) (protonFrame, error) {
	bad := func() (protonFrame, error) { return protonFrame{}, &Error{Code: "invalid_encrypted"} }
	if len(data) < 2 || data[0]&0x80 == 0 {
		return bad()
	}
	f := protonFrame{}
	pos := 1
	if data[0]&0x40 == 0 {
		f.tag = (data[0] >> 2) & 15
		sizeBytes := 1 << (data[0] & 3)
		if sizeBytes == 8 {
			if !allowCompressedIndeterminate || f.tag != 8 {
				return bad()
			}
			f.body, f.end = data[1:], len(data)
			return f, nil
		}
		if len(data)-pos < int(sizeBytes) {
			return bad()
		}
		var n uint32
		switch sizeBytes {
		case 1:
			n = uint32(data[pos])
		case 2:
			n = uint32(binary.BigEndian.Uint16(data[pos : pos+2]))
		case 4:
			n = binary.BigEndian.Uint32(data[pos : pos+4])
		}
		pos += int(sizeBytes)
		if uint64(n) > uint64(len(data)-pos) {
			return bad()
		}
		f.body, f.end = data[pos:pos+int(n)], pos+int(n)
		return f, nil
	}
	f.tag = data[0] & 63
	first := pos
	total := 0
	for {
		n, partial, next, ok := protonNewLength(data, pos)
		if !ok || n > len(data)-next || n > protonByteLimit-total {
			return bad()
		}
		if !f.partial && partial && n < 512 {
			return bad()
		}
		pos, total = next+n, total+n
		if !partial {
			f.end = pos
			if !f.partial {
				f.body = data[next:pos]
				return f, nil
			}
			break
		}
		f.partial = true
	}
	f.body = make([]byte, total)
	for offset, cursor := 0, first; cursor < f.end; {
		n, _, next, _ := protonNewLength(data, cursor)
		copy(f.body[offset:], data[next:next+n])
		offset, cursor = offset+n, next+n
	}
	return f, nil
}

func protonNewLength(data []byte, pos int) (n int, partial bool, next int, ok bool) {
	if pos >= len(data) {
		return
	}
	b := data[pos]
	pos++
	switch {
	case b < 192:
		n = int(b)
	case b < 224:
		if pos >= len(data) {
			return
		}
		n = (int(b)-192)*256 + int(data[pos]) + 192
		pos++
	case b < 255:
		n, partial = 1<<(b&31), true
	default:
		if len(data)-pos < 4 {
			return
		}
		wide := binary.BigEndian.Uint32(data[pos : pos+4])
		if uint64(wide) > protonByteLimit {
			return
		}
		n = int(wide)
		pos += 4
	}
	next, ok = pos, true
	return
}

func protonUnarmor(data []byte) ([]byte, error) {
	bad := func() ([]byte, error) { return nil, &Error{Code: "invalid_encrypted"} }
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), 1024)
	if !scanner.Scan() || !bytes.Equal(scanner.Bytes(), []byte("-----BEGIN PGP MESSAGE-----")) {
		return bad()
	}
	state, headers, bodyLines := 1, 0, 0
	for scanner.Scan() {
		line := scanner.Bytes()
		switch state {
		case 1:
			if len(line) == 0 {
				state = 2
				continue
			}
			headers++
			colon := bytes.IndexByte(line, ':')
			if headers > 16 || colon < 1 {
				return bad()
			}
			for _, b := range line {
				if b < 32 || b > 126 {
					return bad()
				}
			}
		case 2:
			if bytes.Equal(line, []byte("-----END PGP MESSAGE-----")) {
				state = 4
				continue
			}
			if len(line) == 5 && line[0] == '=' {
				if _, err := base64.StdEncoding.Strict().DecodeString(string(line[1:])); err != nil {
					return bad()
				}
				state = 3
				continue
			}
			if len(line) == 0 || len(line) > 96 {
				return bad()
			}
			for _, b := range line {
				if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/' || b == '=') {
					return bad()
				}
			}
			bodyLines++
		case 3:
			if !bytes.Equal(line, []byte("-----END PGP MESSAGE-----")) {
				return bad()
			}
			state = 4
		case 4:
			if len(bytes.Trim(line, " \t\r")) != 0 {
				return bad()
			}
		}
	}
	if scanner.Err() != nil || state != 4 || bodyLines == 0 {
		return bad()
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil || block.Type != "PGP MESSAGE" {
		return bad()
	}
	binary, err := io.ReadAll(io.LimitReader(block.Body, protonByteLimit+1))
	if err != nil {
		return bad()
	}
	if len(binary) > protonByteLimit {
		return nil, &Error{Code: "input_limit"}
	}
	return binary, nil
}

func protonLiteral(raw []byte) ([]byte, error) {
	f, err := protonReadFrame(raw, true)
	if err != nil {
		return nil, err
	}
	if f.partial {
		defer clear(f.body)
	}
	if f.end != len(raw) {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if f.tag == 8 {
		if len(f.body) == 0 {
			return nil, &Error{Code: "invalid_encrypted"}
		}
		compressed := bytes.NewReader(f.body[1:])
		var reader io.ReadCloser
		switch f.body[0] {
		case 0:
			reader = io.NopCloser(compressed)
		case 1:
			reader = flate.NewReader(compressed)
		case 2:
			reader, err = zlib.NewReader(compressed)
			if err != nil {
				return nil, &Error{Code: "invalid_encrypted"}
			}
		default:
			return nil, &Error{Code: "unsupported_encrypted"}
		}
		expanded, readErr := io.ReadAll(io.LimitReader(reader, protonByteLimit+1))
		defer clear(expanded)
		closeErr := reader.Close()
		if len(expanded) > protonByteLimit {
			return nil, &Error{Code: "input_limit"}
		}
		if readErr != nil || closeErr != nil || compressed.Len() != 0 {
			return nil, &Error{Code: "invalid_encrypted"}
		}
		f, err = protonReadFrame(expanded, false)
		if err != nil {
			return nil, err
		}
		if f.partial {
			defer clear(f.body)
		}
		if f.end != len(expanded) {
			return nil, &Error{Code: "invalid_encrypted"}
		}
	}
	if f.tag != 11 {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	// Only binary literals: metadata is bounded and discarded, payload exact.
	if len(f.body) < 6 {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	if f.body[0] != 'b' {
		return nil, &Error{Code: "unsupported_encrypted"}
	}
	start := 2 + int(f.body[1]) + 4
	if start > len(f.body) {
		return nil, &Error{Code: "invalid_encrypted"}
	}
	return bytes.Clone(f.body[start:]), nil
}
