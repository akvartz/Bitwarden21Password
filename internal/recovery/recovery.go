// Package recovery preserves an exact source export in an authenticated age
// envelope. Recovery retention is separate from destination migration.
package recovery

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"

	"filippo.io/age"
)

const (
	// MaxSourceBytes matches the migration engine's actual input byte limit.
	MaxSourceBytes = 32 << 20
	// MaxCiphertextBytes permits bounded age header/stream overhead. An ordinary
	// single-recipient source at the limit produces about 32 MiB + 8.4 KiB.
	MaxCiphertextBytes = 48 << 20
	MaxManifestBytes   = 4 << 10
	MaxIdentityBytes   = 16 << 10
	MaxEnvelopeBytes   = MaxSourceBytes + MaxManifestBytes + len(magic) + 4

	magic = "pwmigrate-recovery\n"
)

// Payload contains the original source, not a successfully migrated export.
// Source includes excluded records and unsupported fields from the entire
// supplied source snapshot. It contains no recovery identity.
type Payload struct {
	Format string
	Source []byte
}

// Error exposes only fixed codes. Library/parser errors and source/key material
// are deliberately not wrapped, interpolated, or retained.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e != nil {
		switch e.Code {
		case "recovery_source_limit", "recovery_ciphertext_limit", "recovery_payload_limit",
			"recovery_identity", "recovery_format", "recovery_manifest", "recovery_authentication", "recovery_encrypt":
			return e.Code
		}
	}
	return "recovery_manifest"
}

func fail(code string) error { return &Error{Code: code} }

// GenerateIdentity returns one newly generated secret X25519 identity as an age
// key string, without comments or a trailing newline. The caller must deliver
// and retain it through a private local key file or secret prompt, never argv,
// logs, reports, or preferences. Losing it makes the recovery unreadable.
func GenerateIdentity() ([]byte, error) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fail("recovery_identity")
	}
	return []byte(identity.String()), nil
}

type manifest struct {
	Schema      string `json:"schema"`
	Version     int    `json:"version"`
	Format      string `json:"source_format"`
	Retention   string `json:"retention"`
	SourceBytes int    `json:"source_bytes"`
}

// Encrypt encrypts the manifest and every original source byte with the
// maintained age X25519 implementation. identity is a single X25519 key string
// or a conventional age key file containing exactly one X25519 secret.
func Encrypt(sourceFormat string, source, identity []byte) ([]byte, error) {
	if len(source) > MaxSourceBytes {
		return nil, fail("recovery_source_limit")
	}
	if !supportedFormat(sourceFormat) {
		return nil, fail("recovery_format")
	}
	key, err := parseIdentity(identity)
	if err != nil {
		return nil, err
	}
	encodedManifest, err := json.Marshal(manifest{
		Schema: "pwmigrate-recovery", Version: 1, Format: sourceFormat,
		Retention: "whole_source", SourceBytes: len(source),
	})
	if err != nil || len(encodedManifest) > MaxManifestBytes {
		return nil, fail("recovery_encrypt")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(encodedManifest)))
	var out bytes.Buffer
	w, err := age.Encrypt(&out, key.Recipient())
	if err != nil {
		return nil, fail("recovery_encrypt")
	}
	// Write the original source directly instead of copying it into an
	// additional assembled plaintext envelope.
	for _, part := range [][]byte{[]byte(magic), size[:], encodedManifest, source} {
		if _, err := w.Write(part); err != nil {
			return nil, fail("recovery_encrypt")
		}
	}
	if err := w.Close(); err != nil {
		return nil, fail("recovery_encrypt")
	}
	if out.Len() > MaxCiphertextBytes {
		return nil, fail("recovery_ciphertext_limit")
	}
	return out.Bytes(), nil
}

// Decrypt authenticates the complete age stream, including its final chunk and
// EOF, before interpreting or returning plaintext. Every failure returns an
// empty Payload. No filesystem writes or runtime network calls occur here.
func Decrypt(ciphertext, identity []byte) (Payload, error) {
	if len(ciphertext) > MaxCiphertextBytes {
		return Payload{}, fail("recovery_ciphertext_limit")
	}
	key, err := parseIdentity(identity)
	if err != nil {
		return Payload{}, err
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), x25519OnlyIdentity{key})
	if err != nil {
		return Payload{}, fail("recovery_authentication")
	}
	plaintext, err := io.ReadAll(io.LimitReader(r, int64(MaxEnvelopeBytes)+1))
	if len(plaintext) > MaxEnvelopeBytes {
		clear(plaintext)
		return Payload{}, fail("recovery_payload_limit")
	}
	if err != nil {
		clear(plaintext)
		return Payload{}, fail("recovery_authentication")
	}
	// At an allowed size LimitReader still has one remaining byte: ReadAll had
	// to observe the authenticated reader's EOF, not just its byte limit.
	// Do not keep any plaintext on malformed framing/manifest failures.
	defer clear(plaintext)
	prefixBytes := len(magic) + 4
	if len(plaintext) < prefixBytes || !bytes.Equal(plaintext[:len(magic)], []byte(magic)) {
		return Payload{}, fail("recovery_manifest")
	}
	manifestBytes := uint64(binary.BigEndian.Uint32(plaintext[len(magic):prefixBytes]))
	if manifestBytes == 0 || manifestBytes > MaxManifestBytes || manifestBytes > uint64(len(plaintext)-prefixBytes) {
		return Payload{}, fail("recovery_manifest")
	}
	sourceStart := prefixBytes + int(manifestBytes)
	m, ok := parseManifest(plaintext[prefixBytes:sourceStart])
	if !ok || m.SourceBytes != len(plaintext)-sourceStart {
		return Payload{}, fail("recovery_manifest")
	}
	return Payload{Format: m.Format, Source: bytes.Clone(plaintext[sourceStart:])}, nil
}

func parseIdentity(data []byte) (*age.X25519Identity, error) {
	if len(data) == 0 || len(data) > MaxIdentityBytes || !utf8.Valid(data) {
		return nil, fail("recovery_identity")
	}
	identities, err := age.ParseIdentities(bytes.NewReader(data))
	if err != nil || len(identities) != 1 {
		return nil, fail("recovery_identity")
	}
	identity, ok := identities[0].(*age.X25519Identity)
	if !ok {
		return nil, fail("recovery_identity")
	}
	return identity, nil
}

// The reader supports only the single native X25519 recipient generated by
// Encrypt. This wrapper examines parsed age metadata; the maintained library
// still performs all key unwrapping, header authentication, and stream crypto.
type x25519OnlyIdentity struct{ key *age.X25519Identity }

func (i x25519OnlyIdentity) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	if len(stanzas) != 1 || stanzas[0].Type != "X25519" {
		return nil, fail("recovery_authentication")
	}
	return i.key.Unwrap(stanzas)
}

func supportedFormat(format string) bool {
	switch format {
	case "chrome-csv", "firefox-csv", "safari-csv", "bitwarden-json", "onepassword-1pux", "proton-pass-zip":
		return true
	}
	return false
}

func parseManifest(data []byte) (manifest, bool) {
	var m manifest
	if !utf8.Valid(data) {
		return m, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return m, false
	}
	seen := make(map[string]bool, 5)
	for d.More() {
		keyToken, err := d.Token()
		if err != nil {
			return m, false
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return m, false
		}
		seen[key] = true
		// Every field is a scalar. Token decoding rejects null/arrays/objects and
		// integer parsing rejects fractional/exponent syntax and overflow.
		value, err := d.Token()
		if err != nil {
			return m, false
		}
		switch key {
		case "schema", "source_format", "retention":
			s, ok := value.(string)
			if !ok {
				return m, false
			}
			switch key {
			case "schema":
				m.Schema = s
			case "source_format":
				m.Format = s
			case "retention":
				m.Retention = s
			}
		case "version", "source_bytes":
			n, ok := value.(json.Number)
			if !ok {
				return m, false
			}
			i, err := strconv.ParseInt(string(n), 10, 64)
			if err != nil || i < 0 || i > MaxSourceBytes {
				return m, false
			}
			if key == "version" {
				m.Version = int(i)
			} else {
				m.SourceBytes = int(i)
			}
		default:
			return m, false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 5 {
		return m, false
	}
	if _, err := d.Token(); err != io.EOF {
		return m, false
	}
	return m, m.Schema == "pwmigrate-recovery" && m.Version == 1 && m.Retention == "whole_source" && supportedFormat(m.Format)
}
