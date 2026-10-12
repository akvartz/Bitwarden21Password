package providercrypto_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/providercrypto"
)

type vector struct {
	Password  string
	Plaintext string
	Envelope  struct {
		Encrypted         bool
		PasswordProtected bool
		Salt              string
		KDFType           int
		KDFIterations     int
		KDFMemory         int
		KDFParallelism    int
		Validation        string `json:"encKeyValidation_DO_NOT_EDIT"`
		Data              string
	}
	BadPadding  []string
	Empty       string
	InvalidUTF8 string
}

func vectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("testdata/bitwarden-vectors.json")
	if err != nil {
		t.Fatal("cannot read synthetic vectors")
	}
	var all []vector
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatal("cannot parse synthetic vectors")
	}
	return all
}

func envelope(v vector) providercrypto.BitwardenEnvelope {
	e := v.Envelope
	return providercrypto.BitwardenEnvelope{Encrypted: e.Encrypted, PasswordProtected: e.PasswordProtected,
		Salt: e.Salt, KDFType: e.KDFType, KDFIterations: e.KDFIterations, KDFMemory: e.KDFMemory,
		KDFParallelism: e.KDFParallelism, Validation: e.Validation, Data: e.Data}
}

func requireCode(t *testing.T, e providercrypto.BitwardenEnvelope, password []byte, code string) {
	t.Helper()
	plain, err := providercrypto.UnlockBitwarden(e, password)
	if plain != nil {
		t.Fatal("plaintext returned on failure")
	}
	var safe *providercrypto.Error
	if !errors.As(err, &safe) || safe.Code != code || err.Error() != code {
		t.Fatalf("wanted fixed code %s", code)
	}
}

func alterPart(record string, part int, alter func([]byte) []byte) string {
	p := strings.Split(strings.TrimPrefix(record, "2."), "|")
	x, _ := base64.StdEncoding.DecodeString(p[part])
	p[part] = base64.StdEncoding.EncodeToString(alter(x))
	return "2." + strings.Join(p, "|")
}

func TestUnlockIndependentSyntheticVectors(t *testing.T) {
	for _, v := range vectors(t) {
		t.Run([]string{"pbkdf2", "argon2id"}[v.Envelope.KDFType], func(t *testing.T) {
			password := []byte(v.Password)
			before := bytes.Clone(password)
			plain, err := providercrypto.UnlockBitwarden(envelope(v), password)
			if err != nil || !bytes.Equal(plain, []byte(v.Plaintext)) {
				t.Fatal("independent synthetic vector did not decrypt exactly")
			}
			if !bytes.Equal(password, before) {
				t.Fatal("caller password changed")
			}
			requireCode(t, envelope(v), []byte("wrong synthetic password"), "authentication_failed")
			requireCode(t, envelope(v), []byte(strings.TrimSpace(v.Password)), "authentication_failed")
		})
	}
}

func TestUnlockAuthenticatesBothRecords(t *testing.T) {
	for _, v := range vectors(t) {
		for _, validation := range []bool{false, true} {
			for part := range 3 {
				e := envelope(v)
				s := e.Data
				if validation {
					s = e.Validation
				}
				s = alterPart(s, part, func(x []byte) []byte { x[0] ^= 1; return x })
				if validation {
					e.Validation = s
				} else {
					e.Data = s
				}
				requireCode(t, e, []byte(v.Password), "authentication_failed")
			}
		}
	}
}

func TestUnlockRejectsMalformedAndUnauthenticatedRecords(t *testing.T) {
	v := vectors(t)[0]
	valid := envelope(v)
	parts := strings.Split(strings.TrimPrefix(valid.Data, "2."), "|")
	bad := []string{"", "2.", "2." + strings.Join(parts[:2], "|"), valid.Data + "|extra",
		"2." + strings.Join([]string{parts[0] + "\n", parts[1], parts[2]}, "|"),
		"2." + strings.Join([]string{strings.TrimRight(parts[0], "="), parts[1], parts[2]}, "|"),
		"2." + strings.Join([]string{"!!!!", parts[1], parts[2]}, "|"),
		alterPart(valid.Data, 0, func(x []byte) []byte { return x[:15] }),
		alterPart(valid.Data, 1, func(x []byte) []byte { return x[:len(x)-1] }),
		alterPart(valid.Data, 2, func(x []byte) []byte { return x[:31] }),
		// Noncanonical pad bits must fail even when the resulting IV bytes match.
		"2." + strings.Join([]string{parts[0][:len(parts[0])-3] + "x==", parts[1], parts[2]}, "|")}
	for _, s := range bad {
		for _, validation := range []bool{false, true} {
			e := valid
			if validation {
				e.Validation = s
			} else {
				e.Data = s
			}
			requireCode(t, e, []byte(v.Password), "invalid_encrypted")
		}
	}
	for _, s := range []string{"0." + strings.Join(parts[:2], "|"), "1." + strings.Join(parts, "|"), "7.cose"} {
		e := valid
		e.Data = s
		requireCode(t, e, []byte(v.Password), "unsupported_encrypted")
	}
	for end := 1; end < len(valid.Data); end++ {
		e := valid
		e.Data = valid.Data[:end]
		requireCode(t, e, []byte(v.Password), "invalid_encrypted")
	}
}

func TestUnlockRejectsAuthenticatedMalformedPadding(t *testing.T) {
	for _, v := range vectors(t) {
		for _, s := range v.BadPadding {
			for _, validation := range []bool{false, true} {
				e := envelope(v)
				if validation {
					e.Validation = s
				} else {
					e.Data = s
				}
				requireCode(t, e, []byte(v.Password), "authentication_failed")
			}
		}
		e := envelope(v)
		e.Data = v.InvalidUTF8
		requireCode(t, e, []byte(v.Password), "invalid_encrypted")
		e = envelope(v)
		e.Validation = v.InvalidUTF8
		requireCode(t, e, []byte(v.Password), "invalid_encrypted")
		e = envelope(v)
		e.Data = v.Empty
		plain, err := providercrypto.UnlockBitwarden(e, []byte(v.Password))
		if err != nil || len(plain) != 0 {
			t.Fatal("authenticated empty plaintext must be handed to source parser")
		}
	}
}

func TestUnlockRejectsEnvelopeAndKDFBounds(t *testing.T) {
	v := vectors(t)[0]
	checks := []struct {
		change func(*providercrypto.BitwardenEnvelope)
		code   string
	}{
		{func(e *providercrypto.BitwardenEnvelope) { e.Encrypted = false }, "unsupported_encrypted"},
		{func(e *providercrypto.BitwardenEnvelope) { e.PasswordProtected = false }, "unsupported_encrypted"},
		{func(e *providercrypto.BitwardenEnvelope) { e.Salt = "" }, "invalid_encrypted"},
		{func(e *providercrypto.BitwardenEnvelope) { e.Salt = string([]byte{255}) }, "invalid_encrypted"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFType = -1 }, "unsupported_kdf"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFType = 2 }, "unsupported_kdf"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = -1 }, "kdf_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = 0 }, "kdf_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = 4999 }, "kdf_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = 2000001 }, "kdf_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFMemory = 1 }, "unsupported_kdf"},
		{func(e *providercrypto.BitwardenEnvelope) { e.KDFParallelism = 1 }, "unsupported_kdf"},
		{func(e *providercrypto.BitwardenEnvelope) { e.Salt = strings.Repeat("s", 1025) }, "input_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.Validation = strings.Repeat("s", 5500) }, "input_limit"},
		{func(e *providercrypto.BitwardenEnvelope) { e.Data = strings.Repeat("s", 32*1024*1024) }, "input_limit"},
	}
	for _, check := range checks {
		e := envelope(v)
		check.change(&e)
		requireCode(t, e, []byte(v.Password), check.code)
	}
	requireCode(t, envelope(v), bytes.Repeat([]byte("s"), 1024*1024+1), "input_limit")
	requireCode(t, envelope(v), []byte{255}, "authentication_failed")
	a := vectors(t)[1]
	for _, change := range []func(*providercrypto.BitwardenEnvelope){
		func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = 1 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFIterations = 11 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFMemory = 15 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFMemory = 257 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFMemory = int(^uint(0) >> 1) },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFParallelism = 0 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFParallelism = 17 },
		func(e *providercrypto.BitwardenEnvelope) { e.KDFMemory = 256; e.KDFIterations = 4 },
	} {
		e := envelope(a)
		change(&e)
		requireCode(t, e, []byte(a.Password), "kdf_limit")
	}
}

func TestErrorNeverRendersUnknownCode(t *testing.T) {
	if (&providercrypto.Error{Code: "synthetic unknown private value"}).Error() != "invalid_encrypted" {
		t.Fatal("unknown code rendered")
	}
}
