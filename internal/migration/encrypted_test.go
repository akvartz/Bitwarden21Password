package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestEncryptedBitwardenUsesIndependentEnvelopeAndPreservesOriginal(t *testing.T) {
	fixture, err := os.ReadFile("../providercrypto/testdata/bitwarden-vectors.json")
	if err != nil {
		t.Fatal("fixture unavailable")
	}
	var vectors []struct {
		Password  string
		Plaintext string
		Envelope  json.RawMessage
	}
	if json.Unmarshal(fixture, &vectors) != nil {
		t.Fatal("fixture invalid")
	}
	for _, v := range vectors {
		_, err := ParseWithPassword(v.Envelope, BitwardenJSON, nil)
		var safe *SafeError
		if !errors.As(err, &safe) || safe.Code != "password_required" {
			t.Fatal("missing secret did not request safe prompt")
		}
		d, err := ParseWithPassword(v.Envelope, BitwardenJSON, []byte(v.Password))
		if err != nil {
			t.Fatal("independent envelope integration failed:", err)
		}
		if d.format != BitwardenJSON || !bytes.Equal(d.original, v.Envelope) || !bytes.Equal(d.source, []byte(v.Plaintext)) {
			t.Fatal("source retention incorrect")
		}
		_, err = ParseWithPassword(v.Envelope, BitwardenJSON, []byte("wrong synthetic password"))
		if !errors.As(err, &safe) || safe.Code != "authentication_failed" {
			t.Fatal("wrong password failure unsafe")
		}
	}
}

func TestAccountBoundEnvelopeDoesNotRequestPassword(t *testing.T) {
	_, err := ParseWithPassword([]byte(`{"encrypted":true,"passwordProtected":false,"items":[]}`), BitwardenJSON, nil)
	var safe *SafeError
	if !errors.As(err, &safe) || safe.Code != "unsupported_encrypted" {
		t.Fatal("account-bound envelope should reject")
	}
}
