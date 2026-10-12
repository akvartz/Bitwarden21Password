package recovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"
)

// TestOfficialAgeCLIInterop is an opt-in interoperability check using the
// maintainer-provisioned official age CLI. The ordinary offline suite does not
// fetch, build, or install a tool. Only public synthetic keys/bytes are used.
func TestOfficialAgeCLIInterop(t *testing.T) {
	ageBinary := os.Getenv("PWMIGRATE_AGE_CLI")
	if ageBinary == "" {
		t.Skip("official age CLI not provisioned")
	}
	if !filepath.IsAbs(ageBinary) {
		t.Fatal("age CLI path must be absolute")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "synthetic-key.txt")
	if err := os.WriteFile(key, []byte(upstreamIdentity+"\n"), 0600); err != nil {
		t.Fatal("key fixture")
	}
	identity, err := age.ParseX25519Identity(upstreamIdentity)
	if err != nil {
		t.Fatal("identity fixture")
	}
	source := []byte{' ', '\r', '\n', 0, 0xff, '\t', ' '}
	for _, format := range []string{"chrome-csv", "firefox-csv", "safari-csv", "bitwarden-json", "onepassword-1pux", "proton-pass-zip"} {
		t.Run(format, func(t *testing.T) {
			manifest := []byte(fmt.Sprintf(`{"schema":"pwmigrate-recovery","version":1,"source_format":%q,"retention":"whole_source","source_bytes":%d}`, format, len(source)))
			frame := append([]byte("pwmigrate-recovery\n"), make([]byte, 4)...)
			binary.BigEndian.PutUint32(frame[19:23], uint32(len(manifest)))
			frame = append(frame, manifest...)
			frame = append(frame, source...)
			cipher, err := Encrypt(format, source, []byte(upstreamIdentity))
			if err != nil {
				t.Fatal("pwmigrate encrypt")
			}
			decrypt := exec.Command(ageBinary, "--decrypt", "--identity", key)
			decrypt.Stdin = bytes.NewReader(cipher)
			plain, err := decrypt.Output()
			if err != nil || !bytes.Equal(plain, frame) {
				t.Fatal("official CLI decrypt/frame mismatch")
			}
			encrypt := exec.Command(ageBinary, "--encrypt", "--recipient", identity.Recipient().String())
			encrypt.Stdin = bytes.NewReader(frame)
			external, err := encrypt.Output()
			if err != nil {
				t.Fatal("official CLI encrypt")
			}
			payload, err := Decrypt(external, []byte(upstreamIdentity))
			if err != nil || payload.Format != format || !bytes.Equal(payload.Source, source) {
				t.Fatal("pwmigrate reader/official ciphertext mismatch")
			}
		})
	}
}
