package protectedoutput

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/testsupport"
)

func TestWriteNamedRejectsUntrustedNamesBeforeFilesystemEffects(t *testing.T) {
	for _, name := range []string{"", "../bitwarden.json", "/bitwarden.json", "BITWARDEN.JSON", "unknown.json", "bitwarden.json/child", "bitwarden.json\x00", "recovery.age/child", "../recovery-key.txt"} {
		parent := t.TempDir()
		result, err := WriteNamed(context.Background(), parent, name, []byte("synthetic"))
		requireFailure(t, result, err, "output_create")
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatal("untrusted name caused filesystem effects")
		}
	}
}

func TestWriteNamedExactAllowedFilename(t *testing.T) {
	if !Supported() {
		t.Skip("public writer remains disabled until native qualification")
	}
	for _, name := range []string{"bitwarden.json", "onepassword.1pux", "proton-pass.zip", "recovery.age", "recovery-key.txt", "source.csv", "source.json", "source.1pux", "source.zip"} {
		t.Run(name, func(t *testing.T) {
			parent := testsupport.PrivateParent(t)
			payload := []byte("synthetic exact \r\n世界")
			result, err := WriteNamed(context.Background(), parent, name, payload)
			if err != nil {
				t.Fatalf("write failed: %v", err)
			}
			if result.FileName != name {
				t.Fatal("receipt filename does not identify selected export")
			}
			job := filepath.Join(parent, result.JobDirectory)
			testsupport.AssertPrivate(t, job, true)
			testsupport.AssertPrivate(t, filepath.Join(job, name), false)
			entries, err := os.ReadDir(job)
			if err != nil || len(entries) != 1 || entries[0].Name() != name {
				t.Fatal("job did not publish exactly the selected filename")
			}
			got, err := os.ReadFile(filepath.Join(job, name))
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatal("named payload differs")
			}
		})
	}
}
