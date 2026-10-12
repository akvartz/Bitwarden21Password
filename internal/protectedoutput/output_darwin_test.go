//go:build darwin

package protectedoutput

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDarwinCandidateNativePrivateExact(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("{\"synthetic\":\" exact \\r\\n世界\"}\n")
	result, err := writeDarwinCandidate(context.Background(), parent, payload)
	if err != nil {
		t.Fatalf("native candidate failed: %v", err)
	}
	job := filepath.Join(parent, result.JobDirectory)
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{job, os.ModeDir | 0700}, {filepath.Join(job, result.FileName), 0600},
	} {
		file, err := os.Open(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		info, statErr := file.Stat()
		private := nativePrivacy(file)
		closeErr := file.Close()
		if statErr != nil || closeErr != nil || info.Mode() != entry.mode || !owned(info) || !private {
			t.Fatal("native effective owner/mode/ACL/volume check failed")
		}
	}
	got, err := os.ReadFile(filepath.Join(job, result.FileName))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("native published bytes changed")
	}
}

func TestDarwinCandidateCancelledCreatesNothing(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := writeDarwinCandidate(ctx, parent, []byte("synthetic"))
	requireFailure(t, result, err, "output_cancelled")
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled candidate changed parent")
	}
}

func TestDarwinCandidateNamedExports(t *testing.T) {
	for _, name := range []string{"bitwarden.json", "onepassword.1pux", "proton-pass.zip"} {
		t.Run(name, func(t *testing.T) {
			parent := privateParent(t)
			result, err := writeNamedWithOps(context.Background(), parent, name, []byte("synthetic"), filesystemOperations())
			if err != nil || result.FileName != name {
				t.Fatalf("native named export failed: %v", err)
			}
			assertContents(t, filepath.Join(parent, result.JobDirectory, name), "synthetic")
			assertAbsent(t, filepath.Join(parent, result.JobDirectory, "."+name+".partial"))
		})
	}
}

func TestDarwinCandidateRejectsACLDespitePrivateBSDModes(t *testing.T) {
	for _, phase := range []string{"parent", "job", "file"} {
		t.Run(phase, func(t *testing.T) {
			parent := privateParent(t)
			setACL := func(path string) {
				t.Helper()
				// Native macOS fixture tool only; the writer never runs a
				// command. The directory/file BSD modes remain private.
				if err := exec.Command("/bin/chmod", "+a", "everyone allow read,readattr,readextattr,readsecurity", path).Run(); err != nil {
					t.Fatal("native ACL fixture could not be established")
				}
			}
			ops := namedOps()
			want := "output_create"
			switch phase {
			case "parent":
				setACL(parent)
				want = "output_parent"
			case "job":
				ops.mkdir = func(root *os.Root, name string, mode os.FileMode) error {
					if err := root.Mkdir(name, mode); err != nil {
						return err
					}
					setACL(filepath.Join(parent, name))
					return nil
				}
			case "file":
				ops.openFile = func(root *os.Root, name string, flag int, mode os.FileMode) (*os.File, error) {
					file, err := root.OpenFile(name, flag, mode)
					if err == nil {
						setACL(filepath.Join(parent, testJobName, name))
					}
					return file, err
				}
			}
			result, err := writeWithOps(context.Background(), parent, []byte("synthetic"), ops)
			requireFailure(t, result, err, want)
			if phase == "parent" {
				assertEmpty(t, parent)
			} else {
				assertAbsent(t, filepath.Join(parent, testJobName, fileName))
				if phase == "file" {
					assertContents(t, filepath.Join(parent, testJobName, partialName), "")
				}
			}
		})
	}
}
