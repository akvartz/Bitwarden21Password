//go:build windows

package protectedoutput

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

func TestWindowsCandidateNativePrivateExact(t *testing.T) {
	parent := windowsPrivateParent(t)
	payload := []byte("{\"synthetic\":\" exact \\r\\n世界\"}\n")
	result, err := writeWindowsCandidate(context.Background(), parent, payload)
	if err != nil {
		t.Fatalf("native candidate failed: %v", err)
	}
	user, err := windowsCurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(parent, result.JobDirectory)
	for _, entry := range []struct {
		path string
		dir  bool
	}{
		{job, true}, {filepath.Join(job, result.FileName), false},
	} {
		file, err := os.Open(entry.path)
		if err != nil {
			t.Fatal(err)
		}
		private := windowsPrivateHandle(syscall.Handle(file.Fd()), user, entry.dir)
		closeErr := file.Close()
		if !private || closeErr != nil {
			t.Fatal("native reparse/owner/protected-DACL check failed")
		}
	}
	got, err := os.ReadFile(filepath.Join(job, result.FileName))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("native published bytes changed")
	}
	if _, err := os.Lstat(filepath.Join(job, partialName)); !os.IsNotExist(err) {
		t.Fatal("successful publication retained partial entry")
	}
}

func TestWindowsCandidateCancelledCreatesNothing(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := writeWindowsCandidate(ctx, parent, []byte("synthetic"))
	requireFailure(t, result, err, "output_cancelled")
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled candidate changed parent")
	}
}

func TestWindowsCandidateNamedExports(t *testing.T) {
	for _, name := range []string{"bitwarden.json", "onepassword.1pux", "proton-pass.zip"} {
		t.Run(name, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			result, err := writeWindowsWithOps(context.Background(), parent, name, []byte("synthetic"), windowsFilesystemOperations())
			if err != nil || result.FileName != name {
				t.Fatalf("native named export failed: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(parent, result.JobDirectory, name))
			if err != nil || string(got) != "synthetic" {
				t.Fatal("native named export changed bytes")
			}
			windowsAssertEntries(t, filepath.Join(parent, result.JobDirectory), 1)
		})
	}
}

func windowsPrivateParent(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	user, err := windowsCurrentUser()
	if err != nil {
		t.Fatal(err)
	}
	root, err := windowsOpenParent(base)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(root)
	parent, err := windowsCreatePrivate(root, "private-parent", true, user)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.CloseHandle(parent); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "private-parent")
}

const windowsTestJob = "job-0123456789abcdef0123456789abcdef"

func windowsNamedOps() windowsOperations {
	ops := windowsFilesystemOperations()
	ops.name = func() (string, error) { return windowsTestJob, nil }
	return ops
}

func TestWindowsCandidateRejectsBroadDACLBeforePayload(t *testing.T) {
	for _, phase := range []string{"parent", "job", "file"} {
		t.Run(phase, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			user, err := windowsCurrentUser()
			if err != nil {
				t.Fatal(err)
			}
			setBroadDACL := func(handle syscall.Handle) {
				t.Helper()
				security := windowsDescriptor(user)
				// The final SYSTEM SID becomes S-1-1-0 (Everyone). The
				// current user's ACE and private ownership remain unchanged.
				security[len(security)-5] = 1
				clear(security[len(security)-4:])
				ok, _, _ := windowsAdvapi.NewProc("SetKernelObjectSecurity").Call(
					uintptr(handle), 4|0x80000000, uintptr(unsafe.Pointer(&security[0])))
				if ok == 0 {
					t.Fatal("native broad-DACL fixture could not be established")
				}
			}
			ops := windowsNamedOps()
			want := "output_create"
			if phase == "parent" {
				handle, err := windowsOpenParent(parent)
				if err != nil {
					t.Fatal(err)
				}
				setBroadDACL(handle)
				if err := syscall.CloseHandle(handle); err != nil {
					t.Fatal(err)
				}
				want = "output_parent"
			} else {
				ops.create = func(root syscall.Handle, name string, directory bool, user []byte) (syscall.Handle, error) {
					handle, err := windowsCreatePrivate(root, name, directory, user)
					if err == nil && (phase == "job" && directory || phase == "file" && !directory) {
						setBroadDACL(handle)
					}
					return handle, err
				}
			}
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), ops)
			requireFailure(t, result, err, want)
			if phase == "parent" {
				windowsAssertEntries(t, parent, 0)
			} else {
				job := filepath.Join(parent, windowsTestJob)
				if _, err := os.Lstat(filepath.Join(job, fileName)); !os.IsNotExist(err) {
					t.Fatal("unproven DACL reached publication")
				}
				if phase == "file" {
					got, err := os.ReadFile(filepath.Join(job, partialName))
					if err != nil || len(got) != 0 {
						t.Fatal("unproven DACL reached payload writing")
					}
				}
			}
		})
	}
}

func TestWindowsCandidateCollisionsPreserveOriginals(t *testing.T) {
	for _, phase := range []string{"job", "partial", "final"} {
		for _, kind := range []string{"regular", "directory", "hardlink"} {
			t.Run(phase+"/"+kind, func(t *testing.T) {
				parent := windowsPrivateParent(t)
				source := filepath.Join(t.TempDir(), "source.txt")
				if err := os.WriteFile(source, []byte("synthetic original"), 0600); err != nil {
					t.Fatal(err)
				}
				job := filepath.Join(parent, windowsTestJob)
				collision := job
				if phase == "partial" {
					collision = filepath.Join(job, partialName)
				} else if phase == "final" {
					collision = filepath.Join(job, fileName)
				}
				createCollision := func() {
					t.Helper()
					var err error
					switch kind {
					case "regular":
						err = os.WriteFile(collision, []byte("synthetic original"), 0600)
					case "directory":
						err = os.Mkdir(collision, 0700)
						if err == nil {
							err = os.WriteFile(filepath.Join(collision, "keep.txt"), []byte("synthetic original"), 0600)
						}
					case "hardlink":
						err = os.Link(source, collision)
					}
					if err != nil {
						t.Fatal("native collision fixture could not be established")
					}
				}
				ops := windowsNamedOps()
				want := "output_create"
				switch phase {
				case "job":
					createCollision()
				case "partial":
					ops.create = func(root syscall.Handle, name string, directory bool, user []byte) (syscall.Handle, error) {
						if !directory {
							createCollision()
						}
						return windowsCreatePrivate(root, name, directory, user)
					}
				case "final":
					want = "output_publish"
					ops.publish = func(file, directory syscall.Handle, name string) error {
						createCollision()
						return windowsPublish(file, directory, name)
					}
				}
				result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("new synthetic"), ops)
				requireFailure(t, result, err, want)
				for _, path := range []string{source, collision} {
					if path == collision && kind == "directory" {
						path = filepath.Join(path, "keep.txt")
					}
					got, err := os.ReadFile(path)
					if err != nil || string(got) != "synthetic original" {
						t.Fatal("collision or existing source changed")
					}
				}
			})
		}
	}
}

func TestWindowsCandidateFaultsReturnNoCompletion(t *testing.T) {
	fault := errors.New("synthetic /untrusted-path fault")
	for name, test := range map[string]struct {
		code      string
		configure func(*windowsOperations)
	}{
		"random": {"output_create", func(ops *windowsOperations) { ops.name = func() (string, error) { return "", fault } }},
		"create": {"output_create", func(ops *windowsOperations) {
			ops.create = func(syscall.Handle, string, bool, []byte) (syscall.Handle, error) {
				return syscall.InvalidHandle, fault
			}
		}},
		"write": {"output_write", func(ops *windowsOperations) {
			ops.write = func(*os.File, []byte) (int, error) { return 0, fault }
		}},
		"short write": {"output_write", func(ops *windowsOperations) {
			ops.write = func(file *os.File, payload []byte) (int, error) { return file.Write(payload[:1]) }
		}},
		"sync": {"output_sync", func(ops *windowsOperations) { ops.sync = func(*os.File) error { return fault } }},
		"readback": {"output_readback", func(ops *windowsOperations) {
			ops.read = func(*os.File, []byte) (int, error) { return 0, fault }
		}},
		"publish": {"output_publish", func(ops *windowsOperations) {
			ops.publish = func(syscall.Handle, syscall.Handle, string) error { return fault }
		}},
		"close": {"output_close", func(ops *windowsOperations) {
			ops.close = func(file *os.File) error { file.Close(); return fault }
		}},
	} {
		t.Run(name, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			ops := windowsNamedOps()
			test.configure(&ops)
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), ops)
			requireFailure(t, result, err, test.code)
		})
	}
}

func TestWindowsCandidateCancellationAtPublicationBoundaries(t *testing.T) {
	for _, phase := range []string{"after create", "after write", "before publish", "after publish", "after close"} {
		t.Run(phase, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := windowsNamedOps()
			switch phase {
			case "after create":
				ops.create = func(root syscall.Handle, name string, directory bool, user []byte) (syscall.Handle, error) {
					handle, err := windowsCreatePrivate(root, name, directory, user)
					cancel()
					return handle, err
				}
			case "after write":
				ops.write = func(file *os.File, payload []byte) (int, error) {
					n, err := file.Write(payload)
					cancel()
					return n, err
				}
			case "before publish":
				ops.read = func(file *os.File, payload []byte) (int, error) {
					n, err := file.Read(payload)
					if n == 0 {
						cancel()
					}
					return n, err
				}
			case "after publish":
				ops.publish = func(file, job syscall.Handle, name string) error {
					err := windowsPublish(file, job, name)
					cancel()
					return err
				}
			case "after close":
				ops.close = func(file *os.File) error { err := file.Close(); cancel(); return err }
			}
			result, err := writeWindowsWithOps(ctx, parent, fileName, []byte("synthetic"), ops)
			requireFailure(t, result, err, "output_cancelled")
			published := phase == "after publish" || phase == "after close"
			_, statErr := os.Lstat(filepath.Join(parent, windowsTestJob, fileName))
			if published && statErr != nil || !published && !os.IsNotExist(statErr) {
				t.Fatal("cancellation publication boundary changed")
			}
		})
	}
}

func TestWindowsCandidateRejectsDeviceAndUNCPathsWithoutEffects(t *testing.T) {
	for _, path := range []string{`\\server\share\synthetic`, `\\.\pipe\synthetic`, `\\?\C:\synthetic`} {
		result, err := writeWindowsCandidate(context.Background(), path, []byte("synthetic"))
		requireFailure(t, result, err, "output_parent")
	}
}

func TestWindowsCandidateAnchoredRenamesCannotRedirectWrites(t *testing.T) {
	for _, phase := range []string{"parent", "job"} {
		t.Run(phase, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			ops := windowsNamedOps()
			moved := parent + "-moved"
			replacement := parent
			if phase == "job" {
				replacement = filepath.Join(parent, windowsTestJob)
			}
			ops.create = func(root syscall.Handle, name string, directory bool, user []byte) (syscall.Handle, error) {
				if phase == "parent" && directory || phase == "job" && !directory {
					if err := os.Rename(replacement, moved); err != nil {
						t.Fatal("native opened-directory rename fixture failed")
					}
					if err := os.Mkdir(replacement, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(replacement, "keep.txt"), []byte("synthetic original"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				return windowsCreatePrivate(root, name, directory, user)
			}
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), ops)
			if err != nil || result.FileName != fileName {
				t.Fatalf("anchored native write failed: %v", err)
			}
			outputJob := moved
			if phase == "parent" {
				outputJob = filepath.Join(moved, windowsTestJob)
			}
			got, err := os.ReadFile(filepath.Join(outputJob, fileName))
			if err != nil || string(got) != "synthetic" {
				t.Fatal("opened directory did not retain the payload")
			}
			got, err = os.ReadFile(filepath.Join(replacement, "keep.txt"))
			if err != nil || string(got) != "synthetic original" {
				t.Fatal("replacement changed")
			}
			windowsAssertEntries(t, replacement, 1)
		})
	}
}

func TestWindowsCandidateRejectsReparseParentAndExistingJob(t *testing.T) {
	for _, phase := range []string{"parent", "job"} {
		t.Run(phase, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			target := windowsPrivateParent(t)
			link := parent + "-link"
			if phase == "job" {
				link = filepath.Join(parent, windowsTestJob)
			}
			if err := os.Symlink(target, link); err != nil {
				if errors.Is(err, syscall.Errno(1314)) {
					t.Skip("native reparse fixture requires symlink privilege or Developer Mode")
				}
				t.Fatal("native reparse fixture could not be established")
			}
			ops := windowsNamedOps()
			want := "output_create"
			if phase == "parent" {
				parent = link
				want = "output_parent"
			}
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), ops)
			requireFailure(t, result, err, want)
			windowsAssertEntries(t, target, 0)
			if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Fatal("existing reparse entry changed")
			}
		})
	}
}

func windowsAssertEntries(t *testing.T, path string, count int) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != count {
		t.Fatal("unexpected filesystem artifact")
	}
}
