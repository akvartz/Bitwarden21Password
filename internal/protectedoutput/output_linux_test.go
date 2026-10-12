//go:build linux

package protectedoutput

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const testJobName = "job-0123456789abcdef0123456789abcdef"
const testPartial = ".bitwarden.json.partial"

var syntheticFault = errors.New("synthetic fault /untrusted-path payload-marker")

func TestWritePrivateExactAndNoClobber(t *testing.T) {
	parent := privateParent(t)
	source := filepath.Join(parent, "source.txt")
	if err := os.WriteFile(source, []byte("synthetic original"), 0600); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(parent, "sibling.txt")
	if err := os.Link(source, sibling); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("{\"items\":[\" synthetic \",\"\\r\\n\",\"世界\"]}\n")
	var previous Result
	for range 2 {
		result, err := Write(context.Background(), parent, payload)
		if err != nil {
			t.Fatalf("write failed: %v", err)
		}
		if result.JobDirectory == "" || filepath.Base(result.JobDirectory) != result.JobDirectory || result.FileName != "bitwarden.json" {
			t.Fatal("result must contain only a generated basename and the fixed filename")
		}
		if result.JobDirectory == previous.JobDirectory {
			t.Fatal("second export reused a job directory")
		}
		job := filepath.Join(parent, result.JobDirectory)
		assertModeOwner(t, job, true, 0700)
		final := filepath.Join(job, "bitwarden.json")
		assertModeOwner(t, final, false, 0600)
		got, err := os.ReadFile(final)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatal("published bytes differ from the supplied payload")
		}
		assertAbsent(t, filepath.Join(job, testPartial))
		previous = result
	}
	for _, path := range []string{source, sibling} {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != "synthetic original" {
			t.Fatal("existing source or hardlink changed")
		}
		after, err := os.Stat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
			t.Fatal("existing source metadata changed")
		}
	}
}

func TestWriteRejectsInsecureOrInvalidParent(t *testing.T) {
	for _, mode := range []os.FileMode{0777, 0770, 0702, 0720} {
		t.Run(mode.String(), func(t *testing.T) {
			parent := privateParent(t)
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal(err)
			}
			result, err := Write(context.Background(), parent, []byte("synthetic payload"))
			requireFailure(t, result, err, "output_parent")
			assertEmpty(t, parent)
		})
	}
	t.Run("missing", func(t *testing.T) {
		parent := filepath.Join(privateParent(t), "missing")
		result, err := Write(context.Background(), parent, nil)
		requireFailure(t, result, err, "output_parent")
		assertAbsent(t, parent)
	})
	t.Run("regular file", func(t *testing.T) {
		parent := filepath.Join(privateParent(t), "parent.txt")
		if err := os.WriteFile(parent, []byte("synthetic original"), 0600); err != nil {
			t.Fatal(err)
		}
		result, err := Write(context.Background(), parent, nil)
		requireFailure(t, result, err, "output_parent")
		assertContents(t, parent, "synthetic original")
	})
}

func TestWriteRejectsForeignParentOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("real foreign-owner fixture requires chown privilege")
	}
	parent := privateParent(t)
	if err := os.Chown(parent, 1, -1); err != nil {
		t.Fatal(err)
	}
	result, err := Write(context.Background(), parent, nil)
	requireFailure(t, result, err, "output_parent")
	assertEmpty(t, parent)
}

func TestWriteCancelledCreatesNothing(t *testing.T) {
	parent := privateParent(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Write(ctx, parent, []byte("synthetic payload"))
	requireFailure(t, result, err, "output_cancelled")
	assertEmpty(t, parent)
}

func TestJobCollisionDoesNotReuseOrRemoveEntries(t *testing.T) {
	for _, kind := range []string{"directory", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			parent := privateParent(t)
			target := filepath.Join(privateParent(t), "original")
			if err := os.WriteFile(target, []byte("synthetic original"), 0600); err != nil {
				t.Fatal(err)
			}
			job := filepath.Join(parent, testJobName)
			var err error
			switch kind {
			case "directory":
				err = os.Mkdir(job, 0700)
				if err == nil {
					err = os.WriteFile(filepath.Join(job, "keep.txt"), []byte("synthetic original"), 0600)
				}
			case "symlink":
				err = os.Symlink(filepath.Dir(target), job)
			case "hardlink":
				err = os.Link(target, job)
			}
			if err != nil {
				t.Fatal(err)
			}
			result, err := writeWithOps(context.Background(), parent, []byte("new synthetic payload"), namedOps())
			requireFailure(t, result, err, "output_create")
			if _, err := os.Lstat(job); err != nil {
				t.Fatal("existing entry was removed")
			}
			if kind == "directory" {
				assertContents(t, filepath.Join(job, "keep.txt"), "synthetic original")
			}
			assertContents(t, target, "synthetic original")
		})
	}
}

func TestPartialAndFinalCollisionsLeaveOriginals(t *testing.T) {
	for _, phase := range []string{"partial", "final"} {
		for _, kind := range []string{"symlink", "hardlink", "regular", "directory"} {
			t.Run(phase+"/"+kind, func(t *testing.T) {
				parent := privateParent(t)
				target := filepath.Join(privateParent(t), "original.txt")
				if err := os.WriteFile(target, []byte("synthetic original"), 0600); err != nil {
					t.Fatal(err)
				}
				createCollision := func(r *os.Root, name string) {
					t.Helper()
					var err error
					switch kind {
					case "symlink":
						err = r.Symlink(target, name)
					case "hardlink":
						err = os.Link(target, filepath.Join(parent, testJobName, name))
					case "regular":
						err = r.WriteFile(name, []byte("synthetic original"), 0600)
					case "directory":
						err = r.Mkdir(name, 0700)
						if err == nil {
							err = r.WriteFile(name+"/keep.txt", []byte("synthetic original"), 0600)
						}
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				ops := namedOps()
				wantCode := "output_create"
				entry := testPartial
				if phase == "partial" {
					ops.openFile = func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
						createCollision(r, name)
						return r.OpenFile(name, flag, perm)
					}
				} else {
					wantCode = "output_publish"
					entry = "bitwarden.json"
					ops.link = func(r *os.Root, old, new string) error {
						createCollision(r, new)
						return r.Link(old, new)
					}
				}
				result, err := writeWithOps(context.Background(), parent, []byte("new synthetic payload"), ops)
				requireFailure(t, result, err, wantCode)
				assertContents(t, target, "synthetic original")
				path := filepath.Join(parent, testJobName, entry)
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("collision entry was removed")
				}
				if kind == "regular" {
					assertContents(t, path, "synthetic original")
				} else if kind == "directory" {
					assertContents(t, filepath.Join(path, "keep.txt"), "synthetic original")
				}
				if phase == "final" {
					assertContents(t, filepath.Join(parent, testJobName, testPartial), "new synthetic payload")
				}
			})
		}
	}
}

func TestCreatedModesMustBeExact(t *testing.T) {
	for _, phase := range []string{"job", "file"} {
		t.Run(phase, func(t *testing.T) {
			parent := privateParent(t)
			ops := namedOps()
			if phase == "job" {
				ops.mkdir = func(r *os.Root, name string, perm os.FileMode) error {
					return r.Mkdir(name, 0750)
				}
			} else {
				ops.openFile = func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
					return r.OpenFile(name, flag, 0640)
				}
			}
			result, err := writeWithOps(context.Background(), parent, []byte("synthetic payload"), ops)
			requireFailure(t, result, err, "output_create")
			assertAbsent(t, filepath.Join(parent, testJobName, "bitwarden.json"))
		})
	}
}

func TestRestrictiveUmaskFailsClosed(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "-test.run=^TestRestrictiveUmaskProcess$", "--", "umask-check")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("restrictive umask process failed: %v\n%s", err, out)
	}
}

func TestRestrictiveUmaskProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] != "umask-check" {
		t.Skip("isolated subprocess only")
	}
	parent := privateParent(t)
	previous := syscall.Umask(0777)
	defer syscall.Umask(previous)
	result, err := writeWithOps(context.Background(), parent, []byte("synthetic payload"), namedOps())
	requireFailure(t, result, err, "output_create")
	job := filepath.Join(parent, testJobName)
	info, err := os.Stat(job)
	if err != nil || info.Mode().Perm() != 0 {
		t.Fatal("restrictive umask was ignored or private failure artifact removed")
	}
	if err := os.Chmod(job, 0700); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, filepath.Join(job, "bitwarden.json"))
}

func TestOperationFailuresReturnNoResult(t *testing.T) {
	tests := []struct {
		name      string
		code      string
		published bool
		partial   bool
		configure func(*operations)
	}{
		{"random", "output_create", false, false, func(o *operations) {
			o.name = func() (string, error) { return "", syntheticFault }
		}},
		{"mkdir", "output_create", false, false, func(o *operations) {
			o.mkdir = func(*os.Root, string, os.FileMode) error { return syntheticFault }
		}},
		{"open", "output_create", false, false, func(o *operations) {
			o.openFile = func(*os.Root, string, int, os.FileMode) (*os.File, error) { return nil, syntheticFault }
		}},
		{"write", "output_write", false, true, func(o *operations) {
			o.write = func(f *os.File, p []byte) (int, error) { n, _ := f.Write(p[:1]); return n, syntheticFault }
		}},
		{"short write", "output_write", false, true, func(o *operations) {
			o.write = func(f *os.File, p []byte) (int, error) { return f.Write(p[:1]) }
		}},
		{"zero write", "output_write", false, true, func(o *operations) {
			o.write = func(*os.File, []byte) (int, error) { return 0, nil }
		}},
		{"payload sync", "output_sync", false, true, func(o *operations) {
			o.sync = func(*os.File) error { return syntheticFault }
		}},
		{"seek", "output_readback", false, true, func(o *operations) {
			o.seek = func(*os.File, int64, int) (int64, error) { return 0, syntheticFault }
		}},
		{"read", "output_readback", false, true, func(o *operations) {
			o.read = func(*os.File, []byte) (int, error) { return 0, syntheticFault }
		}},
		{"zero read", "output_readback", false, true, func(o *operations) {
			o.read = func(*os.File, []byte) (int, error) { return 0, nil }
		}},
		{"read mismatch", "output_readback", false, true, func(o *operations) {
			o.read = func(f *os.File, p []byte) (int, error) {
				n, err := f.Read(p)
				if n > 0 {
					p[0] ^= 1
				}
				return n, err
			}
		}},
		{"extra bytes", "output_readback", false, true, func(o *operations) {
			o.write = func(f *os.File, p []byte) (int, error) {
				n, err := f.Write(p)
				if err == nil {
					_, err = f.Write([]byte("extra"))
				}
				return n, err
			}
		}},
		{"payload close", "output_close", false, true, func(o *operations) {
			o.close = func(f *os.File) error {
				info, err := f.Stat()
				if err != nil {
					return err
				}
				err = f.Close()
				if !info.IsDir() {
					return syntheticFault
				}
				return err
			}
		}},
		{"link", "output_publish", false, true, func(o *operations) {
			o.link = func(*os.Root, string, string) error { return syntheticFault }
		}},
		{"remove", "output_publish", true, true, func(o *operations) {
			o.remove = func(*os.Root, string) error { return syntheticFault }
		}},
		{"job sync", "output_sync", true, false, func(o *operations) {
			o.sync = directoryFault(t, false, false)
		}},
		{"parent sync", "output_sync", true, false, func(o *operations) {
			o.sync = directoryFault(t, true, false)
		}},
		{"job close", "output_close", true, false, func(o *operations) {
			o.close = directoryFault(t, false, true)
		}},
		{"parent close", "output_close", true, false, func(o *operations) {
			o.close = directoryFault(t, true, true)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := privateParent(t)
			ops := namedOps()
			tt.configure(&ops)
			result, err := writeWithOps(context.Background(), parent, []byte("synthetic payload"), ops)
			requireFailure(t, result, err, tt.code)
			job := filepath.Join(parent, testJobName)
			if tt.name == "random" || tt.name == "mkdir" {
				assertEmpty(t, parent)
				return
			}
			assertModeOwner(t, job, true, 0700)
			assertPresence(t, filepath.Join(job, "bitwarden.json"), tt.published)
			assertPresence(t, filepath.Join(job, testPartial), tt.partial)
			if tt.published {
				assertContents(t, filepath.Join(job, "bitwarden.json"), "synthetic payload")
			}
		})
	}
}

func TestCancellationAtPublicationBoundaries(t *testing.T) {
	for _, phase := range []string{"after write", "before link", "after link", "after remove", "after parent close"} {
		t.Run(phase, func(t *testing.T) {
			parent := privateParent(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ops := namedOps()
			switch phase {
			case "after write":
				ops.write = func(f *os.File, p []byte) (int, error) { n, err := f.Write(p); cancel(); return n, err }
			case "before link":
				ops.close = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					err = f.Close()
					if !info.IsDir() {
						cancel()
					}
					return err
				}
			case "after link":
				ops.link = func(r *os.Root, old, new string) error { err := r.Link(old, new); cancel(); return err }
			case "after remove":
				ops.remove = func(r *os.Root, name string) error { err := r.Remove(name); cancel(); return err }
			case "after parent close":
				count := 0
				ops.close = func(f *os.File) error {
					info, err := f.Stat()
					if err != nil {
						return err
					}
					err = f.Close()
					if info.IsDir() {
						count++
						if count == 2 {
							cancel()
						}
					}
					return err
				}
			}
			result, err := writeWithOps(ctx, parent, []byte("synthetic payload"), ops)
			requireFailure(t, result, err, "output_cancelled")
			job := filepath.Join(parent, testJobName)
			published := phase == "after link" || phase == "after remove" || phase == "after parent close"
			partial := phase != "after remove" && phase != "after parent close"
			assertPresence(t, filepath.Join(job, "bitwarden.json"), published)
			assertPresence(t, filepath.Join(job, testPartial), partial)
		})
	}
}

func TestRootedRenamesCannotRedirectWrites(t *testing.T) {
	for _, phase := range []string{"parent", "job"} {
		t.Run(phase, func(t *testing.T) {
			base := privateParent(t)
			parent := filepath.Join(base, "parent")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			ops := namedOps()
			moved := filepath.Join(base, "moved")
			movedParent := moved
			replacement := parent
			if phase == "parent" {
				ops.mkdir = func(r *os.Root, name string, perm os.FileMode) error {
					if err := os.Rename(parent, movedParent); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(parent, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(parent, "keep.txt"), []byte("synthetic original"), 0600); err != nil {
						t.Fatal(err)
					}
					return r.Mkdir(name, perm)
				}
				moved = filepath.Join(moved, testJobName)
			} else {
				replacement = filepath.Join(parent, testJobName)
				ops.openFile = func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
					if err := os.Rename(replacement, moved); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(replacement, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(replacement, "keep.txt"), []byte("synthetic original"), 0600); err != nil {
						t.Fatal(err)
					}
					return r.OpenFile(name, flag, perm)
				}
			}
			result, err := writeWithOps(context.Background(), parent, []byte("synthetic payload"), ops)
			if err != nil || result.FileName != "bitwarden.json" {
				t.Fatalf("rooted write failed: %v", err)
			}
			assertContents(t, filepath.Join(moved, "bitwarden.json"), "synthetic payload")
			assertContents(t, filepath.Join(replacement, "keep.txt"), "synthetic original")
			entries, err := os.ReadDir(replacement)
			if err != nil || len(entries) != 1 {
				t.Fatal("replacement received output writes")
			}
		})
	}
}

func TestReadbackUsesSameHandleAndHandlesShortReads(t *testing.T) {
	parent := privateParent(t)
	ops := namedOps()
	var opened *os.File
	ops.openFile = func(r *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := r.OpenFile(name, flag, perm)
		opened = f
		return f, err
	}
	ops.read = func(f *os.File, p []byte) (int, error) {
		if f != opened {
			t.Fatal("readback reopened a path instead of using the write handle")
		}
		if len(p) > 3 {
			p = p[:3]
		}
		return f.Read(p)
	}
	payload := []byte(strings.Repeat("synthetic-界", 7000))
	result, err := writeWithOps(context.Background(), parent, payload, ops)
	if err != nil {
		t.Fatalf("chunked readback failed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(parent, result.JobDirectory, result.FileName))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatal("chunked output lost bytes")
	}
}

func TestWriteEmptyPayload(t *testing.T) {
	parent := privateParent(t)
	result, err := Write(context.Background(), parent, nil)
	if err != nil {
		t.Fatalf("empty payload failed: %v", err)
	}
	assertContents(t, filepath.Join(parent, result.JobDirectory, result.FileName), "")
}

func directoryFault(t *testing.T, parent, closeFile bool) func(*os.File) error {
	t.Helper()
	count := 0
	return func(f *os.File) error {
		info, err := f.Stat()
		if err != nil {
			return err
		}
		var actual error
		if closeFile {
			actual = f.Close()
		} else {
			actual = f.Sync()
		}
		if info.IsDir() {
			count++
			if (!parent && count == 1) || (parent && count == 2) {
				return syntheticFault
			}
		}
		return actual
	}
}

func namedOps() operations {
	ops := filesystemOperations()
	ops.name = func() (string, error) { return testJobName, nil }
	return ops
}

func privateParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func assertModeOwner(t *testing.T, path string, directory bool, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
		t.Fatalf("wrong file type or private mode: %v", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatal("wrong inode owner")
	}
}

func assertContents(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatal("synthetic file content changed")
	}
}

func assertEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatal("unexpected filesystem artifact")
	}
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unexpected filesystem entry")
	}
}

func assertPresence(t *testing.T, path string, want bool) {
	t.Helper()
	if !want {
		assertAbsent(t, path)
		return
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("private failure artifact was removed")
	}
}
