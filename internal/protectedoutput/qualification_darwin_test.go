//go:build darwin

package protectedoutput

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These destructive fixtures are limited to newly-created temporary images and
// directories. Ordinary native tests remain unprivileged; opting in makes
// missing tools or sudo privileges a failed qualification, never a skip.
func darwinQualification(t *testing.T) {
	t.Helper()
	if os.Getenv("PWMIGRATE_NATIVE_PRIVACY_QUALIFY") != "1" {
		t.Skip("privileged native privacy qualification was not requested")
	}
	for _, tool := range []string{"/usr/bin/sudo", "/usr/bin/hdiutil", "/usr/sbin/diskutil", "/usr/sbin/chown", "/bin/chmod", "/bin/cat", "/bin/ls", "/bin/mkdir", "/bin/rm", "/usr/bin/id"} {
		if info, err := os.Stat(tool); err != nil || !info.Mode().IsRegular() {
			t.Fatal("required native qualification tool is unavailable")
		}
	}
	uid := darwinQualificationCommand(t, "/usr/bin/sudo", "-n", "-u", "nobody", "/usr/bin/id", "-u")
	value, err := strconv.Atoi(strings.TrimSpace(string(uid)))
	if err != nil || value == os.Geteuid() || value == 0 {
		t.Fatal("native second-principal fixture was not established")
	}
}

func darwinQualificationCommand(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		t.Fatal("native qualification fixture command failed")
	}
	return output
}

func darwinQualificationDenied(t *testing.T, name string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := exec.CommandContext(ctx, "/usr/bin/sudo", append([]string{"-n", "-u", "nobody", name}, args...)...).Run()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatal("native second principal was not denied access")
	}
}

func darwinQualificationVolumePremise(t *testing.T, path, want string, owners, readonly bool) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("native volume premise open failed")
	}
	var fs syscall.Statfs_t
	statErr := syscall.Fstatfs(int(file.Fd()), &fs)
	closeErr := file.Close()
	var name []byte
	for _, value := range fs.Fstypename {
		if value == 0 {
			break
		}
		name = append(name, byte(value))
	}
	if statErr != nil || closeErr != nil || string(name) != want || fs.Flags&0x1000 == 0 ||
		(want != "msdos" && (fs.Flags&0x200000 == 0) != owners) || (fs.Flags&1 != 0) != readonly {
		t.Fatal("native volume policy premise was not established")
	}
}

func TestDarwinNativeQualificationSecondPrincipal(t *testing.T) {
	darwinQualification(t)
	// /private/tmp and this 0755 parent are traversable by nobody. A readable
	// control proves that failed access is attributable to the artifact modes.
	parent, err := os.MkdirTemp("/private/tmp", "pwmigrate-native-privacy-")
	if err != nil {
		t.Fatal("native accessible-parent fixture failed")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(parent); err != nil {
			t.Error("native owned-directory cleanup failed")
		}
	})
	if os.Chmod(parent, 0755) != nil {
		t.Fatal("native accessible-parent fixture failed")
	}
	control := filepath.Join(parent, "control.txt")
	if os.WriteFile(control, []byte("synthetic control"), 0644) != nil || os.Chmod(control, 0644) != nil {
		t.Fatal("native readable control fixture failed")
	}
	got := darwinQualificationCommand(t, "/usr/bin/sudo", "-n", "-u", "nobody", "/bin/cat", control)
	if !bytes.Equal(got, []byte("synthetic control")) {
		t.Fatal("native second principal could not reach readable control")
	}
	for _, retained := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "retained_partial"}[retained], func(t *testing.T) {
			ops := filesystemOperations()
			var job string
			ops.name = func() (string, error) {
				name, err := randomJobName()
				job = name
				return name, err
			}
			if retained {
				ops.sync = func(*os.File) error { return errors.New("synthetic failure") }
			}
			result, err := writeWithOps(context.Background(), parent, []byte("synthetic private bytes"), ops)
			name := fileName
			if retained {
				requireFailure(t, result, err, "output_sync")
				name = partialName
			} else if err != nil || result.JobDirectory != job {
				t.Fatal("native publication fixture failed")
			}
			jobPath := filepath.Join(parent, job)
			filePath := filepath.Join(jobPath, name)
			assertContents(t, filePath, "synthetic private bytes")
			darwinQualificationDenied(t, "/bin/ls", jobPath)
			darwinQualificationDenied(t, "/bin/cat", filePath)
			darwinQualificationDenied(t, "/bin/mkdir", filepath.Join(jobPath, "forbidden"))
			darwinQualificationDenied(t, "/bin/rm", filePath)
			assertContents(t, filePath, "synthetic private bytes")
		})
	}
	darwinQualificationDenied(t, "/bin/mkdir", filepath.Join(parent, "forbidden"))
}

func TestDarwinNativeQualificationForeignOwner(t *testing.T) {
	darwinQualification(t)
	parent := t.TempDir()
	// Read/traverse access remains available, so rejection exercises the
	// actual inode owner policy rather than an inaccessible directory.
	if os.Chmod(parent, 0755) != nil {
		t.Fatal("native foreign-owner accessible-parent fixture failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if exec.CommandContext(ctx, "/usr/bin/sudo", "-n", "/usr/sbin/chown", strconv.Itoa(os.Geteuid()), parent).Run() != nil {
			t.Error("native owned-parent owner restoration failed")
		}
	})
	darwinQualificationCommand(t, "/usr/bin/sudo", "-n", "/usr/sbin/chown", "nobody", parent)
	file, err := os.Open(parent)
	if err != nil {
		t.Fatal("native foreign-owner parent was not accessible")
	}
	info, statErr := file.Stat()
	closeErr := file.Close()
	if statErr != nil || closeErr != nil || owned(info) {
		t.Fatal("native foreign inode owner premise was not established")
	}
	result, err := writeDarwinCandidate(context.Background(), parent, []byte("synthetic"))
	requireFailure(t, result, err, "output_parent")
	assertEmpty(t, parent)
}

func TestDarwinNativeQualificationVolumes(t *testing.T) {
	darwinQualification(t)
	for _, fs := range []string{"APFS", "HFS+", "MS-DOS FAT32"} {
		t.Run(fs, func(t *testing.T) {
			base := t.TempDir()
			image := filepath.Join(base, "qualification.sparseimage")
			mount := filepath.Join(base, "mount")
			if os.Mkdir(mount, 0700) != nil {
				t.Fatal("native image mountpoint fixture failed")
			}
			// A sparse image is bounded to 128 MiB and contains only test data.
			darwinQualificationCommand(t, "/usr/bin/hdiutil", "create", "-size", "128m", "-type", "SPARSE", "-fs", fs, "-volname", "pwmigrate-synthetic", image)
			mounted := false
			attach := func(readonly bool) {
				t.Helper()
				owners := "on"
				if fs == "MS-DOS FAT32" {
					// FAT cannot store per-file Unix ownership. Enforcing image
					// root ownership makes a writable volume inaccessible to the
					// ordinary caller instead of establishing the intended fixture.
					owners = "off"
				}
				args := []string{"attach", "-nobrowse", "-owners", owners, "-mountpoint", mount}
				if readonly {
					args = append(args, "-readonly")
				}
				mounted = true
				darwinQualificationCommand(t, "/usr/bin/hdiutil", append(args, image)...)
			}
			detach := func() {
				t.Helper()
				darwinQualificationCommand(t, "/usr/bin/hdiutil", "detach", mount)
				mounted = false
			}
			t.Cleanup(func() {
				if mounted {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					if exec.CommandContext(ctx, "/usr/bin/hdiutil", "detach", mount).Run() != nil {
						t.Error("native owned-image cleanup failed")
					}
				}
			})
			attach(false)
			parent := filepath.Join(mount, "private-parent")
			if os.Mkdir(parent, 0700) != nil {
				t.Fatal("native volume parent fixture failed")
			}
			if fs == "MS-DOS FAT32" {
				// FAT is rejected by filesystem type, independently of whatever
				// ownership mount flag hdiutil establishes. An ordinary-caller
				// write/read/delete control proves the image is actually writable.
				darwinQualificationVolumePremise(t, parent, "msdos", false, false)
				control := filepath.Join(parent, "synthetic-control.txt")
				if os.WriteFile(control, []byte("synthetic control"), 0600) != nil {
					t.Fatal("native unsupported-volume write control failed")
				}
				value, err := os.ReadFile(control)
				if err != nil || !bytes.Equal(value, []byte("synthetic control")) || os.Remove(control) != nil {
					t.Fatal("native unsupported-volume read/delete control failed")
				}
				result, err := writeDarwinCandidate(context.Background(), parent, []byte("synthetic"))
				requireFailure(t, result, err, "output_parent")
				assertEmpty(t, parent)
				return
			}
			if os.Chmod(parent, 0700) != nil {
				t.Fatal("native volume private-parent fixture failed")
			}
			kind := map[string]string{"APFS": "apfs", "HFS+": "hfs"}[fs]
			darwinQualificationVolumePremise(t, parent, kind, true, false)
			result, err := writeDarwinCandidate(context.Background(), parent, []byte("synthetic"))
			if err != nil {
				t.Fatal("native supported-volume publication failed")
			}
			assertContents(t, filepath.Join(parent, result.JobDirectory, result.FileName), "synthetic")
			// A separate empty parent makes each rejection's absence of output
			// observable without modifying or interpreting existing artifacts.
			rejected := filepath.Join(mount, "rejected-parent")
			if os.Mkdir(rejected, 0700) != nil || os.Chmod(rejected, 0700) != nil {
				t.Fatal("native rejected-volume parent fixture failed")
			}
			darwinQualificationCommand(t, "/usr/bin/sudo", "-n", "/usr/sbin/diskutil", "disableOwnership", mount)
			darwinQualificationVolumePremise(t, rejected, kind, false, false)
			result, err = writeDarwinCandidate(context.Background(), rejected, []byte("synthetic"))
			requireFailure(t, result, err, "output_parent")
			assertEmpty(t, rejected)
			darwinQualificationCommand(t, "/usr/bin/sudo", "-n", "/usr/sbin/diskutil", "enableOwnership", mount)
			detach()
			attach(true)
			darwinQualificationVolumePremise(t, rejected, kind, true, true)
			result, err = writeDarwinCandidate(context.Background(), rejected, []byte("synthetic"))
			requireFailure(t, result, err, "output_parent")
			assertEmpty(t, rejected)
		})
	}
}
