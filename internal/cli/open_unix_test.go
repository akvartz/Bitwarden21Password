//go:build unix

package cli

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A subprocess timeout makes regressions to a blocking FIFO open fail instead of
// hanging the whole suite. Replacement is deterministic inside the opener seam.
func TestUnixRejectsFIFOAndReplacedRegularFileWithoutBlocking(t *testing.T) {
	for _, scenario := range []string{"fifo", "replacement"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestUnixFIFOHelper$", "-test.v")
			cmd.Env = append(os.Environ(), "PWMIGRATE_SYNTHETIC_FIFO_CASE="+scenario)
			if output, err := cmd.CombinedOutput(); err != nil {
				if ctx.Err() != nil {
					t.Fatal("nonregular-file open blocked")
				}
				t.Fatalf("nonregular-file safety helper failed: %v\n%s", err, output)
			}
		})
	}
}

func TestUnixFIFOHelper(t *testing.T) {
	scenario := os.Getenv("PWMIGRATE_SYNTHETIC_FIFO_CASE")
	if scenario == "" {
		t.Skip("subprocess helper")
	}
	path := filepath.Join(t.TempDir(), "SYNTHETIC_FIFO_PATH")
	open := fileOpener(openInput)
	if scenario == "replacement" {
		if err := os.WriteFile(path, []byte(syntheticCSV), 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatal("regular precheck fixture failed")
		}
		open = func(path string) (inputFile, error) {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			return openInput(path)
		}
	} else if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"inspect", "--input", path}, &stdout, &stderr, open)
	if code != 3 || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("input_not_regular")) {
		t.Fatalf("FIFO must be rejected after open, got exit %d", code)
	}
	assertRedacted(t, stderr.String(), path)
}

func TestUnixDeviceIsRejectedWithoutReading(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"inspect", "--input", "/dev/null"}, &stdout, &stderr)
	if code != 3 || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("input_not_regular")) {
		t.Fatalf("device must be rejected as invalid input, got exit %d", code)
	}
	assertRedacted(t, stderr.String(), "/dev/null")
}
