package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBinaryVersionReportsLinkerMetadataAndClosedPipeFailure(t *testing.T) {
	const version = "v1.2.3-rc.1+synthetic"
	const commit = "0123456789abcdef0123456789abcdef01234567"
	binary := filepath.Join(t.TempDir(), "pwmigrate-go")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	// A cold -trimpath build recompiles maintained crypto dependencies on small
	// native runners. Keep its budget separate from short runtime pipe checks.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags",
		"-X github.com/akvartz/Bitwarden21Password/internal/buildinfo.Version="+version+
			" -X github.com/akvartz/Bitwarden21Password/internal/buildinfo.Commit="+commit,
		"-o", binary, "../../cmd/pwmigrate")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build stamped CLI: %v\n%s", err, output)
	}
	t.Run("stamped_json", func(t *testing.T) {
		runCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		cmd := exec.CommandContext(runCtx, binary, "version", "--json")
		cmd.Dir = t.TempDir()
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("run stamped CLI: %v; stderr %q", err, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatal("version success wrote stderr")
		}
		var got map[string]string
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{
			"program": "pwmigrate-go", "version": version, "commit": commit,
			"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("linker metadata mismatch: got %v, want %v", got, want)
		}
	})
	for _, args := range [][]string{{"version"}, {"version", "--json"}, {"--version"}} {
		t.Run("closed_pipe_"+strings.Join(args, "_"), func(t *testing.T) {
			runCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			cmd := exec.CommandContext(runCtx, binary, args...)
			cmd.Dir = t.TempDir()
			var stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = closedSyntheticPipe(t), &stderr
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || stderr.String() != "output_write\n" {
				t.Fatalf("closed version pipe must return I/O exit 1: %v; stderr %q", err, stderr.String())
			}
		})
	}
}
