package cli

import (
	"bytes"
	"context"
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

func TestBinaryExitCodesRedactionAndNoFileMutations(t *testing.T) {
	binary := buildSyntheticCLI(t)
	cases := []struct {
		name  string
		args  func(string, string) []string
		want  int
		terms []string
	}{
		{"inventory", func(path, _ string) []string { return []string{"inspect", "--input", path, "--json"} }, 0, []string{`"records": 2`, `"fields": 8`, `"duplicate_groups"`}},
		{"selection", func(path, _ string) []string {
			return []string{"plan", "--input", path, "--to", "bitwarden-json", "--select", "2", "--json"}
		}, 0, []string{`"selected_records": 1`, `"excluded_records": 1`, `"output_emitted": false`, `"destination_import_verified": false`, `"record": 2`}},
		{"usage", func(path, _ string) []string { return []string{"plan", "--input", path} }, 2, []string{"invalid_arguments"}},
		{"malformed", func(_, bad string) []string { return []string{"inspect", "--input", bad, "--from", "chrome-csv"} }, 3, []string{"invalid_csv"}},
		{"missing", func(path, _ string) []string { return []string{"inspect", "--input", path + "-SYNTHETIC_MISSING"} }, 1, []string{"input_open"}},
		{"output_flag", func(path, _ string) []string {
			return []string{"plan", "--input", path, "--to", "bitwarden-json", "--output", "SYNTHETIC_OUTPUT"}
		}, 2, []string{"invalid_arguments"}},
		{"invalid_selection", func(path, _ string) []string {
			return []string{"plan", "--input", path, "--to", "bitwarden-json", "--select="}
		}, 3, []string{"invalid_selection"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "SYNTHETIC_SOURCE_PATH.csv")
			bad := filepath.Join(dir, "SYNTHETIC_MALFORMED_PATH.csv")
			// Independent fixtures: no migration/report helper constructs expectations.
			files := map[string][]byte{
				"SYNTHETIC_SOURCE_PATH.csv":    []byte("name,url,username,password\nSYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD_A\nSYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD_B\n"),
				"SYNTHETIC_MALFORMED_PATH.csv": []byte("name,url,username,password\nSYNTHETIC_TITLE,\"SYNTHETIC_BROKEN\n"),
				"SYNTHETIC_SIBLING.txt":        []byte("SYNTHETIC_SIBLING_UNCHANGED"),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotSyntheticDirectory(t, dir)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args(source, bad)...)
			cmd.Dir = dir
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("run actual CLI: %v", err)
				}
				code = exitErr.ExitCode()
			}
			if ctx.Err() != nil {
				t.Fatal("CLI timed out")
			}
			if code != tc.want {
				t.Fatalf("want actual exit %d, got %d", tc.want, code)
			}
			output := stdout.String() + stderr.String()
			for _, term := range tc.terms {
				if !strings.Contains(output, term) {
					t.Fatalf("missing actual CLI evidence %q", term)
				}
			}
			if tc.want == 0 && stderr.Len() != 0 {
				t.Fatal("success wrote stderr")
			}
			if tc.want != 0 && stdout.Len() != 0 {
				t.Fatal("failure emitted a report")
			}
			assertRedacted(t, output, source, bad, dir)
			after := snapshotSyntheticDirectory(t, dir)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("CLI changed source/sibling content, metadata, or directory entries")
			}
		})
	}
}

type syntheticSnapshot struct {
	data     string
	mode     os.FileMode
	size     int64
	modified time.Time
}

func snapshotSyntheticDirectory(t *testing.T, dir string) map[string]syntheticSnapshot {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]syntheticSnapshot, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Fatal("unexpected synthetic sibling type")
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = syntheticSnapshot{string(data), info.Mode(), info.Size(), info.ModTime()}
	}
	return result
}

func buildSyntheticCLI(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "pwmigrate-go")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "../../cmd/pwmigrate")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build actual CLI: %v\n%s", err, output)
	}
	return binary
}

func closedSyntheticPipe(t *testing.T) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { writer.Close() })
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return writer
}

// Passing a real closed pipe as fd 1/2 exercises os.Stdout/os.Stderr's special
// SIGPIPE behavior, which custom io.Writer failures do not reproduce.
func TestBinaryClosedPipesUseIOExit(t *testing.T) {
	binary := buildSyntheticCLI(t)
	cases := []struct {
		name                     string
		args                     func(string, string) []string
		closeStdout, closeStderr bool
	}{
		{"stdout_formats", func(_, _ string) []string { return []string{"formats"} }, true, false},
		{"stdout_inventory", func(path, _ string) []string { return []string{"inspect", "--input", path, "--json"} }, true, false},
		{"stdout_plan", func(path, _ string) []string { return []string{"plan", "--input", path, "--to", "bitwarden-json"} }, true, false},
		{"stderr_usage", func(_, _ string) []string { return []string{"SYNTHETIC_COMMAND"} }, false, true},
		{"stderr_invalid_input", func(_, bad string) []string { return []string{"inspect", "--input", bad, "--from", "chrome-csv"} }, false, true},
		{"stdout_and_stderr", func(_, _ string) []string { return []string{"formats"} }, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "SYNTHETIC_SOURCE_PATH.csv")
			malformed := filepath.Join(dir, "SYNTHETIC_MALFORMED_PATH.csv")
			files := map[string]string{
				"SYNTHETIC_SOURCE_PATH.csv":    "name,url,username,password\nSYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD\n",
				"SYNTHETIC_MALFORMED_PATH.csv": "name,url,username,password\nSYNTHETIC_TITLE,\"SYNTHETIC_BAD_QUOTE\n",
				"SYNTHETIC_SIBLING.txt":        "SYNTHETIC_SIBLING_UNCHANGED",
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotSyntheticDirectory(t, dir)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args(source, malformed)...)
			cmd.Dir = dir
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if tc.closeStdout {
				cmd.Stdout = closedSyntheticPipe(t)
			}
			if tc.closeStderr {
				cmd.Stderr = closedSyntheticPipe(t)
			}
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatal("closed-pipe CLI timed out")
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("want I/O exit 1, got %v", err)
			}
			if exitErr.ExitCode() != 1 {
				t.Fatalf("want I/O exit 1, got %d (%v)", exitErr.ExitCode(), exitErr)
			}
			if stdout.Len() != 0 {
				t.Fatal("closed-pipe failure emitted a report")
			}
			if tc.closeStdout && !tc.closeStderr && stderr.String() != "output_write\n" {
				t.Fatal("closed stdout must emit only the fixed safe error on writable stderr")
			}
			assertRedacted(t, stdout.String()+stderr.String(), source, malformed, dir)
			if !reflect.DeepEqual(before, snapshotSyntheticDirectory(t, dir)) {
				t.Fatal("closed-pipe failure changed source or sibling files")
			}
		})
	}
}
