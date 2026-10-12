package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func processExit(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal("synthetic CLI subprocess could not complete")
	}
	return exit.ExitCode()
}

func protocolApproval(review observedReview) string {
	words := []string{"approve", review.ReviewID}
	for _, issue := range review.Issues {
		words = append(words, issue.ID)
	}
	return strings.Join(words, " ") + "\n"
}

func TestBinaryConvertApprovalAndSourceSiblingsStayUnchanged(t *testing.T) {
	requireLinuxOutput(t)
	binary := buildSyntheticCLI(t)
	for _, approve := range []bool{false, true} {
		name := map[bool]string{false: "reject", true: "approve"}[approve]
		t.Run(name, func(t *testing.T) {
			sources := t.TempDir()
			source := filepath.Join(sources, "SYNTHETIC_SOURCE_PATH.csv")
			for name, contents := range map[string]string{"SYNTHETIC_SOURCE_PATH.csv": syntheticCSV, "SYNTHETIC_SIBLING.txt": "SYNTHETIC_UNCHANGED_SIBLING"} {
				if err := os.WriteFile(filepath.Join(sources, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := snapshotSyntheticDirectory(t, sources)
			parent := privateOutputParent(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, convertArgs(source, parent)...)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = input.Close()
				_ = cmd.Wait()
				t.Fatal("actual binary did not provide an approval review")
			}
			var event observedEvent
			if err := json.Unmarshal([]byte(line), &event); err != nil || event.Event != "review" || event.Review.ReviewID == "" {
				t.Fatal("actual binary review must be a typed compact event")
			}
			response := "decline\n"
			if approve {
				response = protocolApproval(event.Review)
			}
			if _, err := io.WriteString(input, response); err != nil {
				t.Fatal("could not send synthetic approval")
			}
			_ = input.Close()
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal("could not read actual binary completion")
			}
			code := processExit(t, cmd.Wait())
			if ctx.Err() != nil {
				t.Fatal("actual binary conversion timed out")
			}
			if approve {
				if code != 0 {
					t.Fatalf("approved actual binary conversion exited %d", code)
				}
				events := decodeEvents(t, line+string(remaining))
				if len(events) != 2 || events[1].Event != "completed" {
					t.Fatal("approved binary must emit exactly one completion")
				}
				entries, err := os.ReadDir(parent)
				if err != nil || len(entries) != 1 {
					t.Fatal("approved binary must create exactly one private job")
				}
				if _, err := os.Stat(filepath.Join(parent, events[1].Receipt.JobDirectory, "bitwarden.json")); err != nil {
					t.Fatal("binary completion must identify an existing output")
				}
			} else {
				if code != 3 || len(remaining) != 0 || !strings.HasSuffix(stderr.String(), "approval_invalid\n") {
					t.Fatal("declined binary conversion must have no completion")
				}
				assertNoExport(t, parent)
			}
			if !reflect.DeepEqual(before, snapshotSyntheticDirectory(t, sources)) {
				t.Fatal("binary conversion changed source or sibling contents, modes, size or mtime")
			}
			assertRedacted(t, line+string(remaining)+stderr.String(), source, sources, parent)
		})
	}
}

func TestBinaryConvertClosedReviewPipeAndApprovalEOFProduceNoOutput(t *testing.T) {
	requireLinuxOutput(t)
	binary := buildSyntheticCLI(t)
	for _, brokenReview := range []bool{false, true} {
		name := map[bool]string{false: "approval_eof", true: "closed_review_pipe"}[brokenReview]
		t.Run(name, func(t *testing.T) {
			source := inputFixture(t, syntheticCSV)
			parent := privateOutputParent(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, convertArgs(source, parent)...)
			cmd.Stdin = strings.NewReader("")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if brokenReview {
				cmd.Stdout = closedSyntheticPipe(t)
			}
			code := processExit(t, cmd.Run())
			if ctx.Err() != nil {
				t.Fatal("closed-pipe conversion timed out")
			}
			if brokenReview {
				if code != 1 || stdout.Len() != 0 || !strings.HasSuffix(stderr.String(), "output_write\n") {
					t.Fatal("actual closed review pipe must use I/O exit before approval")
				}
			} else if code != 3 || !strings.HasSuffix(stderr.String(), "approval_required\n") {
				t.Fatal("actual approval EOF must fail safely")
			}
			assertNoExport(t, parent)
			assertRedacted(t, stdout.String()+stderr.String(), source, parent)
		})
	}
}

func TestBinaryConvertSignalsCancelApprovalWithoutOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native signal cancellation checked on Linux")
	}
	binary := buildSyntheticCLI(t)
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			source := inputFixture(t, syntheticCSV)
			parent := privateOutputParent(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, convertArgs(source, parent)...)
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = input.Close()
				_ = cmd.Wait()
				t.Fatal("actual binary did not reach approval")
			}
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal("could not cancel actual binary")
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			code := processExit(t, cmd.Wait())
			if ctx.Err() != nil || code != 1 || len(remaining) != 0 {
				t.Fatal("process signal must cancel approval with safe I/O exit")
			}
			assertNoExport(t, parent)
			assertRedacted(t, line+string(remaining)+stderr.String(), source, parent)
		})
	}
}

func TestBinaryReadOnlyPlanSignalsTerminateDuringBlockedOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("native read-only signal behavior checked on Linux")
	}
	binary := buildSyntheticCLI(t)
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			source := inputFixture(t, "name,url,username,password\n"+strings.Repeat("SYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD\n", 2000))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "plan", "--input", source, "--to", "bitwarden-json")
			output, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader := bufio.NewReader(output)
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = cmd.Wait()
				t.Fatal("read-only binary did not begin its large safe report")
			}
			if line != "source: chrome-csv\n" {
				t.Fatal("read-only binary did not produce the expected report boundary")
			}
			// Stop draining before signaling. The report exceeds pipe capacity,
			// so swallowed signals cannot be hidden by a quick normal exit.
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal("could not signal the read-only binary")
			}
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal("could not drain the safe read-only report")
			}
			err = cmd.Wait()
			var exitErr *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != -1 {
				t.Fatal("read-only signal must terminate the process, not return normal success")
			}
			status, ok := exitErr.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != sig {
				t.Fatal("read-only binary must terminate from the signal that was sent")
			}
			assertRedacted(t, line+string(remaining)+stderr.String(), source)
		})
	}
}
