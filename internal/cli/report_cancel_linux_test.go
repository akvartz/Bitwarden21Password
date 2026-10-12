//go:build linux

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func fullDiagnosticPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal("diagnostic pipe unavailable")
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	capacity, err := unix.FcntlInt(writer.Fd(), unix.F_GETPIPE_SZ, 0)
	if err != nil {
		t.Fatal("diagnostic pipe capacity unavailable")
	}
	if _, err := writer.Write(bytes.Repeat([]byte{'x'}, capacity)); err != nil {
		t.Fatal("diagnostic pipe could not be filled")
	}
	return reader, writer
}

func waitCanceledProcess(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- cmd.Wait() }()
	select {
	case err := <-result:
		var exit *exec.ExitError
		if err == nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatal("canceled output process did not use failure exit 1")
		}
	case <-time.After(time.Second):
		_ = cmd.Process.Kill()
		<-result
		t.Fatal("signal cancellation blocked behind a report write")
	}
}

func TestBinaryConversionSignalsCancelBackpressuredReports(t *testing.T) {
	requireLinuxOutput(t)
	binary := buildSyntheticCLI(t)
	source := inputFixture(t, "name,url,username,password\n"+strings.Repeat("synthetic,url,user,secret\n", 2000))
	for _, stream := range []string{"stdout", "stderr"} {
		for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(stream+"_"+signal.String(), func(t *testing.T) {
				parent := privateOutputParent(t)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary, convertArgs(source, parent)...)
				cmd.Stdin = strings.NewReader("")
				cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
				var reader *os.File
				var writer *os.File
				if stream == "stdout" {
					var err error
					reader, writer, err = os.Pipe()
					if err != nil {
						t.Fatal("report pipe unavailable")
					}
					t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
					cmd.Stdout = writer
				} else {
					reader, writer = fullDiagnosticPipe(t)
					cmd.Stderr = writer
				}
				if err := cmd.Start(); err != nil {
					t.Fatal("conversion subprocess did not start")
				}
				t.Cleanup(func() { _ = cmd.Process.Kill() })
				_ = writer.Close()
				if stream == "stdout" {
					one := make([]byte, 1)
					if _, err := reader.Read(one); err != nil {
						t.Fatal("conversion review did not start")
					}
				}
				time.Sleep(50 * time.Millisecond)
				if err := cmd.Process.Signal(signal); err != nil {
					t.Fatal("conversion signal failed")
				}
				waitCanceledProcess(t, cmd)
				assertNoExport(t, parent)
			})
		}
	}
}

func TestBinaryReadOnlyPasswordSignalRestoresEchoWithBlockedPrompt(t *testing.T) {
	binary := buildSyntheticCLI(t)
	vector := cliEncryptedVectors(t)[0]
	input := inputFixture(t, string(vector.Envelope))
	for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(signal.String(), func(t *testing.T) {
			master, slave := passwordPTY(t)
			defer master.Close()
			initial, err := term.GetState(int(slave.Fd()))
			if err != nil {
				t.Fatal("terminal state unavailable")
			}
			defer term.Restore(int(slave.Fd()), initial)
			_, writer := fullDiagnosticPipe(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "inspect", "--input", input)
			cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, io.Discard, writer
			if err := cmd.Start(); err != nil {
				t.Fatal("password subprocess did not start")
			}
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			_ = writer.Close()
			waitPasswordEchoOff(t, slave)
			if err := cmd.Process.Signal(signal); err != nil {
				t.Fatal("password process signal failed")
			}
			waitCanceledProcess(t, cmd)
			after, err := term.GetState(int(slave.Fd()))
			if err != nil || !reflect.DeepEqual(initial, after) {
				t.Fatal("blocked secret prompt cancellation left echo disabled")
			}
		})
	}
}
