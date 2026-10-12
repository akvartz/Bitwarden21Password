//go:build linux

package cli

import (
	"context"
	"fmt"
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

func passwordPTY(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skip("native pseudo-terminal unavailable")
	}
	master := os.NewFile(uintptr(fd), "synthetic-pty-master")
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal("pseudo-terminal unlock failed")
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal("pseudo-terminal identity unavailable")
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("pseudo-terminal slave unavailable")
	}
	t.Cleanup(func() { _ = slave.Close() })
	return master, slave
}

func waitPasswordEchoOff(t *testing.T, slave *os.File) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	deadline := time.After(time.Second)
	for {
		state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal("terminal state unavailable")
		}
		if state.Lflag&unix.ECHO == 0 {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("password input did not disable echo")
		}
	}
}

func TestTerminalPasswordLongInputAvoidsCanonicalTruncation(t *testing.T) {
	master, slave := passwordPTY(t)
	initial, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal("terminal state unavailable")
	}
	result := make(chan passwordResult, 1)
	go func() {
		password, err := readLocalPassword(context.Background(), slave, io.Discard, false)
		result <- passwordResult{password, err}
	}()
	waitPasswordEchoOff(t, slave)
	const bytes = 8192
	want := strings.Repeat("p", bytes)
	if _, err := master.Write([]byte(want + "\n")); err != nil {
		t.Fatal("long terminal password could not be supplied")
	}
	select {
	case received := <-result:
		if received.err != nil || string(received.password) != want {
			t.Fatal("terminal password was silently truncated or changed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long terminal password blocked")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(initial, after) {
		t.Fatal("terminal state was not restored after long input")
	}
}

func TestTerminalPasswordRejectsOverLimitBeforeReturningAnySecret(t *testing.T) {
	master, slave := passwordPTY(t)
	initial, err := term.GetState(int(slave.Fd()))
	if err != nil {
		t.Fatal("terminal state unavailable")
	}
	result := make(chan passwordResult, 1)
	go func() {
		password, err := readLocalPassword(context.Background(), slave, io.Discard, false)
		result <- passwordResult{password, err}
	}()
	waitPasswordEchoOff(t, slave)
	if _, err := master.Write([]byte(strings.Repeat("p", passwordLineLimit+100) + "\n")); err != nil {
		t.Fatal("over-limit terminal input could not be supplied")
	}
	select {
	case received := <-result:
		if received.err == nil || received.err.Error() != "password_limit" || received.password != nil {
			t.Fatal("over-limit terminal input returned a truncated secret")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("over-limit terminal password blocked")
	}
	after, err := term.GetState(int(slave.Fd()))
	if err != nil || !reflect.DeepEqual(initial, after) {
		t.Fatal("terminal state was not restored after input rejection")
	}
}

func TestTerminalPasswordAcceptsExplicitEmptyValue(t *testing.T) {
	master, slave := passwordPTY(t)
	result := make(chan passwordResult, 1)
	go func() {
		password, err := readLocalPassword(context.Background(), slave, io.Discard, false)
		result <- passwordResult{password, err}
	}()
	if _, err := master.Write([]byte("\n")); err != nil {
		t.Fatal("terminal password could not be supplied")
	}
	select {
	case received := <-result:
		if received.err != nil || received.password == nil || len(received.password) != 0 {
			t.Fatal("explicit empty terminal password collapsed to missing")
		}
	case <-time.After(time.Second):
		t.Fatal("empty terminal password blocked")
	}
}

func TestBinaryReadOnlyPasswordSignalRestoresTerminalEcho(t *testing.T) {
	binary := buildSyntheticCLI(t)
	vector := cliEncryptedVectors(t)[0]
	input := inputFixture(t, string(vector.Envelope))
	for _, command := range []string{"inspect", "plan", "compare"} {
		for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
			t.Run(command+"_"+signal.String(), func(t *testing.T) {
				master, slave := passwordPTY(t)
				defer master.Close()
				fd := int(slave.Fd())
				initial, err := term.GetState(fd)
				if err != nil {
					t.Fatal("terminal state unavailable")
				}
				defer term.Restore(fd, initial)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				args := []string{command, "--input", input}
				if command != "inspect" {
					args = append(args, "--to", "onepassword-1pux")
				}
				if command == "compare" {
					args = append(args, "--destination", input)
				}
				cmd := exec.CommandContext(ctx, binary, args...)
				cmd.Stdin = slave
				cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
				if err := cmd.Start(); err != nil {
					t.Fatal("password subprocess did not start")
				}
				t.Cleanup(func() { _ = cmd.Process.Kill() })
				tick := time.NewTicker(time.Millisecond)
				defer tick.Stop()
				deadline := time.After(3 * time.Second)
				for {
					state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
					if err != nil {
						t.Fatal("terminal state unavailable")
					}
					if state.Lflag&unix.ECHO == 0 {
						break
					}
					select {
					case <-tick.C:
					case <-deadline:
						t.Fatal("subprocess did not hide terminal password")
					}
				}
				if err := cmd.Process.Signal(signal); err != nil {
					t.Fatal("subprocess signal failed")
				}
				err = cmd.Wait()
				if ctx.Err() != nil || err == nil {
					t.Fatal("signal did not cancel the password operation")
				}
				after, err := term.GetState(fd)
				if err != nil || !reflect.DeepEqual(initial, after) {
					t.Fatal("read-only password signal left terminal echo disabled")
				}
			})
		}
	}
}

type cancelPasswordPrompt struct{ cancel context.CancelFunc }

func (w cancelPasswordPrompt) Write(data []byte) (int, error) { w.cancel(); return len(data), nil }

func TestTerminalPasswordHidesInputAndRestoresEchoOnCancellation(t *testing.T) {
	master, slave := passwordPTY(t)
	fd := int(slave.Fd())
	initial, err := term.GetState(fd)
	if err != nil {
		t.Fatal("terminal state unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := readLocalPassword(ctx, slave, io.Discard, false); result <- err }()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		state, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			t.Fatal("terminal state unavailable")
		}
		if state.Lflag&unix.ECHO == 0 {
			break
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatal("password input echo remained enabled")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err == nil || err.Error() != "output_cancelled" {
			t.Fatal("terminal secret cancellation did not fail safely")
		}
	case <-time.After(time.Second):
		t.Fatal("terminal secret cancellation blocked")
	}
	after, err := term.GetState(fd)
	if err != nil || !reflect.DeepEqual(initial, after) {
		t.Fatal("terminal echo/state not restored after cancellation")
	}
	// The caller owns the handle and unblocks ReadPassword after cancellation.
	if _, err := master.Write([]byte("synthetic-unblock\n")); err != nil {
		t.Fatal("terminal read could not be unblocked")
	}
}

func TestTerminalPasswordCancellationBeforeEchoSetupRestoresState(t *testing.T) {
	master, slave := passwordPTY(t)
	fd := int(slave.Fd())
	initial, err := term.GetState(fd)
	if err != nil {
		t.Fatal("terminal state unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = readLocalPassword(ctx, slave, cancelPasswordPrompt{cancel}, false)
	if err == nil || err.Error() != "output_cancelled" {
		t.Fatal("early terminal cancellation did not fail safely")
	}
	after, err := term.GetState(fd)
	if err != nil || !reflect.DeepEqual(initial, after) {
		t.Fatal("early cancellation raced echo restoration")
	}
	if _, err := master.Write([]byte("synthetic-unblock\n")); err != nil {
		t.Fatal("terminal read could not be unblocked")
	}
}
