package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/akvartz/Bitwarden21Password/internal/cli"
)

func main() {
	// Go otherwise terminates on stdout/stderr EPIPE before Run can report
	// its I/O exit code. Keep this process policy outside the reusable CLI.
	signal.Ignore(syscall.SIGPIPE)
	ctx := context.Background()
	var stop context.CancelFunc
	// Read-only commands do not observe a context and retain default signals.
	if len(os.Args) > 1 && (os.Args[1] == "convert" || os.Args[1] == "recovery-key" || os.Args[1] == "recovery-save" || os.Args[1] == "recover") {
		ctx, stop = signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	code := cli.RunContext(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if stop != nil {
		stop()
	}
	os.Exit(code)
}
