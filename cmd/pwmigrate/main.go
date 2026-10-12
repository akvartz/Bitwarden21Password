package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/akvartz/Bitwarden21Password/internal/cli"
)

func main() {
	// Go otherwise terminates on stdout/stderr EPIPE before Run can report
	// its I/O exit code. Keep this process policy outside the reusable CLI.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
