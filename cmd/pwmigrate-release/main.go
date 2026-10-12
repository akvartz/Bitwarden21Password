// pwmigrate-release builds archives locally; it never creates tags or releases.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/akvartz/Bitwarden21Password/internal/releasepack"
)

const usage = "Usage: pwmigrate-release --version vMAJOR.MINOR.PATCH[-prerelease] --commit FULL_COMMIT --output NEW_DIRECTORY\nRun at the clean repository root. The output parent must already exist.\n"

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("pwmigrate-release", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options releasepack.Options
	flags.StringVar(&options.Version, "version", "", "explicit release version")
	flags.StringVar(&options.Commit, "commit", "", "full Git commit")
	flags.StringVar(&options.Output, "output", "", "new output directory")
	err := flags.Parse(args)
	if err == flag.ErrHelp {
		if _, err := io.WriteString(stdout, usage); err != nil {
			return 1
		}
		return 0
	}
	if err != nil || flags.NArg() != 0 || options.Version == "" || options.Commit == "" || options.Output == "" {
		if _, err := io.WriteString(stderr, usage); err != nil {
			return 1
		}
		return 2
	}
	if err := releasepack.Pack(context.Background(), options); err != nil {
		fmt.Fprintf(stderr, "Release packaging failed: %v\n", err)
		return 1
	}
	if _, err := io.WriteString(stdout, "Created six release archives, release-manifest.json, and SHA256SUMS.\n"); err != nil {
		return 1
	}
	return 0
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
