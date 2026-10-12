package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRejectsMissingExtraAndUnknownArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"--version", "v1.2.3"}, {"--unknown"}, {"--version", "v1.2.3", "--commit", "0123456789abcdef0123456789abcdef01234567", "--output", "unused", "extra"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("invalid arguments returned %d", code)
		}
		if stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatal("argument failure missing diagnostic or emitted success")
		}
	}
}

func TestHelpDocumentsExplicitReleaseInputs(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help returned %d", code)
	}
	for _, text := range []string{"--version", "--commit", "--output"} {
		if !strings.Contains(stdout.String(), text) {
			t.Fatalf("help omits %s", text)
		}
	}
	if stderr.Len() != 0 {
		t.Fatal("help emitted diagnostic")
	}
}
