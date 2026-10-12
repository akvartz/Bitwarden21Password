package protectedoutput

import (
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestErrorAllowlist(t *testing.T) {
	for _, code := range []string{
		"output_platform", "output_parent", "output_create", "output_write",
		"output_sync", "output_readback", "output_close", "output_publish", "output_cancelled",
	} {
		t.Run(code, func(t *testing.T) {
			if got := (&Error{Code: code}).Error(); got != code {
				t.Fatalf("got %q, want fixed code %q", got, code)
			}
		})
	}
	for _, code := range []string{"", "synthetic untrusted path /example", "output_unknown"} {
		if got := (&Error{Code: code}).Error(); got != "output_write" {
			t.Fatalf("untrusted code escaped allowlist: %q", got)
		}
	}
	if got := (*Error)(nil).Error(); got != "output_write" {
		t.Fatalf("nil error returned %q", got)
	}
}

func TestUnsupportedPlatformHasNoFilesystemEffects(t *testing.T) {
	if runtime.GOOS == "linux" {
		if !Supported() {
			t.Fatal("Linux output must be supported")
		}
		return
	}
	if Supported() {
		t.Fatal("unqualified platform must fail closed")
	}
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := Write(ctx, parent, []byte("synthetic payload"))
	requireFailure(t, result, err, "output_platform")
	for _, name := range []string{"bitwarden.json", "onepassword.1pux", "proton-pass.zip"} {
		result, err := WriteNamed(ctx, parent, name, []byte("synthetic payload"))
		requireFailure(t, result, err, "output_platform")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("unsupported write changed the parent")
	}
}

func requireFailure(t *testing.T, result Result, err error, code string) {
	t.Helper()
	if result != (Result{}) {
		t.Fatal("failure returned a completion result")
	}
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != code || err.Error() != code {
		t.Fatalf("want fixed %s error, got %v", code, err)
	}
}
