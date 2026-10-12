//go:build !windows

// Package testsupport supplies synthetic private output fixtures. Production
// code must not import it or use it to change platform qualification gates.
package testsupport

import (
	"os"
	"testing"
)

func PrivateParent(t testing.TB) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal("private test parent setup failed")
	}
	return parent
}

func AssertPrivate(t testing.TB, path string, directory bool) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("private test artifact observation failed")
	}
	mode := os.FileMode(0600)
	if directory {
		mode = 0700
	}
	if info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) || info.Mode().Perm() != mode {
		t.Fatal("private test artifact type or mode differed")
	}
}
