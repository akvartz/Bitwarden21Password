//go:build linux

package protectedoutput

import (
	"context"
	"os"
)

// Supported reports whether protected output is enabled on this platform.
func Supported() bool { return true }

func write(ctx context.Context, parent string, payload []byte) (Result, error) {
	return writeNamed(ctx, parent, fileName, payload)
}

func writeNamed(ctx context.Context, parent, name string, payload []byte) (Result, error) {
	return writeNamedWithOps(ctx, parent, name, payload, filesystemOperations())
}

// Linux retains the existing effective-UID/BSD-mode privacy boundary. This
// hook imposes macOS's additional native ACL/volume policy only on macOS.
func nativePrivacy(*os.File) bool { return true }
