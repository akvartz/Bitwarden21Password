//go:build !linux && !darwin && !windows

package protectedoutput

import "context"

// Supported reports whether protected output is enabled on this platform.
func Supported() bool { return false }

func write(context.Context, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}

func writeNamed(context.Context, string, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}
