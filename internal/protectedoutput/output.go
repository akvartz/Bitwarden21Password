// Package protectedoutput writes private, no-clobber export artifacts.
package protectedoutput

import "context"

// Result identifies a completed export relative to the supplied parent.
type Result struct {
	JobDirectory string
	FileName     string
}

// Error exposes only a fixed output failure code.
type Error struct {
	Code string
}

func (e *Error) Error() string {
	if e != nil {
		switch e.Code {
		case "output_platform", "output_parent", "output_create", "output_write",
			"output_sync", "output_readback", "output_close", "output_publish", "output_cancelled":
			return e.Code
		}
	}
	return "output_write"
}

// Write creates a private job directory and publishes a validated payload.
// Failure can leave private artifacts, including a complete published file.
// A file without a successful Result must be treated as unverified.
func Write(ctx context.Context, parent string, payload []byte) (Result, error) {
	return write(ctx, parent, payload)
}

// WriteNamed chooses a fixed, supported export filename. It never accepts an
// arbitrary filesystem path. Its failure and privacy contract matches Write.
func WriteNamed(ctx context.Context, parent, name string, payload []byte) (Result, error) {
	if !allowedFileName(name) {
		return Result{}, &Error{Code: "output_create"}
	}
	return writeNamed(ctx, parent, name, payload)
}

func allowedFileName(name string) bool {
	switch name {
	case "bitwarden.json", "onepassword.1pux", "proton-pass.zip", "recovery.age", "recovery-key.txt", "source.csv", "source.json", "source.1pux", "source.zip":
		return true
	}
	return false
}
