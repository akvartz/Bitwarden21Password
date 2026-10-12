//go:build windows

package protectedoutput

import (
	"context"
	"os"
	"syscall"
)

// Supported remains false until native DACL, reparse, volume, and failure
// tests qualify this implementation. A 0600 argument is no Windows ACL proof.
func Supported() bool { return false }

func write(context.Context, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}

func writeNamed(context.Context, string, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}

type windowsOperations struct {
	name    func() (string, error)
	create  func(syscall.Handle, string, bool, []byte) (syscall.Handle, error)
	write   func(*os.File, []byte) (int, error)
	sync    func(*os.File) error
	seek    func(*os.File, int64, int) (int64, error)
	read    func(*os.File, []byte) (int, error)
	close   func(*os.File) error
	publish func(syscall.Handle, syscall.Handle, string) error
}

func windowsFilesystemOperations() windowsOperations {
	return windowsOperations{
		name: randomJobName, create: windowsCreatePrivate, write: (*os.File).Write,
		sync: (*os.File).Sync, seek: (*os.File).Seek, read: (*os.File).Read,
		close: (*os.File).Close, publish: windowsPublish,
	}
}

func writeWindowsCandidate(ctx context.Context, parent string, payload []byte) (Result, error) {
	return writeWindowsWithOps(ctx, parent, fileName, payload, windowsFilesystemOperations())
}

func writeWindowsWithOps(ctx context.Context, parent, name string, payload []byte, ops windowsOperations) (result Result, err error) {
	if !allowedFileName(name) {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	var parentDir, jobDir, partial *os.File
	defer func() {
		for _, file := range []*os.File{partial, jobDir, parentDir} {
			if file != nil && ops.close(file) != nil && err == nil {
				err = &Error{Code: "output_close"}
			}
		}
		if ctx.Err() != nil && err == nil {
			err = &Error{Code: "output_cancelled"}
		}
		if err != nil {
			result = Result{}
		}
	}()
	user, userErr := windowsCurrentUser()
	if userErr != nil {
		return Result{}, &Error{Code: "output_parent"}
	}
	parentHandle, openErr := windowsOpenParent(parent)
	if openErr != nil {
		return Result{}, &Error{Code: "output_parent"}
	}
	parentDir = os.NewFile(uintptr(parentHandle), "output-parent")
	if !windowsPrivateHandle(parentHandle, user, true) {
		return Result{}, &Error{Code: "output_parent"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	jobName, nameErr := ops.name()
	if nameErr != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	jobHandle, createErr := ops.create(parentHandle, jobName, true, user)
	if createErr != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	jobDir = os.NewFile(uintptr(jobHandle), jobName)
	if !windowsPrivateHandle(jobHandle, user, true) {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	partialEntry := "." + name + ".partial"
	partialHandle, createErr := ops.create(jobHandle, partialEntry, false, user)
	if createErr != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	partial = os.NewFile(uintptr(partialHandle), partialEntry)
	if !windowsPrivateHandle(partialHandle, user, false) {
		return Result{}, &Error{Code: "output_create"}
	}
	for offset := 0; offset < len(payload); {
		if ctx.Err() != nil {
			return Result{}, &Error{Code: "output_cancelled"}
		}
		end := min(offset+chunkSize, len(payload))
		n, writeErr := ops.write(partial, payload[offset:end])
		if writeErr != nil || n != end-offset {
			return Result{}, &Error{Code: "output_write"}
		}
		offset = end
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	if ops.sync(partial) != nil {
		return Result{}, &Error{Code: "output_sync"}
	}
	if readErr := readback(ctx, partial, payload, readbackOperations{seek: ops.seek, read: ops.read}); readErr != nil {
		return Result{}, readErr
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	// Publication renames this open complete file handle relative to the open
	// job handle. ReplaceIfExists is false; no existing entry can be replaced.
	if ops.publish(partialHandle, jobHandle, name) != nil {
		return Result{}, &Error{Code: "output_publish"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	if ops.sync(partial) != nil {
		return Result{}, &Error{Code: "output_sync"}
	}
	// Windows directory flushing is not treated as a portable durability
	// primitive. Only checked file flushes and checked handle closes are
	// claimed; this candidate promises no crash-durable directory publication.
	return Result{JobDirectory: jobName, FileName: name}, nil
}
