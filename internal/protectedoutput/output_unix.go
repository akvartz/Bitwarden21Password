//go:build linux || darwin

package protectedoutput

import (
	"context"
	"os"
	"syscall"
)

// operations permits focused filesystem faults without replacing real roots.
// Each invocation has its own operations; no mutable global hooks are used.
type operations struct {
	name     func() (string, error)
	mkdir    func(*os.Root, string, os.FileMode) error
	openFile func(*os.Root, string, int, os.FileMode) (*os.File, error)
	write    func(*os.File, []byte) (int, error)
	sync     func(*os.File) error
	seek     func(*os.File, int64, int) (int64, error)
	read     func(*os.File, []byte) (int, error)
	close    func(*os.File) error
	link     func(*os.Root, string, string) error
	remove   func(*os.Root, string) error
}

func filesystemOperations() operations {
	return operations{
		name: randomJobName, mkdir: (*os.Root).Mkdir, openFile: (*os.Root).OpenFile,
		write: (*os.File).Write, sync: (*os.File).Sync, seek: (*os.File).Seek,
		read: (*os.File).Read, close: (*os.File).Close,
		link: (*os.Root).Link, remove: (*os.Root).Remove,
	}
}

func writeWithOps(ctx context.Context, parent string, payload []byte, ops operations) (Result, error) {
	return writeNamedWithOps(ctx, parent, fileName, payload, ops)
}

func writeNamedWithOps(ctx context.Context, parent, name string, payload []byte, ops operations) (result Result, err error) {
	if !allowedFileName(name) {
		return Result{}, &Error{Code: "output_create"}
	}
	partialEntry := "." + name + ".partial"
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}

	var parentRoot, jobRoot *os.Root
	var parentDir, jobDir, partial *os.File
	defer func() {
		// Retain separate directory files: Go 1.26 Root.Close discards the
		// underlying syscall close error and is not checked-close evidence.
		for _, f := range []*os.File{partial, jobDir, parentDir} {
			if f != nil {
				if closeErr := ops.close(f); closeErr != nil && err == nil {
					err = &Error{Code: "output_close"}
				}
			}
		}
		for _, r := range []*os.Root{jobRoot, parentRoot} {
			if r != nil {
				if closeErr := r.Close(); closeErr != nil && err == nil {
					err = &Error{Code: "output_close"}
				}
			}
		}
		if ctx.Err() != nil && err == nil {
			err = &Error{Code: "output_cancelled"}
		}
		if err != nil {
			result = Result{}
		}
	}()

	parentRoot, err = os.OpenRoot(parent)
	if err != nil {
		return Result{}, &Error{Code: "output_parent"}
	}
	parentDir, err = parentRoot.Open(".")
	if err != nil {
		return Result{}, &Error{Code: "output_parent"}
	}
	parentInfo, statErr := parentDir.Stat()
	if statErr != nil || !owned(parentInfo) || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0022 != 0 || !nativePrivacy(parentDir) {
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
	// A collision is terminal. Never reuse an existing directory or entry.
	if err = ops.mkdir(parentRoot, jobName, 0700); err != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	jobRoot, err = parentRoot.OpenRoot(jobName)
	if err != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	jobDir, err = jobRoot.Open(".")
	if err != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	jobInfo, statErr := jobDir.Stat()
	if statErr != nil || !owned(jobInfo) || jobInfo.Mode() != os.ModeDir|0700 || !nativePrivacy(jobDir) {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	partial, err = ops.openFile(jobRoot, partialEntry, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	fileInfo, statErr := partial.Stat()
	if statErr != nil || !owned(fileInfo) || fileInfo.Mode() != 0600 || !nativePrivacy(partial) {
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
	if err = ops.sync(partial); err != nil {
		return Result{}, &Error{Code: "output_sync"}
	}
	if err = readback(ctx, partial, payload, readbackOperations{seek: ops.seek, read: ops.read}); err != nil {
		return Result{}, err
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	closeErr := ops.close(partial)
	partial = nil
	if closeErr != nil {
		return Result{}, &Error{Code: "output_close"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	// Link publishes the complete inode and fails if any final entry exists.
	if err = ops.link(jobRoot, partialEntry, name); err != nil {
		return Result{}, &Error{Code: "output_publish"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	// Remove only our partial entry after publication, never on failure.
	if err = ops.remove(jobRoot, partialEntry); err != nil {
		return Result{}, &Error{Code: "output_publish"}
	}
	for _, directory := range []*os.File{jobDir, parentDir} {
		if ctx.Err() != nil {
			return Result{}, &Error{Code: "output_cancelled"}
		}
		if err = ops.sync(directory); err != nil {
			return Result{}, &Error{Code: "output_sync"}
		}
	}
	return Result{JobDirectory: jobName, FileName: name}, nil
}

func owned(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
