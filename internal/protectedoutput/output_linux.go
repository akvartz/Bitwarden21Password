//go:build linux

package protectedoutput

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
)

const (
	fileName    = "bitwarden.json"
	partialName = ".bitwarden.json.partial"
	chunkSize   = 32 * 1024
)

// Supported reports whether protected output is enabled on this platform.
func Supported() bool { return true }

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

func randomJobName() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(entropy[:]), nil
}

func write(ctx context.Context, parent string, payload []byte) (Result, error) {
	return writeWithOps(ctx, parent, payload, filesystemOperations())
}

func writeWithOps(ctx context.Context, parent string, payload []byte, ops operations) (result Result, err error) {
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
	if statErr != nil || !owned(parentInfo) || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0022 != 0 {
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
	if statErr != nil || !owned(jobInfo) || jobInfo.Mode() != os.ModeDir|0700 {
		return Result{}, &Error{Code: "output_create"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	partial, err = ops.openFile(jobRoot, partialName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Result{}, &Error{Code: "output_create"}
	}
	fileInfo, statErr := partial.Stat()
	if statErr != nil || !owned(fileInfo) || fileInfo.Mode() != 0600 {
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
	if err = readback(ctx, partial, payload, ops); err != nil {
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
	if err = ops.link(jobRoot, partialName, fileName); err != nil {
		return Result{}, &Error{Code: "output_publish"}
	}
	if ctx.Err() != nil {
		return Result{}, &Error{Code: "output_cancelled"}
	}
	// Remove only our partial entry after publication, never on failure.
	if err = ops.remove(jobRoot, partialName); err != nil {
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
	return Result{JobDirectory: jobName, FileName: fileName}, nil
}

func owned(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func readback(ctx context.Context, file *os.File, payload []byte, ops operations) error {
	if ctx.Err() != nil {
		return &Error{Code: "output_cancelled"}
	}
	position, err := ops.seek(file, 0, io.SeekStart)
	if err != nil || position != 0 {
		return &Error{Code: "output_readback"}
	}
	var buffer [chunkSize]byte
	for offset := 0; offset < len(payload); {
		if ctx.Err() != nil {
			return &Error{Code: "output_cancelled"}
		}
		limit := min(len(buffer), len(payload)-offset)
		n, readErr := ops.read(file, buffer[:limit])
		if n <= 0 || n > limit || (readErr != nil && !errors.Is(readErr, io.EOF)) {
			return &Error{Code: "output_readback"}
		}
		if !bytes.Equal(buffer[:n], payload[offset:offset+n]) {
			return &Error{Code: "output_readback"}
		}
		offset += n
		if errors.Is(readErr, io.EOF) && offset != len(payload) {
			return &Error{Code: "output_readback"}
		}
	}
	if ctx.Err() != nil {
		return &Error{Code: "output_cancelled"}
	}
	// Read at most one extra byte; truncation or extra data cannot validate.
	n, err := ops.read(file, buffer[:1])
	if n != 0 || !errors.Is(err, io.EOF) {
		return &Error{Code: "output_readback"}
	}
	return nil
}
