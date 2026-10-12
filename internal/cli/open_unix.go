//go:build unix

package cli

import (
	"os"
	"syscall"
)

func openInput(path string) (inputFile, error) {
	// Opening a replaced path as a FIFO must not wait for a writer. The loader
	// immediately checks this handle's file type before attempting any read.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "input"), nil
}
