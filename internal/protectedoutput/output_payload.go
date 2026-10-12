package protectedoutput

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

const (
	fileName    = "bitwarden.json"
	partialName = ".bitwarden.json.partial"
	chunkSize   = 32 * 1024
)

type readbackOperations struct {
	seek func(*os.File, int64, int) (int64, error)
	read func(*os.File, []byte) (int, error)
}

func randomJobName() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return "job-" + hex.EncodeToString(entropy[:]), nil
}

func readback(ctx context.Context, file *os.File, payload []byte, ops readbackOperations) error {
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
