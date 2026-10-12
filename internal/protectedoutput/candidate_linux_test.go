//go:build linux

package protectedoutput

import "context"

func candidateWrite(ctx context.Context, parent string, payload []byte) (Result, error) {
	return Write(ctx, parent, payload)
}
