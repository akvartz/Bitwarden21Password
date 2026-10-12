//go:build darwin

package protectedoutput

import "context"

func candidateWrite(ctx context.Context, parent string, payload []byte) (Result, error) {
	return writeDarwinCandidate(ctx, parent, payload)
}
