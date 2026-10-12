//go:build windows

package cli

import "os"

func openInput(path string) (inputFile, error) {
	// Reject obvious nonregular paths before Windows open, then validate the
	// opened handle in readInput as well. This is not a native Windows device,
	// pipe, or replacement-race qualification; cross-builds cannot provide it.
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &failure{"input_not_regular", 3}
	}
	return os.Open(path)
}
