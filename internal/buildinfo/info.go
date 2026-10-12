// Package buildinfo describes the executable without inspecting export data.
package buildinfo

import "runtime"

// Version and Commit are supplied by release builds through linker -X flags.
// Ordinary development builds retain these explicit, non-release defaults.
var (
	Version = "dev"
	Commit  = "unknown"
)

// Info identifies a build and its target platform.
type Info struct {
	Program   string `json:"program"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

// Current returns the linker metadata and runtime's compiled platform details.
func Current() Info {
	return Info{
		Program: "pwmigrate-go", Version: Version, Commit: Commit,
		GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
}
