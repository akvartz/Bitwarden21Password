// Package releasepack builds the project's offline release archives.
package releasepack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Options names an explicit release from the current, clean repository root.
// Output's parent must exist. Output itself must not exist, even as a symlink.
type Options struct{ Version, Commit, Output string }

type BuildInfo struct {
	Program   string `json:"program"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Version       string     `json:"version"`
	Commit        string     `json:"commit"`
	GoVersion     string     `json:"go_version"`
	Artifacts     []Artifact `json:"artifacts"`
}

var versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validateVersion(version string) error {
	if len(version) > 128 || !versionPattern.MatchString(version) {
		return errors.New("version must be vMAJOR.MINOR.PATCH with optional prerelease, without build metadata")
	}
	if _, prerelease, found := strings.Cut(version, "-"); found {
		for _, identifier := range strings.Split(prerelease, ".") {
			numeric := strings.Trim(identifier, "0123456789") == ""
			if numeric && len(identifier) > 1 && identifier[0] == '0' {
				return errors.New("numeric prerelease identifiers must not have leading zeroes")
			}
		}
	}
	return nil
}

// Pack builds six archives. Failure can leave an incomplete, newly created
// output directory; it never retries, replaces a directory, or publishes.
func Pack(ctx context.Context, options Options) error {
	if err := validateVersion(options.Version); err != nil {
		return err
	}
	if !commitPattern.MatchString(options.Commit) {
		return errors.New("commit must be a full lowercase 40-digit Git object ID")
	}
	if options.Output == "" {
		return errors.New("output is required")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := verifySource(ctx, root, options.Commit); err != nil {
		return err
	}
	// A clean pinned checkout does not prove that extracted dependency sources
	// or cached module ZIPs still match their downloaded checksums. Verify the
	// offline cache before creating any release directory or artifact.
	if _, err := run(ctx, root, buildEnv("", ""), "go", "mod", "verify"); err != nil {
		return errors.New("cannot verify pinned dependencies")
	}
	// mod verify trusts the cache's mutable .ziphash. Loading each target's
	// actual build dependencies also checks that hash against committed go.sum.
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			if _, err := run(ctx, root, buildEnv(goos, goarch), "go", "list", "-deps", "-mod=readonly", "./cmd/pwmigrate"); err != nil {
				return errors.New("cannot verify pinned dependencies")
			}
		}
	}
	// Fail before any artifact writes if dependency loading changed source
	// inputs, including go.mod or go.sum, despite readonly module resolution.
	if err := verifySource(ctx, root, options.Commit); err != nil {
		return errors.New("cannot verify pinned dependencies")
	}
	license, err := os.ReadFile(filepath.Join(root, "LICENSE"))
	if err != nil {
		return err
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		return err
	}
	notices, err := os.ReadFile(filepath.Join(root, "THIRD-PARTY-NOTICES.md"))
	if err != nil {
		return err
	}
	goVersion, err := run(ctx, root, buildEnv("", ""), "go", "env", "GOVERSION")
	if err != nil {
		return errors.New("cannot identify local Go toolchain")
	}
	version := strings.TrimSpace(string(goVersion))
	if !strings.HasPrefix(version, "go1.") || strings.ContainsAny(version, "\r\n\t ") {
		return errors.New("release requires a released Go toolchain")
	}
	output, err := filepath.Abs(options.Output)
	if err != nil {
		return err
	}
	if err := os.Mkdir(output, 0755); err != nil {
		return fmt.Errorf("create new release directory (parent must exist): %w", err)
	}
	work, err := os.MkdirTemp(output, ".build-")
	if err != nil {
		return err
	}
	// Only known temporary paths are removed. Unexpected files are retained.
	binaryPath := filepath.Join(work, "pwmigrate-build")
	defer func() {
		os.Remove(binaryPath)
		os.Remove(work)
	}()
	manifest := Manifest{SchemaVersion: 1, Version: options.Version, Commit: options.Commit, GoVersion: version}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			info := BuildInfo{Program: "pwmigrate-go", Version: options.Version, Commit: options.Commit, GoVersion: version, GOOS: goos, GOARCH: goarch}
			flags := "-X github.com/akvartz/Bitwarden21Password/internal/buildinfo.Version=" + options.Version + " -X github.com/akvartz/Bitwarden21Password/internal/buildinfo.Commit=" + options.Commit
			if _, err := run(ctx, root, buildEnv(goos, goarch), "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", binaryPath, "./cmd/pwmigrate"); err != nil {
				return fmt.Errorf("build failed for %s/%s: %w", goos, goarch, err)
			}
			binary, err := os.ReadFile(binaryPath)
			if err != nil {
				return err
			}
			if err := os.Remove(binaryPath); err != nil {
				return err
			}
			data, err := makeArchive(info, binary, license, readme, notices)
			if err != nil {
				return err
			}
			extension := ".tar.gz"
			if goos == "windows" {
				extension = ".zip"
			}
			name := "pwmigrate-go_" + options.Version + "_" + goos + "_" + goarch + extension
			artifact, err := writeAsset(output, name, data)
			if err != nil {
				return err
			}
			manifest.Artifacts = append(manifest.Artifacts, artifact)
		}
	}
	if err := os.Remove(work); err != nil {
		return err
	}
	if err := verifySource(ctx, root, options.Commit); err != nil {
		return err
	}
	return finish(output, manifest)
}

func verifySource(ctx context.Context, root, commit string) error {
	// A replacement object must not make different contents appear clean under
	// the requested original commit ID. This does not change Git configuration.
	top, err := run(ctx, root, nil, "git", "--no-replace-objects", "rev-parse", "--show-toplevel")
	if err != nil {
		return errors.New("run from a Git repository root")
	}
	physicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	physicalTop, err := filepath.EvalSymlinks(strings.TrimSpace(string(top)))
	if err != nil || physicalRoot != physicalTop {
		return errors.New("run from the Git repository root")
	}
	head, err := run(ctx, root, nil, "git", "--no-replace-objects", "rev-parse", "--verify", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != commit {
		return errors.New("requested commit does not match Git HEAD")
	}
	status, err := run(ctx, root, nil, "git", "--no-replace-objects", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=no")
	if err != nil {
		return errors.New("cannot verify clean source checkout")
	}
	if len(status) != 0 {
		return errors.New("source checkout must be clean, including untracked files; output must be outside the checkout or ignored")
	}
	// Git status alone trusts assume-unchanged and skip-worktree bits.
	entries, err := run(ctx, root, nil, "git", "--no-replace-objects", "ls-files", "-v", "-z")
	if err != nil {
		return errors.New("cannot verify tracked source flags")
	}
	for _, entry := range bytes.Split(entries, []byte{0}) {
		if len(entry) != 0 && (len(entry) < 2 || entry[0] != 'H' || entry[1] != ' ') {
			return errors.New("source index must not use assume-unchanged or skip-worktree entries")
		}
	}
	// Ignored artifacts are allowed, but ignored package sources or embedded
	// files could otherwise enter the executable without changing Git status.
	ignored, err := run(ctx, root, nil, "git", "--no-replace-objects", "ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "cmd/pwmigrate", "internal")
	if err != nil {
		return errors.New("cannot verify ignored build inputs")
	}
	if len(ignored) != 0 {
		return errors.New("ignored files in command or internal packages are not release inputs")
	}
	return nil
}

func run(ctx context.Context, root string, env []string, program string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, program, args...)
	command.Dir = root
	if env != nil {
		command.Env = env
	}
	// Compiler/Git diagnostics are not release metadata. Keep them out of logs.
	return command.Output()
}

func buildEnv(goos, goarch string) []string {
	overrides := map[string]string{
		"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "CGO_ENABLED": "0",
		"GOPRIVATE": "", "GONOPROXY": "none", "GONOSUMDB": "none",
		"GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "GO111MODULE": "on",
		"GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0",
	}
	if goos != "" {
		overrides["GOOS"] = goos
		overrides["GOARCH"] = goarch
	}
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, replace := overrides[strings.ToUpper(key)]; !replace {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

func makeArchive(info BuildInfo, binary, license, readme, notices []byte) ([]byte, error) {
	metadata, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return nil, err
	}
	metadata = append(metadata, '\n')
	binaryName := "pwmigrate-go"
	if info.GOOS == "windows" {
		binaryName += ".exe"
	}
	members := []struct {
		name string
		mode int64
		data []byte
	}{
		{binaryName, 0755, binary}, {"LICENSE", 0644, license}, {"README.md", 0644, readme}, {"THIRD-PARTY-NOTICES.md", 0644, notices}, {"BUILD-INFO.json", 0644, metadata},
	}
	var output bytes.Buffer
	if info.GOOS == "windows" {
		writer := zip.NewWriter(&output)
		for _, member := range members {
			header := &zip.FileHeader{Name: member.name, Method: zip.Deflate}
			header.SetMode(os.FileMode(member.mode))
			header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
			file, err := writer.CreateHeader(header)
			if err != nil {
				return nil, err
			}
			if _, err := file.Write(member.data); err != nil {
				return nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
	} else {
		compressed := gzip.NewWriter(&output)
		writer := tar.NewWriter(compressed)
		for _, member := range members {
			header := &tar.Header{Name: member.name, Mode: member.mode, Size: int64(len(member.data)), Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
			if err := writer.WriteHeader(header); err != nil {
				return nil, err
			}
			if _, err := writer.Write(member.data); err != nil {
				return nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		if err := compressed.Close(); err != nil {
			return nil, err
		}
	}
	return output.Bytes(), nil
}

func writeAsset(output, name string, data []byte) (Artifact, error) {
	file, err := os.OpenFile(filepath.Join(output, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return Artifact{}, err
	}
	n, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return Artifact{}, writeErr
	}
	if n != len(data) {
		return Artifact{}, io.ErrShortWrite
	}
	if closeErr != nil {
		return Artifact{}, closeErr
	}
	hash := sha256.Sum256(data)
	return Artifact{Name: name, SHA256: hex.EncodeToString(hash[:]), Size: int64(len(data))}, nil
}

func finish(output string, manifest Manifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	artifact, err := writeAsset(output, "release-manifest.json", data)
	if err != nil {
		return err
	}
	var sums strings.Builder
	for _, item := range append(manifest.Artifacts, artifact) {
		fmt.Fprintf(&sums, "%s  %s\n", item.SHA256, item.Name)
	}
	_, err = writeAsset(output, "SHA256SUMS", []byte(sums.String()))
	return err
}
