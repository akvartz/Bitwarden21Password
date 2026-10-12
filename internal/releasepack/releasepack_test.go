package releasepack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestVersionRejectsUnsafeOrNoncanonicalIdentifiers(t *testing.T) {
	for _, version := range []string{"", "1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2", "v1.2.3-", "v1.2.3-01", "v1.2.3-rc.01", "v1.2.3-rc..1", "v1.2.3+metadata", "v1.2.3/other", "v1.2.3\n", "v1.2.3;echo", "v1.2.3-$(id)", "v1.2.3_foo", "v1.2.3-" + strings.Repeat("a", 122)} {
		t.Run(version, func(t *testing.T) {
			if err := validateVersion(version); err == nil {
				t.Fatal("invalid version accepted")
			}
		})
	}
	for _, version := range []string{"v0.0.0", "v1.2.3", "v123.456.789", "v1.2.3-rc.1", "v1.2.3-0", "v1.2.3-01a", "v1.2.3-alpha-beta.2", "v1.2.3-" + strings.Repeat("a", 121)} {
		if err := validateVersion(version); err != nil {
			t.Fatalf("valid version %q rejected: %v", version, err)
		}
	}
}

func TestPackRejectsArgumentsBeforeCreatingOutput(t *testing.T) {
	for _, options := range []Options{
		{Version: "v01.2.3", Commit: testCommit},
		{Version: "v1.2.3", Commit: "abc"},
		{Version: "v1.2.3", Commit: strings.ToUpper(testCommit)},
		{Version: "v1.2.3", Commit: strings.Repeat("z", 40)},
	} {
		options.Output = filepath.Join(t.TempDir(), "release")
		if err := Pack(context.Background(), options); err == nil {
			t.Fatal("invalid options accepted")
		}
		if _, err := os.Lstat(options.Output); !os.IsNotExist(err) {
			t.Fatalf("output changed before validation: %v", err)
		}
	}
}

func TestArchiveContainsOnlyExactReleaseMembers(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			info := BuildInfo{Program: "pwmigrate-go", Version: "v1.2.3-rc.1", Commit: testCommit, GoVersion: "go1.26.0", GOOS: goos, GOARCH: "amd64"}
			data, err := makeArchive(info, []byte("synthetic executable"), []byte("synthetic license\n"), []byte("synthetic readme\n"), []byte("synthetic dependency notices\n"))
			if err != nil {
				t.Fatal(err)
			}
			members, modes := archiveMembers(t, goos, data)
			binary := "pwmigrate-go"
			if goos == "windows" {
				binary += ".exe"
			}
			if len(members) != 5 || string(members[binary]) != "synthetic executable" || string(members["LICENSE"]) != "synthetic license\n" || string(members["README.md"]) != "synthetic readme\n" || string(members["THIRD-PARTY-NOTICES.md"]) != "synthetic dependency notices\n" {
				t.Fatalf("unexpected archive members: %v", members)
			}
			if modes[binary]&0111 != 0111 || modes["README.md"]&0111 != 0 {
				t.Fatalf("incorrect executable/document modes: %v", modes)
			}
			var got BuildInfo
			if err := json.Unmarshal(members["BUILD-INFO.json"], &got); err != nil || got != info {
				t.Fatalf("incorrect metadata: %+v, %v", got, err)
			}
			again, err := makeArchive(info, []byte("synthetic executable"), []byte("synthetic license\n"), []byte("synthetic readme\n"), []byte("synthetic dependency notices\n"))
			if err != nil || !bytes.Equal(data, again) {
				t.Fatalf("non-deterministic archive: %v", err)
			}
		})
	}
}

func TestReleaseManifestAndChecksumsCoverExactlyAllAssets(t *testing.T) {
	output := t.TempDir()
	manifest := Manifest{SchemaVersion: 1, Version: "v1.2.3", Commit: testCommit, GoVersion: "go1.26.0"}
	names := []string{
		"pwmigrate-go_v1.2.3_linux_amd64.tar.gz", "pwmigrate-go_v1.2.3_linux_arm64.tar.gz",
		"pwmigrate-go_v1.2.3_darwin_amd64.tar.gz", "pwmigrate-go_v1.2.3_darwin_arm64.tar.gz",
		"pwmigrate-go_v1.2.3_windows_amd64.zip", "pwmigrate-go_v1.2.3_windows_arm64.zip",
	}
	for _, name := range names {
		artifact, err := writeAsset(output, name, []byte("archive: "+name))
		if err != nil {
			t.Fatal(err)
		}
		manifest.Artifacts = append(manifest.Artifacts, artifact)
	}
	if err := finish(output, manifest); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(output, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Manifest
	if err := json.Unmarshal(data, &got); err != nil || !reflect.DeepEqual(got, manifest) {
		t.Fatalf("manifest mismatch: %+v, %v", got, err)
	}
	sums, err := os.ReadFile(filepath.Join(output, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(sums), "\n"), "\n")
	if len(lines) != 7 {
		t.Fatalf("want seven checksum entries, got %d", len(lines))
	}
	for i, name := range append(names, "release-manifest.json") {
		body, err := os.ReadFile(filepath.Join(output, name))
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(body)
		if lines[i] != hex.EncodeToString(hash[:])+"  "+name {
			t.Fatalf("checksum mismatch for %s", name)
		}
		if i < 6 && (got.Artifacts[i].Name != name || got.Artifacts[i].Size != int64(len(body)) || got.Artifacts[i].SHA256 != hex.EncodeToString(hash[:])) {
			t.Fatalf("artifact metadata mismatch: %+v", got.Artifacts[i])
		}
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 8 {
		t.Fatalf("unexpected release contents: %v, %v", entries, err)
	}
}

func TestAssetNeverReplacesExistingFile(t *testing.T) {
	output := t.TempDir()
	path := filepath.Join(output, "SHA256SUMS")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAsset(output, "SHA256SUMS", []byte("replacement")); err == nil {
		t.Fatal("overwriting existing asset succeeded")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "existing" {
		t.Fatalf("existing asset changed: %q, %v", got, err)
	}
}

func archiveMembers(t *testing.T, goos string, data []byte) (map[string][]byte, map[string]os.FileMode) {
	t.Helper()
	members := map[string][]byte{}
	modes := map[string]os.FileMode{}
	if goos == "windows" {
		reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range reader.File {
			if _, exists := members[f.Name]; exists || !f.Mode().IsRegular() {
				t.Fatalf("invalid zip entry: %s", f.Name)
			}
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			members[f.Name], err = io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			modes[f.Name] = f.Mode()
		}
		return members, modes
	}
	compressed, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := members[header.Name]; exists || header.Typeflag != tar.TypeReg {
			t.Fatalf("invalid tar entry: %s", header.Name)
		}
		members[header.Name], err = io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		modes[header.Name] = os.FileMode(header.Mode)
	}
	return members, modes
}

func TestSourceGuardRejectsChangedOrWrongCheckout(t *testing.T) {
	for _, kind := range []string{"clean", "ignored-artifact", "wrong-commit", "unstaged", "staged", "untracked", "ignored-source", "assume-unchanged", "skip-worktree", "subdirectory"} {
		t.Run(kind, func(t *testing.T) {
			root, commit := gitFixture(t)
			switch kind {
			case "ignored-artifact":
				if err := os.Mkdir(filepath.Join(root, "dist"), 0755); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(root, "dist", "archive.zip"), "ignored artifact")
			case "wrong-commit":
				commit = strings.Repeat("0", 40)
			case "unstaged":
				writeTestFile(t, filepath.Join(root, "README.md"), "changed")
			case "staged":
				writeTestFile(t, filepath.Join(root, "README.md"), "changed")
				fixtureGit(t, root, "add", "README.md")
			case "untracked":
				writeTestFile(t, filepath.Join(root, "other.txt"), "untracked")
			case "ignored-source":
				if err := os.MkdirAll(filepath.Join(root, "internal", "hidden"), 0755); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, filepath.Join(root, "internal", "hidden", "extra.go"), "package hidden\n")
			case "skip-worktree":
				fixtureGit(t, root, "update-index", "--skip-worktree", "README.md")
				writeTestFile(t, filepath.Join(root, "README.md"), "changed")
			case "assume-unchanged":
				fixtureGit(t, root, "update-index", "--assume-unchanged", "README.md")
				writeTestFile(t, filepath.Join(root, "README.md"), "changed")
			case "subdirectory":
				root = filepath.Join(root, "subdir")
				if err := os.Mkdir(root, 0755); err != nil {
					t.Fatal(err)
				}
			}
			err := verifySource(context.Background(), root, commit)
			if (kind == "clean" || kind == "ignored-artifact") && err != nil {
				t.Fatalf("clean source rejected: %v", err)
			}
			if kind != "clean" && kind != "ignored-artifact" && err == nil {
				t.Fatalf("%s source accepted", kind)
			}
		})
	}
}

func TestPackPreservesExistingOutputAndFailureHasNoCompletionManifest(t *testing.T) {
	root, commit := gitFixture(t)
	t.Chdir(root)
	existing := t.TempDir()
	sentinel := filepath.Join(existing, "sentinel")
	writeTestFile(t, sentinel, "keep")
	if err := Pack(context.Background(), Options{Version: "v1.2.3", Commit: commit, Output: existing}); err == nil || !strings.Contains(err.Error(), "create new release directory") {
		t.Fatalf("expected directory collision, got %v", err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("existing output changed: %q %v", got, err)
	}
	output := filepath.Join(t.TempDir(), "new-release")
	// The clean synthetic command passes dependency loading but fails compilation.
	if err := Pack(context.Background(), Options{Version: "v1.2.3", Commit: commit, Output: output}); err == nil || !strings.Contains(err.Error(), "build failed for linux/amd64") {
		t.Fatalf("expected compiler failure, got %v", err)
	}
	for _, name := range []string{"release-manifest.json", "SHA256SUMS"} {
		if _, err := os.Lstat(filepath.Join(output, name)); !os.IsNotExist(err) {
			t.Fatalf("build failure published %s: %v", name, err)
		}
	}
}

func TestPackRejectsTamperedPinnedDependencyCacheBeforeOutput(t *testing.T) {
	for _, kind := range []string{"cached-source", "cached-zip", "coordinated-cache"} {
		t.Run(kind, func(t *testing.T) {
			root, _ := gitFixture(t)
			cache := t.TempDir()
			t.Cleanup(func() {
				// Go makes extracted module directories read-only. Restore write
				// permission only in this owned fixture before TempDir cleanup.
				if err := filepath.WalkDir(cache, func(path string, entry os.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if entry.IsDir() {
						return os.Chmod(path, 0700)
					}
					return nil
				}); err != nil {
					t.Errorf("cannot restore synthetic module-cache cleanup permissions: %v", err)
				}
			})
			t.Setenv("GOMODCACHE", cache)
			const module = "example.invalid/pwmigrate-synthetic"
			const version = "v1.0.0"
			mod := "module " + module + "\n\ngo 1.26.0\n"
			writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/pwmigrate-release-fixture\n\ngo 1.26.0\n\nrequire "+module+" "+version+"\n")
			writeTestFile(t, filepath.Join(root, "cmd", "pwmigrate", "main.go"), "package main\nimport synthetic \""+module+"\"\nfunc main() { _ = synthetic.Value; undefinedSyntheticIdentifier() }\n")
			proxy := t.TempDir()
			versions := filepath.Join(proxy, filepath.FromSlash(module), "@v")
			if err := os.MkdirAll(versions, 0755); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(versions, version+".mod"), mod)
			writeTestFile(t, filepath.Join(versions, version+".info"), `{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`)
			makeZIP := func(content string) []byte {
				var archive bytes.Buffer
				writer := zip.NewWriter(&archive)
				for _, member := range []struct{ name, content string }{{"go.mod", mod}, {"synthetic.go", content}} {
					file, err := writer.Create(module + "@" + version + "/" + member.name)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := io.WriteString(file, member.content); err != nil {
						t.Fatal(err)
					}
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				return archive.Bytes()
			}
			if err := os.WriteFile(filepath.Join(versions, version+".zip"), makeZIP("package synthetic\n\nconst Value = \"synthetic original\"\n"), 0644); err != nil {
				t.Fatal(err)
			}
			proxyPath := filepath.ToSlash(proxy)
			if !strings.HasPrefix(proxyPath, "/") {
				proxyPath = "/" + proxyPath
			}
			proxyURL := (&url.URL{Scheme: "file", Path: proxyPath}).String()
			// Populate only this test's module cache, exclusively from a local
			// file:// proxy; checksum lookup and network proxies remain disabled.
			downloadEnv := buildEnv("", "")
			for i, entry := range downloadEnv {
				if strings.HasPrefix(entry, "GOPROXY=") {
					downloadEnv[i] = "GOPROXY=" + proxyURL
				}
			}
			if _, err := run(context.Background(), root, downloadEnv, "go", "mod", "download", module+"@"+version); err != nil {
				t.Fatalf("cannot populate synthetic local module cache: %v", err)
			}
			if _, err := run(context.Background(), root, buildEnv("", ""), "go", "mod", "verify"); err != nil {
				t.Fatalf("pristine synthetic module did not verify: %v", err)
			}
			fixtureGit(t, root, "add", "go.mod", "go.sum", "cmd/pwmigrate/main.go")
			fixtureGit(t, root, "commit", "--quiet", "-m", "Pin synthetic fixture dependency")
			commit := strings.TrimSpace(fixtureGit(t, root, "rev-parse", "HEAD"))
			tampered := filepath.Join(cache, filepath.FromSlash(module)+"@"+version, "synthetic.go")
			if kind == "cached-zip" {
				tampered = filepath.Join(cache, "cache", "download", filepath.FromSlash(module), "@v", version+".zip")
			}
			if err := os.Chmod(tampered, 0644); err != nil {
				t.Fatal(err)
			}
			if kind != "coordinated-cache" {
				writeTestFile(t, tampered, "synthetic cache mutation\n")
			} else {
				// Coordinated source, ZIP and mutable .ziphash changes can pass
				// go mod verify. They must still fail the committed go.sum pin.
				changed := "package synthetic\n\nconst Value = \"synthetic mutation\"\n"
				writeTestFile(t, tampered, changed)
				cachedZIP := filepath.Join(cache, "cache", "download", filepath.FromSlash(module), "@v", version+".zip")
				if err := os.Chmod(cachedZIP, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(cachedZIP, makeZIP(changed), 0644); err != nil {
					t.Fatal(err)
				}
				hash := sha256.New()
				for _, member := range []struct{ name, content string }{{"go.mod", mod}, {"synthetic.go", changed}} {
					fmt.Fprintf(hash, "%x  %s\n", sha256.Sum256([]byte(member.content)), module+"@"+version+"/"+member.name)
				}
				if err := os.Chmod(cachedZIP+"hash", 0644); err != nil {
					t.Fatal(err)
				}
				writeTestFile(t, cachedZIP+"hash", "h1:"+base64.StdEncoding.EncodeToString(hash.Sum(nil)))
				if _, err := run(context.Background(), root, buildEnv("", ""), "go", "mod", "verify"); err != nil {
					t.Fatal("coordinated synthetic cache did not exercise the mutable-hash case")
				}
			}
			pins := make(map[string][]byte)
			for _, name := range []string{"go.mod", "go.sum"} {
				content, err := os.ReadFile(filepath.Join(root, name))
				if err != nil {
					t.Fatal(err)
				}
				pins[name] = content
			}
			t.Chdir(root)
			output := filepath.Join(t.TempDir(), "release")
			err := Pack(context.Background(), Options{Version: "v1.2.3", Commit: commit, Output: output})
			if err == nil || err.Error() != "cannot verify pinned dependencies" {
				t.Errorf("tampered dependency did not produce the fixed verification failure: %v", err)
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Errorf("dependency verification failure created output directory: %v", err)
			}
			for name, before := range pins {
				after, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || !bytes.Equal(before, after) {
					t.Errorf("dependency preflight changed committed %s", name)
				}
			}
			for _, name := range []string{"release-manifest.json", "SHA256SUMS"} {
				if _, err := os.Lstat(filepath.Join(output, name)); !os.IsNotExist(err) {
					t.Errorf("dependency verification failure published %s: %v", name, err)
				}
			}
		})
	}
}

func TestBuildEnvironmentDisablesCallerOverrides(t *testing.T) {
	for key, value := range map[string]string{"GOFLAGS": "-race", "GOWORK": "/nonexistent/workspace", "GOTOOLCHAIN": "automatic-invalid", "GOENV": "/nonexistent/goenv", "GOAMD64": "v4", "GOEXPERIMENT": "bad-experiment", "CGO_ENABLED": "1", "GOPRIVATE": "*", "GONOPROXY": "*", "GONOSUMDB": "*"} {
		t.Setenv(key, value)
	}
	data, err := run(context.Background(), t.TempDir(), buildEnv("linux", "amd64"), "go", "env", "-json", "GOFLAGS", "GOWORK", "GOTOOLCHAIN", "GOENV", "GOAMD64", "GOEXPERIMENT", "CGO_ENABLED", "GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOOS", "GOARCH")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"GOFLAGS": "", "GOWORK": "off", "GOTOOLCHAIN": "local", "GOENV": "", "GOAMD64": "v1", "GOEXPERIMENT": "", "CGO_ENABLED": "0", "GOPROXY": "off", "GOPRIVATE": "", "GONOPROXY": "none", "GONOSUMDB": "none", "GOOS": "linux", "GOARCH": "amd64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("build settings changed by caller: %v", got)
	}
}

func gitFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	fixtureGit(t, root, "init", "--quiet")
	writeTestFile(t, filepath.Join(root, "LICENSE"), "synthetic license\n")
	writeTestFile(t, filepath.Join(root, "README.md"), "synthetic readme\n")
	writeTestFile(t, filepath.Join(root, "THIRD-PARTY-NOTICES.md"), "synthetic dependency notices\n")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "/dist/\n/internal/hidden/\n")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/pwmigrate-release-fixture\n\ngo 1.26.0\n")
	if err := os.MkdirAll(filepath.Join(root, "cmd", "pwmigrate"), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, "cmd", "pwmigrate", "main.go"), "package main\nfunc main() { undefinedSyntheticIdentifier() }\n")
	fixtureGit(t, root, "add", "LICENSE", "README.md", "THIRD-PARTY-NOTICES.md", ".gitignore", "go.mod", "cmd/pwmigrate/main.go")
	fixtureGit(t, root, "commit", "--quiet", "-m", "Synthetic release fixture")
	return root, strings.TrimSpace(fixtureGit(t, root, "rev-parse", "HEAD"))
}

func fixtureGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	base := []string{"-C", root, "-c", "user.name=Synthetic Test", "-c", "user.email=synthetic@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + filepath.Join(root, "no-hooks"), "-c", "init.templateDir="}
	cmd := exec.Command("git", append(base, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture Git failed: %v: %s", err, out)
	}
	return string(out)
}

func writeTestFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestSourceGuardRejectsReplacementContentsUnderOriginalCommit(t *testing.T) {
	root, original := gitFixture(t)
	writeTestFile(t, filepath.Join(root, "README.md"), "different synthetic source content\n")
	fixtureGit(t, root, "add", "README.md")
	fixtureGit(t, root, "commit", "--quiet", "-m", "Synthetic replacement content")
	replacement := strings.TrimSpace(fixtureGit(t, root, "rev-parse", "HEAD"))
	fixtureGit(t, root, "replace", original, replacement)
	fixtureGit(t, root, "update-ref", "HEAD", original)
	if got := strings.TrimSpace(fixtureGit(t, root, "rev-parse", "HEAD")); got != original {
		t.Fatal("fixture lost original literal commit identity")
	}
	if status := fixtureGit(t, root, "status", "--porcelain=v1"); status != "" {
		t.Fatalf("replacement fixture should appear clean: %q", status)
	}
	if status := fixtureGit(t, root, "--no-replace-objects", "status", "--porcelain=v1"); status == "" {
		t.Fatal("fixture did not differ from genuine commit")
	}
	if err := verifySource(context.Background(), root, original); err == nil {
		t.Fatal("replacement source accepted under original commit identity")
	}
}

func TestOfflineEnvironmentBlocksInheritedPrivateBypass(t *testing.T) {
	root, _ := gitFixture(t)
	t.Setenv("GOMODCACHE", t.TempDir())
	t.Setenv("GONOPROXY", "*")
	t.Setenv("GOPRIVATE", "*")
	var requests atomic.Int32
	// Synthetic proxy intercepts requests locally and never forwards anything.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); w.WriteHeader(http.StatusBadGateway) }))
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	writeTestFile(t, filepath.Join(root, "go.mod"), "module example.invalid/pwmigrate-release-fixture\n\ngo 1.26.0\nrequire example.invalid/pwmigrate-offline-probe v1.0.0\n")
	fixtureGit(t, root, "add", "go.mod")
	fixtureGit(t, root, "commit", "--quiet", "-m", "Synthetic uncached module")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	run(ctx, root, buildEnv("", ""), "go", "mod", "verify")
	if requests.Load() != 0 {
		t.Error("offline build environment contacted synthetic proxy under caller GONOPROXY/GOPRIVATE")
	}
}
