//go:build windows

package protectedoutput

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/akvartz/Bitwarden21Password/internal/testsupport"
	"golang.org/x/sys/windows"
)

const windowsRecipeDocumentLimit = 64 << 10
const windowsRecipeOutputLimit = 16 << 10
const windowsRecipeColdTimeout = 3 * time.Minute
const windowsRecipeWarmTimeout = 30 * time.Second

// This executes the current user's built-in PowerShell recipe. It does not
// assert that an administrative runner has become a standard-user actor.
func TestWindowsDocumentedPowerShellPrivateParentRecipe(t *testing.T) {
	if !Supported() {
		t.Fatal("documented recipe requires the qualified public Windows writer")
	}
	body := windowsDocumentedRecipe(t)
	base := testsupport.PrivateParent(t)
	baseSecurity := windowsRecipeSecurity(t, base)
	source := filepath.Join(base, "synthetic-existing-source.txt")
	const sourceBytes = "synthetic existing source, exact\r\nbytes\n"
	if os.WriteFile(source, []byte(sourceBytes), 0600) != nil {
		t.Fatal("documented recipe synthetic source setup failed")
	}
	sourceInfo, err := os.Stat(source)
	if err != nil {
		t.Fatal("documented recipe source observation failed")
	}
	sourceSecurity := windowsRecipeSecurity(t, source)
	windowsRunDocumentedRecipe(t, body, base, true)
	parent := filepath.Join(base, "pwmigrate-output")
	testsupport.AssertPrivate(t, parent, true)
	if windowsRecipeSecurity(t, base) != baseSecurity {
		t.Fatal("documented recipe changed the existing base security")
	}
	artifacts := make(map[string][]byte, 2)
	for _, fixture := range []struct{ name, payload string }{
		{"bitwarden.json", "{\"synthetic\":\" exact \\r\\n世界\"}\n"},
		// This fixed synthetic payload proves named private publication only;
		// actual age-key generation/recovery has separate CLI journey tests.
		{"recovery-key.txt", "synthetic recovery-key fixture bytes\r\n"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		result, writeErr := WriteNamed(ctx, parent, fixture.name, []byte(fixture.payload))
		cancel()
		if writeErr != nil || result.FileName != fixture.name || !regexp.MustCompile(`^job-[0-9a-f]{32}$`).MatchString(result.JobDirectory) {
			t.Fatal("documented recipe public named publication failed")
		}
		job := filepath.Join(parent, result.JobDirectory)
		path := filepath.Join(job, result.FileName)
		testsupport.AssertPrivate(t, job, true)
		testsupport.AssertPrivate(t, path, false)
		got, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(got, []byte(fixture.payload)) {
			t.Fatal("documented recipe public artifact bytes differed")
		}
		artifacts[path] = got
	}
	parentSecurity := windowsRecipeSecurity(t, parent)
	beforeBase, beforeParent := windowsRecipeEntries(t, base), windowsRecipeEntries(t, parent)
	windowsRunDocumentedRecipe(t, body, base, false)
	if !reflect.DeepEqual(beforeBase, windowsRecipeEntries(t, base)) || !reflect.DeepEqual(beforeParent, windowsRecipeEntries(t, parent)) ||
		windowsRecipeSecurity(t, base) != baseSecurity || windowsRecipeSecurity(t, parent) != parentSecurity {
		t.Fatal("repeated documented recipe replaced existing directory state")
	}
	testsupport.AssertPrivate(t, parent, true)
	got, err := os.ReadFile(source)
	afterSource, statErr := os.Stat(source)
	if err != nil || statErr != nil || string(got) != sourceBytes || afterSource.Size() != sourceInfo.Size() ||
		afterSource.Mode() != sourceInfo.Mode() || !afterSource.ModTime().Equal(sourceInfo.ModTime()) || windowsRecipeSecurity(t, source) != sourceSecurity {
		t.Fatal("documented recipe changed the existing synthetic source")
	}
	for path, original := range artifacts {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, original) {
			t.Fatal("repeated documented recipe changed a published artifact")
		}
		testsupport.AssertPrivate(t, path, false)
	}
}

func windowsDocumentedRecipe(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "agentic", "native-output-journey.md")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("documented recipe source unavailable")
	}
	info, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, windowsRecipeDocumentLimit+1))
	closeErr := file.Close()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() > windowsRecipeDocumentLimit || readErr != nil || closeErr != nil ||
		len(data) > windowsRecipeDocumentLimit || !utf8.Valid(data) {
		t.Fatal("documented recipe source boundary differed")
	}
	fences := regexp.MustCompile("(?ms)^```powershell\\r?\\n(.*?)^```\\r?$").FindAllStringSubmatch(string(data), -1)
	var found []string
	for _, fence := range fences {
		if strings.Contains(fence[1], "$ErrorActionPreference = 'Stop'") {
			found = append(found, fence[1])
		}
	}
	if len(found) != 1 || len(found[0]) == 0 {
		t.Fatal("documented recipe fence was missing or ambiguous")
	}
	return found[0]
}

type windowsRecipeDiscard struct {
	bytes  atomic.Int64
	cancel context.CancelFunc
}

func (output *windowsRecipeDiscard) Write(data []byte) (int, error) {
	if output.bytes.Add(int64(len(data))) > windowsRecipeOutputLimit {
		output.cancel()
		return 0, errors.New("documented_recipe_output_limit")
	}
	return len(data), nil
}

func TestWindowsDocumentedRecipeOutputCollectorBounds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := &windowsRecipeDiscard{cancel: cancel}
	if n, err := output.Write([]byte("synthetic")); n != 9 || err != nil || ctx.Err() != nil {
		t.Fatal("documented recipe output discard differed")
	}
	if n, err := output.Write(make([]byte, windowsRecipeOutputLimit)); n != 0 || err == nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("documented recipe output limit did not cancel the child")
	}
}

func windowsRunDocumentedRecipe(t *testing.T, body, base string, success bool) {
	t.Helper()
	root := os.Getenv("SystemRoot")
	nativeRoot, err := windows.GetWindowsDirectory()
	if err != nil || !filepath.IsAbs(root) || !strings.EqualFold(filepath.Clean(root), filepath.Clean(nativeRoot)) {
		t.Fatal("documented recipe built-in system directory unavailable")
	}
	program := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	info, err := os.Lstat(program)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("documented recipe built-in Windows PowerShell unavailable")
	}
	units := utf16.Encode([]rune(body))
	encoded := make([]byte, 2*len(units))
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[2*index:], unit)
	}
	// The first inbox PowerShell/.NET launch can initialize cold assemblies on
	// ARM64 runners while other test packages build. Keep that bounded startup
	// budget separate from the warm repeat that must promptly refuse clobbering.
	budget := windowsRecipeWarmTimeout
	if success {
		budget = windowsRecipeColdTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	command := exec.CommandContext(ctx, program, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	command.Dir = base
	command.WaitDelay = time.Second
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_NO_WINDOW}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "LOCALAPPDATA") {
			command.Env = append(command.Env, entry)
		}
	}
	command.Env = append(command.Env, "LOCALAPPDATA="+base)
	output := &windowsRecipeDiscard{cancel: cancel}
	command.Stdout, command.Stderr = output, output
	// No profile, script file, raw report, SID or diagnostic leaves this test.
	runErr := command.Run()
	if ctx.Err() != nil || output.bytes.Load() > windowsRecipeOutputLimit {
		if success {
			t.Fatal("documented recipe process bound exceeded phase 1")
		}
		t.Fatal("documented recipe process bound exceeded phase 2")
	}
	if success {
		if runErr != nil {
			t.Fatal("documented recipe native execution failed")
		}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) || exitErr.ExitCode() == 0 {
			t.Fatal("repeated documented recipe did not refuse existing output")
		}
	}
}

func windowsRecipeSecurity(t *testing.T, path string) string {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("documented recipe security path unavailable")
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("documented recipe security handle unavailable")
	}
	security, securityErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	closeErr := windows.CloseHandle(handle)
	if securityErr != nil || closeErr != nil || security == nil {
		t.Fatal("documented recipe security observation failed")
	}
	// This SID-bearing snapshot remains in memory and is compared without logs.
	snapshot := security.String()
	if snapshot == "" {
		t.Fatal("documented recipe security snapshot unavailable")
	}
	return snapshot
}

func windowsRecipeEntries(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal("documented recipe directory observation failed")
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}
