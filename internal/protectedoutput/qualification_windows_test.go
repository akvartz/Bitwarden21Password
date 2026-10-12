//go:build windows

package protectedoutput

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsQualification(t *testing.T) {
	t.Helper()
	if os.Getenv("PWMIGRATE_NATIVE_PRIVACY_QUALIFY") != "1" {
		t.Skip("privileged native privacy qualification was not requested")
	}
}

type windowsQualificationUser struct {
	name     []uint16
	password []uint16
	token    windows.Token
	sid      string
}

// Diagnostics cross the helper boundary only as fixed phase identifiers.
// Neither its stdout/stderr nor arbitrary file contents are ever printed.
func windowsQualificationHelperPhase(value string) string {
	switch value {
	case "identity", "private_parent", "writer", "artifact_privacy", "exact_bytes", "writer_cleanup", "foreign_parent", "foreign_dacl", "complete":
		return value
	}
	return "process_start"
}

func windowsQualificationHelperProgress(t *testing.T, base string) func(string) {
	t.Helper()
	file, err := os.OpenFile(filepath.Join(base, "helper-phase.txt"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("native helper fixed-diagnostic creation failed")
	}
	t.Cleanup(func() {
		if file.Close() != nil {
			t.Error("native helper fixed-diagnostic close failed")
		}
	})
	return func(phase string) {
		t.Helper()
		if windowsQualificationHelperPhase(phase) != phase {
			t.Fatal("native helper fixed-diagnostic phase was invalid")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			t.Fatal("native helper fixed-diagnostic seek failed")
		}
		if file.Truncate(0) != nil {
			t.Fatal("native helper fixed-diagnostic truncation failed")
		}
		if _, err := io.WriteString(file, phase); err != nil {
			t.Fatal("native helper fixed-diagnostic write failed")
		}
	}
}

func windowsQualificationReadHelperPhase(base string) string {
	root, err := windowsOpenParent(base)
	if err != nil {
		return "process_start"
	}
	handle, openErr := windowsChild(root, "helper-phase.txt", false, false, syscall.GENERIC_READ, nil)
	closeErr := syscall.CloseHandle(root)
	if openErr != nil {
		return "process_start"
	}
	file := os.NewFile(uintptr(handle), "native-helper-phase")
	defer file.Close()
	if closeErr != nil || !windowsDiskObject(handle, false) {
		return "process_start"
	}
	value, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil || len(value) > 32 {
		return "process_start"
	}
	return windowsQualificationHelperPhase(string(value))
}

// The randomly generated temporary account password goes only to native API
// pointers, never process arguments, environment, files, or test diagnostics.
func windowsQualificationAccount(t *testing.T) windowsQualificationUser {
	t.Helper()
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("native account randomness failed")
	}
	name, _ := syscall.UTF16FromString("pwmig-" + hex.EncodeToString(random[:6]))
	password, _ := syscall.UTF16FromString("Aa1!" + base64.RawStdEncoding.EncodeToString(random[:]))
	clear(random[:])
	user := windowsQualificationUser{name: name, password: password}
	t.Cleanup(func() { clear(password) })
	var info struct {
		Name, Password *uint16
		PasswordAge    uint32
		Privilege      uint32
		Home, Comment  *uint16
		Flags          uint32
		Script         *uint16
	}
	info.Name, info.Password, info.Privilege, info.Flags = &name[0], &password[0], 1, 1|0x200|0x10000
	var parameter uint32
	netapi := syscall.NewLazyDLL("netapi32.dll")
	status, _, _ := netapi.NewProc("NetUserAdd").Call(0, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&parameter)))
	runtime.KeepAlive(info)
	runtime.KeepAlive(password)
	if status != 0 {
		t.Fatal("native temporary standard-account creation failed; administrative privilege is required")
	}
	t.Cleanup(func() {
		status, _, _ := netapi.NewProc("NetUserDel").Call(0, uintptr(unsafe.Pointer(&name[0])))
		runtime.KeepAlive(name)
		if status != 0 {
			t.Error("native owned-account cleanup failed")
		}
	})
	domain, _ := syscall.UTF16FromString(".")
	ok, _, _ := windowsAdvapi.NewProc("LogonUserW").Call(uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&password[0])), 2, 0, uintptr(unsafe.Pointer(&user.token)))
	runtime.KeepAlive(password)
	runtime.KeepAlive(domain)
	if ok == 0 {
		t.Fatal("native standard-account logon failed")
	}
	t.Cleanup(func() {
		if user.token.Close() != nil {
			t.Error("native account-token cleanup failed")
		}
	})
	identity, err := user.token.GetTokenUser()
	current, currentErr := windowsCurrentUser()
	if err != nil || currentErr != nil || user.token.IsElevated() || identity.User.Sid.String() == (*windows.SID)(unsafe.Pointer(&current[0])).String() {
		t.Fatal("native second-principal standard token was not established")
	}
	user.sid = identity.User.Sid.String()
	return user
}

func windowsQualificationPublicACL(t *testing.T, path string, directory bool) {
	t.Helper()
	user, err := windowsCurrentUser()
	if err != nil {
		t.Fatal("native fixture identity failed")
	}
	sid := (*windows.SID)(unsafe.Pointer(&user[0])).String()
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	// Only synthetic controls and the copied test executable are shared. The
	// candidate's parent/job/files retain its exact protected private DACL.
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + inheritance + ";FA;;;" + sid + ")(A;" + inheritance + ";FA;;;SY)(A;" + inheritance + ";FA;;;BU)")
	if err != nil {
		t.Fatal("native shared-fixture descriptor failed")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("native shared-fixture path failed")
	}
	flags := uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := syscall.CreateFile(name, windowsAllAccess, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatal("native shared-fixture open failed")
	}
	ok, _, _ := windowsAdvapi.NewProc("SetKernelObjectSecurity").Call(uintptr(handle), 1|4|0x80000000, uintptr(unsafe.Pointer(descriptor)))
	runtime.KeepAlive(descriptor)
	closeErr := syscall.CloseHandle(handle)
	if ok == 0 || closeErr != nil {
		t.Fatal("native shared-fixture ACL failed")
	}
}

func windowsQualificationBase(t *testing.T) string {
	t.Helper()
	root, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal("native fixture system-volume discovery failed")
	}
	// The drive root avoids a private profile/temp ancestor. The new fixture
	// is explicitly shared only after it is created by this test process.
	volume := filepath.VolumeName(root)
	base, err := os.MkdirTemp(volume+`\`, "pwmigrate-native-privacy-")
	if err != nil {
		t.Fatal("native shared-fixture creation failed; administrative privilege is required")
	}
	t.Cleanup(func() {
		if os.RemoveAll(base) != nil {
			t.Error("native owned-directory cleanup failed")
		}
	})
	windowsQualificationPublicACL(t, base, true)
	return base
}

func windowsQualificationPrivateParent(t *testing.T, base, name string) string {
	t.Helper()
	user, err := windowsCurrentUser()
	if err != nil {
		t.Fatal("native private-fixture identity failed")
	}
	root, err := windowsOpenParent(base)
	if err != nil {
		t.Fatal("native private-fixture root failed")
	}
	parent, createErr := windowsCreatePrivate(root, name, true, user)
	rootErr := syscall.CloseHandle(root)
	if createErr != nil || rootErr != nil {
		t.Fatal("native private-fixture creation failed")
	}
	if syscall.CloseHandle(parent) != nil {
		t.Fatal("native private-fixture close failed")
	}
	return filepath.Join(base, name)
}

func windowsQualificationProbe(t *testing.T, path string, directory bool, access uint32, denied bool) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("native access-probe path failed")
	}
	flags := uint32(syscall.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= syscall.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := syscall.CreateFile(name, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, flags, 0)
	if err == nil {
		if syscall.CloseHandle(handle) != nil {
			t.Fatal("native access-probe close failed")
		}
	}
	if denied && !errors.Is(err, syscall.ERROR_ACCESS_DENIED) || !denied && err != nil {
		t.Fatal("native second-principal access result was unexpected")
	}
}

func TestWindowsNativeQualificationSecondPrincipal(t *testing.T) {
	windowsQualification(t)
	user := windowsQualificationAccount(t)
	base := windowsQualificationBase(t)
	control := filepath.Join(base, "control.txt")
	if os.WriteFile(control, []byte("synthetic control"), 0600) != nil {
		t.Fatal("native readable-control fixture failed")
	}
	windowsQualificationPublicACL(t, control, false)
	var jobs, files []string
	for _, retained := range []bool{false, true} {
		name := map[bool]string{false: "published", true: "retained-partial"}[retained]
		parent := windowsQualificationPrivateParent(t, base, name)
		ops := windowsNamedOps()
		if retained {
			ops.sync = func(*os.File) error { return errors.New("synthetic failure") }
		}
		result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic private bytes"), ops)
		artifact := fileName
		if retained {
			requireFailure(t, result, err, "output_sync")
			artifact = partialName
		} else if err != nil {
			t.Fatal("native publication fixture failed")
		}
		job := filepath.Join(parent, windowsTestJob)
		file := filepath.Join(job, artifact)
		got, err := os.ReadFile(file)
		if err != nil || !bytes.Equal(got, []byte("synthetic private bytes")) {
			t.Fatal("native publication/failure fixture bytes changed")
		}
		// Broaden only this fixture ancestor after publication, so job/file
		// denials demonstrate their own DACLs rather than an inaccessible
		// profile or parent. Protected child DACLs do not inherit this change.
		windowsQualificationPublicACL(t, parent, true)
		jobs, files = append(jobs, job), append(files, file)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ok, _, _ := windowsAdvapi.NewProc("ImpersonateLoggedOnUser").Call(uintptr(user.token))
	if ok == 0 {
		t.Fatal("native standard-account impersonation failed")
	}
	defer func() {
		if windows.RevertToSelf() != nil {
			// A failed revert must not return this thread to the Go pool.
			os.Exit(1)
		}
	}()
	var thread windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &thread) != nil {
		t.Fatal("native effective-thread token query failed")
	}
	identity, err := thread.GetTokenUser()
	closeErr := thread.Close()
	if err != nil || closeErr != nil || identity.User.Sid.String() != user.sid {
		t.Fatal("native effective-thread identity was not the second principal")
	}
	windowsQualificationProbe(t, base, true, 1, false) // FILE_LIST_DIRECTORY.
	windowsQualificationProbe(t, control, false, syscall.GENERIC_READ, false)
	for index, job := range jobs {
		windowsQualificationProbe(t, job, true, 1, true)
		windowsQualificationProbe(t, job, true, 2, true)                                        // FILE_ADD_FILE.
		for _, access := range []uint32{syscall.GENERIC_READ, syscall.GENERIC_WRITE, 0x10000} { // DELETE covers removal/rename.
			windowsQualificationProbe(t, files[index], false, access, true)
		}
	}
}

// A separate process is required: the writer intentionally queries its
// process identity, and must never be exercised under a thread-only disguise.
func TestWindowsNativeQualificationStandardUserWriter(t *testing.T) {
	windowsQualification(t)
	user := windowsQualificationAccount(t)
	base := windowsQualificationBase(t)
	admin, err := windowsCurrentUser()
	if err != nil {
		t.Fatal("native foreign-owner fixture identity failed")
	}
	adminSID := (*windows.SID)(unsafe.Pointer(&admin[0])).String()
	foreign := filepath.Join(base, "foreign-owner-parent")
	t.Cleanup(func() {
		if _, err := os.Stat(foreign); os.IsNotExist(err) {
			return
		}
		handle, err := windowsOpenParent(foreign)
		if err != nil {
			t.Error("native owned-parent owner restoration open failed")
			return
		}
		ownerErr := windows.SetSecurityInfo(windows.Handle(handle), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
			(*windows.SID)(unsafe.Pointer(&admin[0])), nil, nil, nil)
		closeErr := syscall.CloseHandle(handle)
		if ownerErr != nil || closeErr != nil {
			t.Error("native owned-parent owner restoration failed")
		}
	})
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("native helper executable discovery failed")
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal("native helper executable read failed")
	}
	helper := filepath.Join(base, "qualification.test.exe")
	destination, err := os.OpenFile(helper, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		source.Close()
		t.Fatal("native helper executable creation failed")
	}
	_, copyErr := io.Copy(destination, source)
	sourceErr, destinationErr := source.Close(), destination.Close()
	if copyErr != nil || sourceErr != nil || destinationErr != nil {
		t.Fatal("native helper executable copy failed")
	}
	windowsQualificationPublicACL(t, helper, false)
	application, _ := syscall.UTF16FromString(helper)
	command, _ := syscall.UTF16FromString(`"` + helper + `" -test.run=^TestWindowsPrivacyQualificationHelper$`)
	domain, _ := syscall.UTF16FromString(".")
	directory, _ := syscall.UTF16FromString(base)
	// No parent secrets/environment are inherited by this fixture helper.
	environment := utf16.Encode([]rune("PWMIGRATE_NATIVE_PRIVACY_HELPER=" + base + "\x00PWMIGRATE_NATIVE_PRIVACY_HELPER_ADMIN_SID=" + adminSID + "\x00PWMIGRATE_NATIVE_PRIVACY_HELPER_SID=" + user.sid + "\x00SystemRoot=" + os.Getenv("SystemRoot") + "\x00TEMP=" + base + "\x00TMP=" + base + "\x00\x00"))
	var startup windows.StartupInfo
	startup.Cb = uint32(unsafe.Sizeof(startup))
	var process windows.ProcessInformation
	ok, _, _ := windowsAdvapi.NewProc("CreateProcessWithLogonW").Call(uintptr(unsafe.Pointer(&user.name[0])), uintptr(unsafe.Pointer(&domain[0])),
		uintptr(unsafe.Pointer(&user.password[0])), 0, uintptr(unsafe.Pointer(&application[0])), uintptr(unsafe.Pointer(&command[0])),
		windows.CREATE_UNICODE_ENVIRONMENT, uintptr(unsafe.Pointer(&environment[0])), uintptr(unsafe.Pointer(&directory[0])),
		uintptr(unsafe.Pointer(&startup)), uintptr(unsafe.Pointer(&process)))
	runtime.KeepAlive(user)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(command)
	if ok == 0 {
		t.Fatal("native standard-user helper launch failed")
	}
	defer windows.CloseHandle(process.Process)
	defer windows.CloseHandle(process.Thread)
	wait, err := windows.WaitForSingleObject(process.Process, 90000)
	if err != nil || wait != windows.WAIT_OBJECT_0 {
		windows.TerminateProcess(process.Process, 1)
		windows.WaitForSingleObject(process.Process, 10000)
		t.Fatal("native standard-user helper did not complete")
	}
	var code uint32
	if windows.GetExitCodeProcess(process.Process, &code) != nil {
		t.Fatal("native standard-user helper exit observation failed")
	}
	phase := windowsQualificationReadHelperPhase(base)
	if code != 0 || phase != "complete" {
		if code == 0xc0000142 {
			phase = "process_initialization"
		}
		t.Fatalf("native standard-user helper failed at fixed phase %s", phase)
	}
	// The standard-user child leaves one empty fixture owned by that user,
	// with a protected DACL granting only this process's user and SYSTEM.
	// Thus this process has real access, but the owner policy must reject it.
	handle, err := windowsOpenParent(foreign)
	if err != nil {
		t.Fatal("native foreign-owner fixture was not accessible")
	}
	security, securityErr := windows.GetSecurityInfo(windows.Handle(handle), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	closeErr := syscall.CloseHandle(handle)
	if securityErr != nil || closeErr != nil {
		t.Fatal("native foreign-owner observation failed")
	}
	owner, _, ownerErr := security.Owner()
	if ownerErr != nil || owner.String() != user.sid || owner.String() == adminSID {
		t.Fatal("native foreign-owner premise was not established")
	}
	windowsAssertEntries(t, foreign, 0)
	result, err := writeWindowsCandidate(context.Background(), foreign, []byte("synthetic"))
	requireFailure(t, result, err, "output_parent")
	windowsAssertEntries(t, foreign, 0)
}

func TestWindowsPrivacyQualificationHelper(t *testing.T) {
	base := os.Getenv("PWMIGRATE_NATIVE_PRIVACY_HELPER")
	if base == "" {
		t.Skip("standard-user fixture helper was not requested")
	}
	progress := windowsQualificationHelperProgress(t, base)
	progress("identity")
	identity, err := windowsCurrentUser()
	token, tokenErr := windows.OpenCurrentProcessToken()
	if tokenErr != nil {
		t.Fatal("native helper process token failed")
	}
	defer token.Close()
	if err != nil || token.IsElevated() || (*windows.SID)(unsafe.Pointer(&identity[0])).String() != os.Getenv("PWMIGRATE_NATIVE_PRIVACY_HELPER_SID") {
		t.Fatal("native helper was not running as the expected standard principal")
	}
	progress("private_parent")
	parent := windowsQualificationPrivateParent(t, base, "standard-user-parent")
	t.Cleanup(func() {
		if os.RemoveAll(parent) != nil {
			t.Error("native standard-user owned-directory cleanup failed")
		}
	})
	progress("writer")
	result, err := writeWindowsCandidate(context.Background(), parent, []byte("synthetic standard-user output"))
	if err != nil {
		t.Fatal("native standard-user candidate failed")
	}
	progress("artifact_privacy")
	for _, entry := range []struct {
		path string
		dir  bool
	}{{parent, true}, {filepath.Join(parent, result.JobDirectory), true}, {filepath.Join(parent, result.JobDirectory, result.FileName), false}} {
		file, err := os.Open(entry.path)
		if err != nil {
			t.Fatal("native standard-user artifact open failed")
		}
		private := windowsPrivateHandle(syscall.Handle(file.Fd()), identity, entry.dir)
		if file.Close() != nil || !private {
			t.Fatal("native standard-user owner/DACL/volume qualification failed")
		}
	}
	progress("exact_bytes")
	got, err := os.ReadFile(filepath.Join(parent, result.JobDirectory, result.FileName))
	if err != nil || !bytes.Equal(got, []byte("synthetic standard-user output")) {
		t.Fatal("native standard-user output bytes changed")
	}
	// The helper owns its private subtree; clean it before the account token
	// exits, since the administrator deliberately lacks a destination ACE.
	progress("writer_cleanup")
	if os.RemoveAll(parent) != nil {
		t.Fatal("native standard-user owned-directory cleanup failed")
	}
	progress("foreign_parent")
	foreign := windowsQualificationPrivateParent(t, base, "foreign-owner-parent")
	transferred := false
	t.Cleanup(func() {
		if !transferred && os.RemoveAll(foreign) != nil {
			t.Error("native standard-user foreign-owner fixture cleanup failed")
		}
	})
	progress("foreign_dacl")
	handle, err := windowsOpenParent(foreign)
	if err != nil {
		t.Fatal("native foreign-owner DACL fixture open failed")
	}
	admin := os.Getenv("PWMIGRATE_NATIVE_PRIVACY_HELPER_ADMIN_SID")
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + admin + ")(A;;FA;;;SY)")
	if err != nil {
		syscall.CloseHandle(handle)
		t.Fatal("native foreign-owner DACL fixture failed")
	}
	// Change only the DACL. The foreign owner is the real creating account;
	// no privileged assignment of a guessed owner SID is required.
	ok, _, _ := windowsAdvapi.NewProc("SetKernelObjectSecurity").Call(uintptr(handle), 4|0x80000000, uintptr(unsafe.Pointer(descriptor)))
	runtime.KeepAlive(descriptor)
	if ok != 0 {
		transferred = true // The parent can restore ownership and clean it.
	}
	closeErr := syscall.CloseHandle(handle)
	if ok == 0 || closeErr != nil {
		t.Fatal("native foreign-owner DACL publication failed")
	}
	progress("complete")
}

func windowsQualificationJunction(t *testing.T, link, target string) {
	t.Helper()
	if os.Mkdir(link, 0700) != nil {
		t.Fatal("native junction directory fixture failed")
	}
	name, _ := syscall.UTF16PtrFromString(link)
	handle, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("native junction handle fixture failed")
	}
	defer syscall.CloseHandle(handle)
	substitute, _ := syscall.UTF16FromString(`\??\` + target)
	printName, _ := syscall.UTF16FromString(target)
	buffer := make([]byte, 16+2*(len(substitute)+len(printName)))
	binary.LittleEndian.PutUint32(buffer, 0xa0000003) // IO_REPARSE_TAG_MOUNT_POINT.
	binary.LittleEndian.PutUint16(buffer[4:], uint16(len(buffer)-8))
	binary.LittleEndian.PutUint16(buffer[10:], uint16(2*(len(substitute)-1)))
	binary.LittleEndian.PutUint16(buffer[12:], uint16(2*len(substitute)))
	binary.LittleEndian.PutUint16(buffer[14:], uint16(2*(len(printName)-1)))
	for index, value := range append(substitute, printName...) {
		binary.LittleEndian.PutUint16(buffer[16+2*index:], value)
	}
	var returned uint32
	if windows.DeviceIoControl(windows.Handle(handle), 0x900a4, &buffer[0], uint32(len(buffer)), nil, 0, &returned, nil) != nil {
		t.Fatal("native junction fixture creation failed")
	}
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		t.Fatal("native junction fixture was not a reparse point")
	}
	resolved, resolveErr := os.Stat(link)
	intended, targetErr := os.Stat(target)
	if resolveErr != nil || targetErr != nil || !os.SameFile(resolved, intended) {
		t.Fatal("native junction did not resolve to the intended target")
	}
}

func TestWindowsNativeQualificationJunctions(t *testing.T) {
	windowsQualification(t)
	for _, phase := range []string{"parent", "intermediate_parent", "existing_job"} {
		t.Run(phase, func(t *testing.T) {
			parent, target := windowsPrivateParent(t), windowsPrivateParent(t)
			link := filepath.Join(filepath.Dir(parent), "junction")
			want := "output_parent"
			if phase == "existing_job" {
				link, want = filepath.Join(parent, windowsTestJob), "output_create"
			}
			windowsQualificationJunction(t, link, target)
			if phase == "parent" {
				parent = link
			} else if phase == "intermediate_parent" {
				windowsQualificationPrivateParent(t, target, "child")
				parent = filepath.Join(link, "child")
			}
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), windowsNamedOps())
			requireFailure(t, result, err, want)
			count := 0
			if phase == "intermediate_parent" {
				count = 1
				windowsAssertEntries(t, filepath.Join(target, "child"), 0)
			}
			windowsAssertEntries(t, target, count)
			if os.Remove(link) != nil {
				t.Fatal("native owned-junction cleanup failed")
			}
		})
	}
}

func windowsQualificationDiskpart(t *testing.T, scriptPath, script string) {
	t.Helper()
	if os.WriteFile(scriptPath, []byte(script), 0600) != nil {
		t.Fatal("native disk fixture script failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, filepath.Join(os.Getenv("SystemRoot"), "System32", "diskpart.exe"), "/s", scriptPath).Run() != nil {
		t.Fatal("native disk fixture command failed")
	}
}

func windowsQualificationOpenImage(image string, access uintptr) (syscall.Handle, uintptr) {
	var storage struct {
		Device uint32
		Vendor windows.GUID
	}
	storage.Device = 2 // VIRTUAL_STORAGE_TYPE_DEVICE_VHD.
	storage.Vendor = windows.GUID{Data1: 0xec984aec, Data2: 0xa0f9, Data3: 0x47e9,
		Data4: [8]byte{0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b}}
	parameters := struct{ Version, RWDepth uint32 }{1, 1}
	name, _ := syscall.UTF16PtrFromString(image)
	var disk syscall.Handle
	virtdisk := syscall.NewLazyDLL("virtdisk.dll")
	status, _, _ := virtdisk.NewProc("OpenVirtualDisk").Call(uintptr(unsafe.Pointer(&storage)), uintptr(unsafe.Pointer(name)),
		access, 0, uintptr(unsafe.Pointer(&parameters)), uintptr(unsafe.Pointer(&disk)))
	runtime.KeepAlive(storage)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(name)
	return disk, status
}

func windowsQualificationOwnedVolume(t *testing.T, image, root string) {
	t.Helper()
	// Bind the assigned letter to our exact new image before writing any
	// fixture directory. Another device claiming the free letter cannot
	// turn a failed diskpart assignment into a write on an unrelated volume.
	rootName, _ := syscall.UTF16PtrFromString(root)
	driveType, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(rootName)))
	if driveType != 3 {
		t.Fatal("native unsupported-filesystem fixture was not a fixed drive")
	}
	disk, status := windowsQualificationOpenImage(image, 0x80000) // VIRTUAL_DISK_ACCESS_GET_INFO.
	if status != 0 || disk == 0 || disk == syscall.InvalidHandle {
		t.Fatal("native owned-image handle premise failed")
	}
	var physical [260]uint16
	capacity := uint32(2 * len(physical))
	virtdisk := syscall.NewLazyDLL("virtdisk.dll")
	status, _, _ = virtdisk.NewProc("GetVirtualDiskPhysicalPath").Call(uintptr(disk), uintptr(unsafe.Pointer(&capacity)), uintptr(unsafe.Pointer(&physical[0])))
	closeErr := syscall.CloseHandle(disk)
	path := syscall.UTF16ToString(physical[:])
	const prefix = `\\.\PhysicalDrive`
	if status != 0 || closeErr != nil || len(path) <= len(prefix) || !strings.EqualFold(path[:len(prefix)], prefix) {
		t.Fatal("native owned-image physical-disk premise failed")
	}
	number, err := strconv.ParseUint(path[len(prefix):], 10, 32)
	if err != nil {
		t.Fatal("native owned-image disk-number premise failed")
	}
	volumeName, _ := syscall.UTF16PtrFromString(`\\.\` + strings.TrimSuffix(root, `\`))
	volume, err := syscall.CreateFile(volumeName, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal("native assigned-volume handle premise failed")
	}
	var extents [64]byte
	var returned uint32
	queryErr := windows.DeviceIoControl(windows.Handle(volume), 0x560000, nil, 0, &extents[0], uint32(len(extents)), &returned, nil) // IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
	closeErr = syscall.CloseHandle(volume)
	// Native VOLUME_DISK_EXTENTS has an aligned DISK_EXTENT at offset 8.
	// The disposable single-partition image must occupy exactly one disk.
	if queryErr != nil || closeErr != nil || returned < 32 || binary.LittleEndian.Uint32(extents[:]) != 1 ||
		binary.LittleEndian.Uint32(extents[8:]) != uint32(number) {
		t.Fatal("native assigned-volume did not belong to the owned image")
	}
}

func windowsQualificationDetachImage(image string) string {
	// Enable the administrative volume privilege only on a temporary
	// impersonation token tied to this locked thread, then revert it before
	// that thread can return to the Go pool. No process token is modified.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if windows.ImpersonateSelf(windows.SecurityImpersonation) != nil {
		return "cleanup_identity"
	}
	defer func() {
		if windows.RevertToSelf() != nil {
			os.Exit(1)
		}
	}()
	var token windows.Token
	if windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &token) != nil {
		return "cleanup_token"
	}
	name, _ := windows.UTF16PtrFromString("SeManageVolumePrivilege")
	var privilege windows.LUID
	if windows.LookupPrivilegeValue(nil, name, &privilege) != nil {
		token.Close()
		return "cleanup_privilege"
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: privilege, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	privilegeErr := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil)
	enabled := privilegeErr == nil && windowsQualificationPrivilegeEnabled(token, privilege)
	closeErr := token.Close()
	if !enabled || closeErr != nil {
		return "cleanup_privilege"
	}
	disk, status := windowsQualificationOpenImage(image, 0xc0000) // GET_INFO | DETACH.
	if status != 0 || disk == 0 || disk == syscall.InvalidHandle {
		return "cleanup_image_open"
	}
	status, _, _ = syscall.NewLazyDLL("virtdisk.dll").NewProc("DetachVirtualDisk").Call(uintptr(disk), 0, 0)
	closeErr = syscall.CloseHandle(disk)
	if closeErr != nil {
		return "cleanup_image_close"
	}
	if status == 0 || status == uintptr(windows.ERROR_DEV_NOT_EXIST) {
		return ""
	}
	switch status {
	case uintptr(windows.ERROR_ACCESS_DENIED):
		return "cleanup_access"
	case uintptr(windows.ERROR_PRIVILEGE_NOT_HELD):
		return "cleanup_privilege"
	case uintptr(windows.ERROR_DEVICE_IN_USE), uintptr(windows.ERROR_SHARING_VIOLATION):
		return "cleanup_in_use"
	}
	return "cleanup_detach"
}

func windowsQualificationPrivilegeEnabled(token windows.Token, want windows.LUID) bool {
	// AdjustTokenPrivileges can report BOOL=true while assigning nothing.
	// Read the effective token back rather than trusting that wrapper result.
	var information [4096]byte
	var returned uint32
	if windows.GetTokenInformation(token, windows.TokenPrivileges, &information[0], uint32(len(information)), &returned) != nil ||
		returned < 4 || returned > uint32(len(information)) {
		return false
	}
	count := binary.LittleEndian.Uint32(information[:])
	if count > (returned-4)/12 {
		return false
	}
	for index := uint32(0); index < count; index++ {
		entry := information[4+12*index : 4+12*(index+1)]
		if binary.LittleEndian.Uint32(entry) == want.LowPart && int32(binary.LittleEndian.Uint32(entry[4:])) == want.HighPart {
			return binary.LittleEndian.Uint32(entry[8:])&windows.SE_PRIVILEGE_ENABLED != 0
		}
	}
	return false
}

func TestWindowsNativeQualificationUnsupportedVolume(t *testing.T) {
	windowsQualification(t)
	base := t.TempDir()
	image, script := filepath.Join(base, "qualification.vhd"), filepath.Join(base, "diskpart.txt")
	mask, _, _ := windowsKernel.NewProc("GetLogicalDrives").Call()
	if mask == 0 {
		t.Fatal("native unused-drive discovery failed")
	}
	var drive byte
	for candidate := byte('Z'); candidate >= 'D'; candidate-- {
		if mask&(1<<(candidate-'A')) == 0 {
			drive = candidate
			break
		}
	}
	if drive == 0 {
		t.Fatal("native disk fixture has no unused drive letter")
	}
	// Cleanup always selects the exact newly owned image, never a disk number
	// or a system/user volume. No existing drive is formatted or detached.
	t.Cleanup(func() {
		if _, err := os.Stat(image); err == nil {
			if phase := windowsQualificationDetachImage(image); phase != "" {
				t.Errorf("native owned-image cleanup failed at fixed phase %s", phase)
			}
		}
	})
	windowsQualificationDiskpart(t, script, "create vdisk file=\""+image+"\" maximum=64 type=expandable\r\nselect vdisk file=\""+image+"\"\r\nattach vdisk\r\ncreate partition primary\r\nformat fs=fat32 quick\r\nassign letter="+string(drive)+"\r\nexit\r\n")
	root := string(drive) + `:\`
	name, _ := syscall.UTF16PtrFromString(root)
	var fs [32]uint16
	if windows.GetVolumeInformation(name, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) != nil || windows.UTF16ToString(fs[:]) != "FAT32" {
		t.Fatal("native disposable FAT32 volume was not established")
	}
	windowsQualificationOwnedVolume(t, image, root)
	parent := filepath.Join(root, "parent")
	if os.Mkdir(parent, 0700) != nil {
		t.Fatal("native unsupported-volume parent fixture failed")
	}
	result, err := writeWindowsCandidate(context.Background(), parent, []byte("synthetic"))
	requireFailure(t, result, err, "output_parent")
	windowsAssertEntries(t, parent, 0)
}

func TestWindowsNativeQualificationPostPublishFailures(t *testing.T) {
	windowsQualification(t)
	for _, phase := range []string{"published_sync", "file_close", "job_close", "parent_close"} {
		t.Run(phase, func(t *testing.T) {
			parent := windowsPrivateParent(t)
			ops := windowsNamedOps()
			want := "output_close"
			if phase == "published_sync" {
				want = "output_sync"
				calls := 0
				ops.sync = func(file *os.File) error {
					calls++
					if calls == 2 {
						return errors.New("synthetic failure")
					}
					return file.Sync()
				}
			} else {
				failAt := map[string]int{"file_close": 1, "job_close": 2, "parent_close": 3}[phase]
				calls := 0
				ops.close = func(file *os.File) error {
					calls++
					err := file.Close()
					if calls == failAt {
						return errors.New("synthetic failure")
					}
					return err
				}
			}
			result, err := writeWindowsWithOps(context.Background(), parent, fileName, []byte("synthetic"), ops)
			requireFailure(t, result, err, want)
			got, err := os.ReadFile(filepath.Join(parent, windowsTestJob, fileName))
			if err != nil || !bytes.Equal(got, []byte("synthetic")) {
				t.Fatal("native retained publication changed after reported failure")
			}
		})
	}
}
