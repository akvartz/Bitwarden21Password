//go:build windows

// Package testsupport supplies synthetic private output fixtures. Production
// code must not import it or use it to change platform qualification gates.
package testsupport

import (
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const fullFileAccess = 0x001f01ff

func fixtureUserSID(t testing.TB) string {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal("private fixture process token unavailable")
	}
	user, userErr := token.GetTokenUser()
	closeErr := token.Close()
	if userErr != nil || closeErr != nil {
		t.Fatal("private fixture process identity unavailable")
	}
	return user.User.Sid.String()
}

func PrivateParent(t testing.TB) string {
	t.Helper()
	base := t.TempDir()
	user := fixtureUserSID(t)
	acl := "(A;;FA;;;" + user + ")"
	if user != "S-1-5-18" {
		acl += "(A;;FA;;;SY)"
	}
	// Create the new directory with a protected DACL and an explicit current-
	// user owner. No inheritance flags, groups or administrator ACEs are used.
	sd, err := windows.SecurityDescriptorFromString("O:" + user + "D:P" + acl)
	if err != nil {
		t.Fatal("private fixture descriptor creation failed")
	}
	path := filepath.Join(base, "private-output")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("private fixture path encoding failed")
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal("private fixture exclusive directory creation failed")
	}
	runtime.KeepAlive(sd)
	AssertPrivate(t, path, true)
	return path
}

func AssertPrivate(t testing.TB, path string, directory bool) {
	t.Helper()
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatal("private fixture was not on a fixed local drive")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		t.Fatal("private fixture was not on a fixed local drive")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("private fixture path encoding failed")
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatal("private fixture observation handle failed")
	}
	defer func() {
		if windows.CloseHandle(handle) != nil {
			t.Error("private fixture observation close failed")
		}
	}()
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || (!directory && info.NumberOfLinks != 1) {
		t.Fatal("private fixture object type differed")
	}
	var fs [32]uint16
	var volumeFlags uint32
	if windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, &volumeFlags, &fs[0], uint32(len(fs))) != nil ||
		windows.UTF16ToString(fs[:]) != "NTFS" || volumeFlags&windows.FILE_PERSISTENT_ACLS == 0 {
		t.Fatal("private fixture volume policy differed")
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("private fixture security observation failed")
	}
	owner, _, err := sd.Owner()
	user := fixtureUserSID(t)
	if err != nil || owner == nil || owner.String() != user {
		t.Fatal("private fixture owner differed")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 || control&windows.SE_DACL_PRESENT == 0 {
		t.Fatal("private fixture DACL was not protected")
	}
	acl, _, err := sd.DACL()
	want := uint16(2)
	if user == "S-1-5-18" {
		want = 1
	}
	if err != nil || acl == nil || acl.AceCount != want {
		t.Fatal("private fixture DACL had extra or missing grants")
	}
	seen := make(map[string]bool, 2)
	for index := uint32(0); index < uint32(acl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, index, &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 || ace.Mask != fullFileAccess {
			t.Fatal("private fixture ACE policy differed")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if (sid != user && sid != "S-1-5-18") || seen[sid] {
			t.Fatal("private fixture grant identity differed")
		}
		seen[sid] = true
	}
	if !seen[user] || !seen["S-1-5-18"] {
		t.Fatal("private fixture user or system grant was absent")
	}
	runtime.KeepAlive(sd)
}
