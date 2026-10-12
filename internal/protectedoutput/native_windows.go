//go:build windows

package protectedoutput

import (
	"bytes"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

var (
	windowsNTDLL      = syscall.NewLazyDLL("ntdll.dll")
	windowsAdvapi     = syscall.NewLazyDLL("advapi32.dll")
	windowsKernel     = syscall.NewLazyDLL("kernel32.dll")
	ntCreateFile      = windowsNTDLL.NewProc("NtCreateFile")
	ntSetInformation  = windowsNTDLL.NewProc("NtSetInformationFile")
	ntQueryVolume     = windowsNTDLL.NewProc("NtQueryVolumeInformationFile")
	getObjectSecurity = windowsAdvapi.NewProc("GetKernelObjectSecurity")
	getDriveType      = windowsKernel.NewProc("GetDriveTypeW")
	getVolumeInfo     = windowsKernel.NewProc("GetVolumeInformationByHandleW")
)

const windowsAllAccess = 0x001f01ff

type windowsUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type windowsObjectAttributes struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *windowsUnicodeString
	Attributes               uint32
	SecurityDescriptor       *byte
	SecurityQualityOfService uintptr
}

type windowsIOStatus struct {
	Status      uintptr
	Information uintptr
}

func windowsCurrentUser() ([]byte, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	user, userErr := token.GetTokenUser()
	if userErr != nil {
		token.Close()
		return nil, userErr
	}
	length := user.User.Sid.Len()
	if length < 12 || length > 68 {
		token.Close()
		return nil, syscall.EINVAL
	}
	sid := bytes.Clone(unsafe.Slice((*byte)(unsafe.Pointer(user.User.Sid)), length))
	runtime.KeepAlive(user)
	if err := token.Close(); err != nil {
		return nil, err
	}
	if !validSID(sid) {
		return nil, syscall.EINVAL
	}
	return sid, nil
}

// windowsOpenParent opens a drive root, then every path component relative
// to the preceding handle. UNC/device spellings, remote/non-NTFS volumes and
// all reparse points are rejected. Parent renames cannot redirect children.
func windowsOpenParent(path string) (syscall.Handle, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	volume := filepath.VolumeName(absolute)
	if len(volume) != 2 || volume[1] != ':' || (volume[0] < 'A' || volume[0] > 'Z') && (volume[0] < 'a' || volume[0] > 'z') {
		return syscall.InvalidHandle, syscall.EINVAL
	}
	rootName, err := syscall.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	driveType, _, _ := getDriveType.Call(uintptr(unsafe.Pointer(rootName)))
	if driveType != 3 { // DRIVE_FIXED; removable and network drives fail closed.
		return syscall.InvalidHandle, syscall.EINVAL
	}
	root, err := syscall.CreateFile(rootName, 0x001200a9,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	if !windowsDiskObject(root, true) || !windowsSupportedVolume(root) {
		syscall.CloseHandle(root)
		return syscall.InvalidHandle, syscall.EINVAL
	}
	components := strings.Split(strings.TrimPrefix(absolute[len(volume):], `\`), `\`)
	if len(components) == 1 && components[0] == "" {
		return root, nil
	}
	for i, component := range components {
		access := uint32(0x001200a9) // READ_CONTROL, SYNCHRONIZE, read/traverse.
		if i == len(components)-1 {
			access = windowsAllAccess
		}
		next, openErr := windowsChild(root, component, true, false, access, nil)
		closeErr := syscall.CloseHandle(root)
		if openErr != nil {
			return syscall.InvalidHandle, openErr
		}
		if closeErr != nil {
			syscall.CloseHandle(next)
			return syscall.InvalidHandle, closeErr
		}
		root = next
		if !windowsDiskObject(root, true) || !windowsSupportedVolume(root) {
			syscall.CloseHandle(root)
			return syscall.InvalidHandle, syscall.EINVAL
		}
	}
	return root, nil
}

func windowsCreatePrivate(parent syscall.Handle, name string, directory bool, user []byte) (syscall.Handle, error) {
	security := windowsDescriptor(user)
	if security == nil {
		return syscall.InvalidHandle, syscall.EINVAL
	}
	return windowsChild(parent, name, directory, true, windowsAllAccess, security)
}

func windowsChild(parent syscall.Handle, name string, directory, create bool, access uint32, security []byte) (syscall.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`+"\x00") {
		return syscall.InvalidHandle, syscall.EINVAL
	}
	utf16Name, err := syscall.UTF16FromString(name)
	if err != nil || len(utf16Name)*2 > 65535 {
		return syscall.InvalidHandle, syscall.EINVAL
	}
	unicodeName := windowsUnicodeString{
		Length: uint16((len(utf16Name) - 1) * 2), MaximumLength: uint16(len(utf16Name) * 2), Buffer: &utf16Name[0],
	}
	attributes := windowsObjectAttributes{
		Length: uint32(unsafe.Sizeof(windowsObjectAttributes{})), RootDirectory: parent,
		ObjectName: &unicodeName, Attributes: 0x40 | 0x1000, // OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE.
	}
	if len(security) != 0 {
		attributes.SecurityDescriptor = &security[0]
	}
	disposition := uintptr(1) // FILE_OPEN.
	if create {
		disposition = 2 // FILE_CREATE: collisions fail, including reparse entries.
	}
	options := uintptr(0x20 | 0x200000) // FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT.
	fileAttributes := uintptr(syscall.FILE_ATTRIBUTE_NORMAL)
	if directory {
		options |= 1 // FILE_DIRECTORY_FILE.
		fileAttributes = syscall.FILE_ATTRIBUTE_DIRECTORY
	} else {
		options |= 0x40 // FILE_NON_DIRECTORY_FILE.
	}
	var handle syscall.Handle
	var status windowsIOStatus
	code, _, _ := ntCreateFile.Call(uintptr(unsafe.Pointer(&handle)), uintptr(access),
		uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&status)), 0,
		fileAttributes, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		disposition, options, 0, 0)
	runtime.KeepAlive(utf16Name)
	runtime.KeepAlive(security)
	runtime.KeepAlive(attributes)
	if uint32(code)&0x80000000 != 0 {
		return syscall.InvalidHandle, syscall.EINVAL
	}
	if handle == 0 || handle == syscall.InvalidHandle || create && status.Information != 2 {
		if handle != 0 && handle != syscall.InvalidHandle {
			syscall.CloseHandle(handle)
		}
		return syscall.InvalidHandle, syscall.EINVAL
	}
	return handle, nil
}

func windowsDiskObject(handle syscall.Handle, directory bool) bool {
	kind, err := syscall.GetFileType(handle)
	if err != nil || kind != syscall.FILE_TYPE_DISK {
		return false
	}
	var info syscall.ByHandleFileInformation
	if syscall.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if (info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return false
	}
	return directory || info.NumberOfLinks == 1
}

func windowsSupportedVolume(handle syscall.Handle) bool {
	var fs [32]uint16
	var flags uint32
	ok, _, _ := getVolumeInfo.Call(uintptr(handle), 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&flags)), uintptr(unsafe.Pointer(&fs[0])), uintptr(len(fs)))
	if ok == 0 || syscall.UTF16ToString(fs[:]) != "NTFS" || flags&8 == 0 {
		return false // FILE_PERSISTENT_ACLS.
	}
	var device struct{ Type, Characteristics uint32 }
	var status windowsIOStatus
	code, _, _ := ntQueryVolume.Call(uintptr(handle), uintptr(unsafe.Pointer(&status)),
		uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), 4) // FileFsDeviceInformation.
	return uint32(code)&0x80000000 == 0 && device.Type == 7 && device.Characteristics&0x10 == 0
}

func windowsPrivateHandle(handle syscall.Handle, user []byte, directory bool) bool {
	if !windowsDiskObject(handle, directory) || !windowsSupportedVolume(handle) {
		return false
	}
	security := make([]byte, 512)
	for range 2 {
		var needed uint32
		ok, _, err := getObjectSecurity.Call(uintptr(handle), 1|4,
			uintptr(unsafe.Pointer(&security[0])), uintptr(len(security)), uintptr(unsafe.Pointer(&needed)))
		if ok != 0 {
			return needed >= 20 && needed <= uint32(len(security)) && windowsPrivateDescriptor(security[:needed], user)
		}
		if err != syscall.ERROR_INSUFFICIENT_BUFFER || needed <= uint32(len(security)) || needed > 65536 {
			return false
		}
		security = make([]byte, needed)
	}
	return false
}

func windowsPublish(file, job syscall.Handle, name string) error {
	if !allowedFileName(name) {
		return syscall.EINVAL
	}
	utf16Name, err := syscall.UTF16FromString(name)
	if err != nil {
		return err
	}
	// Native FILE_RENAME_INFORMATION, using the open directory handle and
	// ReplaceIfExists=false. This does not resolve or reopen a partial path.
	var rename struct {
		ReplaceIfExists byte
		RootDirectory   syscall.Handle
		FileNameLength  uint32
		FileName        [260]uint16
	}
	rename.RootDirectory = job
	rename.FileNameLength = uint32((len(utf16Name) - 1) * 2)
	copy(rename.FileName[:], utf16Name)
	var status windowsIOStatus
	code, _, _ := ntSetInformation.Call(uintptr(file), uintptr(unsafe.Pointer(&status)),
		uintptr(unsafe.Pointer(&rename)), unsafe.Offsetof(rename.FileName)+uintptr(rename.FileNameLength), 10)
	if uint32(code)&0x80000000 != 0 {
		return syscall.EINVAL
	}
	return nil
}
