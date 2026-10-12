//go:build darwin

package protectedoutput

import (
	"context"
	"encoding/binary"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// Supported remains false until native ACL, volume, and filesystem-failure
// tests qualify this implementation. Cross-compilation never enables output.
func Supported() bool { return false }

func write(context.Context, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}

func writeNamed(context.Context, string, string, []byte) (Result, error) {
	return Result{}, &Error{Code: "output_platform"}
}

// writeDarwinCandidate is reachable only by same-package native tests. It
// shares Linux's anchored, exclusive, checked, no-clobber write pipeline.
func writeDarwinCandidate(ctx context.Context, parent string, payload []byte) (Result, error) {
	return writeNamedWithOps(ctx, parent, fileName, payload, filesystemOperations())
}

// nativePrivacy checks opened handles, never the current spelling of a path.
// APFS/HFS must be local, honor ownership, and report ACL support before an
// empty extended-security reply is evidence that no ACL grants access.
func nativePrivacy(file *os.File) bool {
	var fs syscall.Statfs_t
	if syscall.Fstatfs(int(file.Fd()), &fs) != nil || fs.Flags&0x1000 == 0 || fs.Flags&(0x200000|1) != 0 {
		return false // MNT_LOCAL, MNT_IGNORE_OWNERSHIP, MNT_RDONLY.
	}
	var name []byte
	for _, value := range fs.Fstypename {
		if value == 0 {
			break
		}
		name = append(name, byte(value))
	}
	if string(name) != "apfs" && string(name) != "hfs" {
		return false
	}
	capabilities, err := darwinAttributes(file, 0, 0x80000000|0x20000, 36)
	if err != nil || !darwinVolumeCapabilities(capabilities) {
		return false
	}
	security, err := darwinAttributes(file, 0x400000, 0, 4096)
	return err == nil && darwinACLAbsent(security)
}

// The ABI is struct attrlist from Darwin sys/attr.h. These are kernel
// syscalls provided by the stdlib; no cgo or shell command is involved.
type darwinAttrlist struct {
	BitmapCount uint16
	Reserved    uint16
	Common      uint32
	Volume      uint32
	Directory   uint32
	File        uint32
	Fork        uint32
}

func darwinAttributes(file *os.File, common, volume uint32, capacity int) ([]byte, error) {
	attributes := darwinAttrlist{BitmapCount: 5, Common: common, Volume: volume}
	buffer := make([]byte, capacity)
	_, _, errno := syscall.Syscall6(syscall.SYS_FGETATTRLIST, file.Fd(),
		uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)), 4, 0) // FSOPT_REPORT_FULLSIZE.
	runtime.KeepAlive(file)
	runtime.KeepAlive(attributes)
	runtime.KeepAlive(buffer)
	if errno != 0 {
		return nil, errno
	}
	length := binary.LittleEndian.Uint32(buffer)
	if length < 4 || uint64(length) > uint64(len(buffer)) {
		return nil, syscall.EINVAL
	}
	return buffer[:length], nil
}
