package protectedoutput

import (
	"bytes"
	"encoding/binary"
)

// Native privacy-policy decoding is shared so malformed replies can be tested
// on every host. No policy check itself enables a platform's public writer.
func darwinACLAbsent(reply []byte) bool {
	if len(reply) < 12 || binary.LittleEndian.Uint32(reply) != uint32(len(reply)) {
		return false
	}
	// Query exactly one variable-size attribute. Its reference starts at
	// byte 4 and the payload follows the 8-byte reference immediately.
	if binary.LittleEndian.Uint32(reply[4:]) != 8 {
		return false
	}
	length := binary.LittleEndian.Uint32(reply[8:])
	if length == 0 {
		return len(reply) == 12
	}
	if length != 44 || len(reply) != 56 || binary.LittleEndian.Uint32(reply[12:]) != 0x012cc16d {
		return false
	}
	// Do not accept UUID-based authority or unfamiliar ACL semantics.
	if !bytes.Equal(reply[16:48], make([]byte, 32)) || binary.LittleEndian.Uint32(reply[52:]) != 0 {
		return false
	}
	count := binary.LittleEndian.Uint32(reply[48:])
	return count == 0 || count == 0xffffffff // KAUTH_FILESEC_NOACL.
}

func darwinVolumeCapabilities(reply []byte) bool {
	return len(reply) == 36 && binary.LittleEndian.Uint32(reply) == 36 &&
		binary.LittleEndian.Uint32(reply[8:])&0x400 != 0 &&
		binary.LittleEndian.Uint32(reply[24:])&0x400 != 0
}

var systemSID = []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}

func windowsPrivateDescriptor(sd, currentUser []byte) bool {
	if len(sd) < 20 || sd[0] != 1 || sd[1] != 0 || !validSID(currentUser) {
		return false
	}
	const required = 0x8000 | 0x1000 | 0x0004 // SELF_RELATIVE, DACL_PROTECTED, DACL_PRESENT.
	if binary.LittleEndian.Uint16(sd[2:])&required != required {
		return false
	}
	ownerOffset := uint64(binary.LittleEndian.Uint32(sd[4:]))
	daclOffset := uint64(binary.LittleEndian.Uint32(sd[16:]))
	if ownerOffset < 20 || ownerOffset >= uint64(len(sd)) || daclOffset < 20 || daclOffset+8 > uint64(len(sd)) {
		return false
	}
	owner := sidPrefix(sd[ownerOffset:])
	if !bytes.Equal(owner, currentUser) {
		return false
	}
	acl := sd[daclOffset:]
	aclLength := uint64(binary.LittleEndian.Uint16(acl[2:]))
	if acl[0] != 2 || acl[1] != 0 || aclLength < 8 || aclLength > uint64(len(acl)) || acl[6] != 0 || acl[7] != 0 {
		return false
	}
	if ownerOffset < daclOffset+aclLength && daclOffset < ownerOffset+uint64(len(owner)) {
		return false
	}
	acl = acl[:aclLength]
	wantCount := uint16(2)
	if bytes.Equal(currentUser, systemSID) {
		wantCount = 1
	}
	if binary.LittleEndian.Uint16(acl[4:]) != wantCount {
		return false
	}
	userSeen, systemSeen := false, false
	position := 8
	for range wantCount {
		if position+8 > len(acl) {
			return false
		}
		ace := acl[position:]
		size := int(binary.LittleEndian.Uint16(ace[2:]))
		if ace[0] != 0 || ace[1] != 0 || size < 16 || size > len(ace) || binary.LittleEndian.Uint32(ace[4:]) != 0x001f01ff {
			return false
		}
		sid := ace[8:size]
		if !validSID(sid) {
			return false
		}
		switch {
		case bytes.Equal(sid, currentUser) && !userSeen:
			userSeen = true
			if bytes.Equal(currentUser, systemSID) {
				systemSeen = true
			}
		case bytes.Equal(sid, systemSID) && !systemSeen:
			systemSeen = true
		default:
			return false
		}
		position += size
	}
	return position == len(acl) && userSeen && systemSeen
}

func validSID(sid []byte) bool {
	return len(sid) >= 12 && sid[0] == 1 && sid[1] > 0 && sid[1] <= 15 && len(sid) == 8+4*int(sid[1])
}

func sidPrefix(data []byte) []byte {
	if len(data) < 8 || data[0] != 1 || data[1] == 0 || data[1] > 15 {
		return nil
	}
	length := 8 + 4*int(data[1])
	if length > len(data) {
		return nil
	}
	return data[:length]
}

// SYSTEM is an explicit privileged exception, like root on Unix. It is used
// by the operating system and administrators and is outside the other-user
// privacy boundary. There are no group, administrator, or inherited ACEs.
func windowsDescriptor(user []byte) []byte {
	if !validSID(user) {
		return nil
	}
	sids := [][]byte{user}
	if !bytes.Equal(user, systemSID) {
		sids = append(sids, systemSID)
	}
	aclSize := 8
	for _, sid := range sids {
		aclSize += 8 + len(sid)
	}
	daclOffset := 20 + len(user)
	security := make([]byte, daclOffset+aclSize)
	security[0] = 1
	binary.LittleEndian.PutUint16(security[2:], 0x9004)
	binary.LittleEndian.PutUint32(security[4:], 20)
	binary.LittleEndian.PutUint32(security[16:], uint32(daclOffset))
	copy(security[20:], user)
	acl := security[daclOffset:]
	acl[0] = 2
	binary.LittleEndian.PutUint16(acl[2:], uint16(aclSize))
	binary.LittleEndian.PutUint16(acl[4:], uint16(len(sids)))
	offset := 8
	for _, sid := range sids {
		ace := acl[offset:]
		binary.LittleEndian.PutUint16(ace[2:], uint16(8+len(sid)))
		binary.LittleEndian.PutUint32(ace[4:], 0x001f01ff)
		copy(ace[8:], sid)
		offset += 8 + len(sid)
	}
	return security
}
