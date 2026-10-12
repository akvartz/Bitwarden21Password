package protectedoutput

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestDarwinACLAbsenceRequiresCompleteNativeReply(t *testing.T) {
	// getattrlist: total byte count, attrreference offset from byte 4,
	// attrreference length. The queried local volume must separately prove
	// extended-security support before this no-ACL representation is trusted.
	absent := []byte{12, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0}
	if !darwinACLAbsent(absent) {
		t.Fatal("complete no-ACL reply was rejected")
	}
	for _, reply := range [][]byte{
		nil, absent[:11], append(append([]byte{}, absent...), 0),
		{12, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0},
		{12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{12, 0, 0, 0, 8, 0, 0, 0, 44, 0, 0, 0},
	} {
		if darwinACLAbsent(reply) {
			t.Fatal("ambiguous, truncated, or ACL-bearing reply accepted")
		}
	}
	// Explicit kauth_filesec with zero entries still has no granting ACEs.
	empty := make([]byte, 56)
	binary.LittleEndian.PutUint32(empty, 56)
	binary.LittleEndian.PutUint32(empty[4:], 8)
	binary.LittleEndian.PutUint32(empty[8:], 44)
	binary.LittleEndian.PutUint32(empty[12:], 0x012cc16d)
	if !darwinACLAbsent(empty) {
		t.Fatal("complete zero-entry ACL was rejected")
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[12] ^= 1 },
		func(b []byte) { b[48] = 1 }, // ACL entry count.
		func(b []byte) { b[16] = 1 }, // Unexpected owner UUID authority.
		func(b []byte) { b[52] = 1 }, // Unknown ACL flag.
	} {
		bad := append([]byte{}, empty...)
		mutate(bad)
		if darwinACLAbsent(bad) {
			t.Fatal("unproven native ACL accepted")
		}
	}
}

func TestDarwinVolumeMustProveExtendedSecurity(t *testing.T) {
	// Length followed by capabilities[4] and valid[4]. Interface index 1;
	// VOL_CAP_INT_EXTENDED_SECURITY is 0x400 in both arrays.
	reply := make([]byte, 36)
	binary.LittleEndian.PutUint32(reply, 36)
	binary.LittleEndian.PutUint32(reply[8:], 0x400)
	binary.LittleEndian.PutUint32(reply[24:], 0x400)
	if !darwinVolumeCapabilities(reply) {
		t.Fatal("proven extended-security capability rejected")
	}
	for _, index := range []int{0, 9, 25} {
		bad := append([]byte{}, reply...)
		bad[index] = 0
		if darwinVolumeCapabilities(bad) {
			t.Fatal("missing/invalid extended-security proof accepted")
		}
	}
}

func TestWindowsPrivacyRequiresExactProtectedDACL(t *testing.T) {
	// Independent self-relative SECURITY_DESCRIPTOR literal: owner
	// S-1-5-21-1001, protected DACL, exactly two non-inherited allow ACEs
	// granting FILE_ALL_ACCESS to that owner and S-1-5-18 (SYSTEM).
	sd, err := hex.DecodeString("0100049014000000000000000000000024000000" +
		"010200000000000515000000e9030000" +
		"0200340002000000" +
		"00001800ff011f00010200000000000515000000e9030000" +
		"00001400ff011f00010100000000000512000000")
	if err != nil {
		t.Fatal(err)
	}
	user := []byte{1, 2, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 233, 3, 0, 0}
	if !windowsPrivateDescriptor(sd, user) {
		t.Fatal("exact current-user/SYSTEM protected DACL rejected")
	}
	if got := windowsDescriptor(user); string(got) != string(sd) {
		t.Fatal("creation descriptor differs from the independent literal")
	}
	for name, mutate := range map[string]func([]byte){
		"unprotected":            func(b []byte) { b[3] &^= 0x10 },
		"not self-relative":      func(b []byte) { b[3] &^= 0x80 },
		"null DACL":              func(b []byte) { clear(b[16:20]) },
		"foreign owner":          func(b []byte) { b[32] ^= 1 },
		"inherited ACE":          func(b []byte) { b[45] = 0x10 },
		"inheritable ACE":        func(b []byte) { b[45] = 3 },
		"deny ACE":               func(b []byte) { b[44] = 1 },
		"weaker ACE":             func(b []byte) { b[48] = 1 },
		"foreign grant":          func(b []byte) { b[84] = 32 },
		"duplicate current-user": func(b []byte) { b[76] = 2 },
		"empty DACL":             func(b []byte) { b[40] = 0 },
		"oversized ACL":          func(b []byte) { b[38] = 255 },
		"invalid owner offset":   func(b []byte) { b[4] = 255 },
		"invalid DACL offset":    func(b []byte) { b[16] = 255 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := append([]byte{}, sd...)
			mutate(bad)
			if windowsPrivateDescriptor(bad, user) {
				t.Fatal("unproven privacy accepted")
			}
		})
	}
	for size := 0; size < len(sd); size++ {
		if windowsPrivateDescriptor(sd[:size], user) {
			t.Fatalf("truncated descriptor at %d accepted", size)
		}
	}
	for _, invalid := range [][]byte{nil, {1, 1}, {1, 0, 0, 0, 0, 0, 0, 5}} {
		if windowsDescriptor(invalid) != nil {
			t.Fatal("invalid SID produced a creation descriptor")
		}
	}
}
