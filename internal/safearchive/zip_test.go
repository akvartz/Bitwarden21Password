package safearchive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"testing"
)

// Produced independently with Python's standard-library zipfile, with a stored
// synthetic file and a Unix regular-file mode. Expected content is a literal,
// rather than the result of a roundtrip through the implementation under test.
const storedFixture = "504b03041400000000000000215c3a7b4182150000001500000009000000646174612e6a736f6e207b2273796e746865746963223a747275657d0d0a504b010214031400000000000000215c3a7b41821500000015000000090000000000000000000000808100000000646174612e6a736f6e504b05060000000001000100370000003c0000000000"

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(storedFixture)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type member struct {
	name string
	data []byte
	mode fs.FileMode
}

func makeZIP(t *testing.T, members ...member) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, m := range members {
		h := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		if m.mode != 0 {
			h.SetMode(m.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(m.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func requireCode(t *testing.T, data []byte, code string) {
	t.Helper()
	got, err := ReadZIP(data)
	if got != nil {
		t.Fatal("failed archive returned partial data")
	}
	var safe *Error
	if !errors.As(err, &safe) || safe.Code != code || err.Error() != code {
		t.Fatalf("expected fixed code %s; got %T %v", code, err, err)
	}
}

func TestReadZIPIndependentStoredFixture(t *testing.T) {
	data := fixture(t)
	got, err := ReadZIP(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got["data.json"], []byte(" {\"synthetic\":true}\r\n")) {
		t.Fatal("archive did not preserve the literal bytes")
	}
	for i := range data {
		data[i] = 0
	}
	if string(got["data.json"]) != " {\"synthetic\":true}\r\n" {
		t.Fatal("returned payload aliases caller-owned archive bytes")
	}
}

func TestReadZIPFilesAndDirectories(t *testing.T) {
	got, err := ReadZIP(makeZIP(t,
		member{name: "folder/", mode: fs.ModeDir | 0700},
		member{name: "folder/data.json", data: []byte("\r\n exact \x00 bytes \n")},
		member{name: "empty", data: []byte{}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got["folder/data.json"]) != "\r\n exact \x00 bytes \n" {
		t.Fatal("files changed or directory returned")
	}
	if b, ok := got["empty"]; !ok || len(b) != 0 {
		t.Fatal("empty file omitted")
	}
}

func TestReadZIPRejectsUnsafePaths(t *testing.T) {
	for i, name := range []string{
		"", "../private", "a/../../private", "/private", "//server/private",
		"C:/private", "C:private", "a\\private", "a\x00private", "a//b", "a/./b",
		"a/../b", ".", "..", "a/b/c/d/e/f/g/h/i", "\xffbad",
	} {
		t.Run(fmt.Sprintf("case_%d", i+1), func(t *testing.T) {
			requireCode(t, makeZIP(t, member{name: name}), "archive_path")
		})
	}
	if _, err := ReadZIP(makeZIP(t, member{name: "a/b/c/d/e/f/g/h"})); err != nil {
		t.Fatal("maximum allowed depth was rejected")
	}
}

func TestReadZIPRejectsConflictingNames(t *testing.T) {
	for i, names := range [][2]string{
		{"same", "same"}, {"same", "SAME"}, {"σ", "ς"}, {"a", "a/b"},
		{"a/b", "a"}, {"a/", "a"}, {"a", "a/"}, {"a/", "a/"},
		{"a/b", "A/c"}, {"a/b/", "a/b"},
	} {
		t.Run(fmt.Sprintf("case_%d", i+1), func(t *testing.T) {
			requireCode(t, makeZIP(t, member{name: names[0]}, member{name: names[1]}), "archive_conflict")
		})
	}
}

func TestReadZIPRejectsSpecialEntries(t *testing.T) {
	for i, mode := range []fs.FileMode{
		fs.ModeSymlink, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeDevice,
		fs.ModeDevice | fs.ModeCharDevice,
	} {
		t.Run(fmt.Sprintf("case_%d", i+1), func(t *testing.T) {
			requireCode(t, makeZIP(t, member{name: "private", mode: mode | 0600}), "archive_special")
		})
	}
}

func TestReadZIPRejectsUnrecognizedUnixAndDOSSpecialModes(t *testing.T) {
	data := fixture(t)
	c := centralOffset(t, data)
	binary.LittleEndian.PutUint32(data[c+38:c+42], 0xd000<<16)
	requireCode(t, data, "archive_special")
	for _, attr := range []uint32{0x08, 0x40} {
		data := fixture(t)
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint16(data[c+4:c+6], 20)
		binary.LittleEndian.PutUint32(data[c+38:c+42], attr)
		requireCode(t, data, "archive_special")
	}
}

func centralOffset(t *testing.T, data []byte) int {
	t.Helper()
	n := bytes.Index(data, []byte("PK\x01\x02"))
	if n < 0 {
		t.Fatal("synthetic fixture central header missing")
	}
	return n
}

func TestReadZIPRejectsEncryptedAndUnsupportedCompression(t *testing.T) {
	for _, flag := range []uint16{1, 1 << 6, 1 << 13} {
		data := fixture(t)
		binary.LittleEndian.PutUint16(data[6:8], flag)
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint16(data[c+8:c+10], flag)
		requireCode(t, data, "archive_encrypted")
	}
	data := fixture(t)
	binary.LittleEndian.PutUint16(data[8:10], 99)
	c := centralOffset(t, data)
	binary.LittleEndian.PutUint16(data[c+10:c+12], 99)
	requireCode(t, data, "archive_compression")
}

func TestReadZIPRejectsNestedZIPMagic(t *testing.T) {
	for _, magic := range []string{"PK\x03\x04", "PK\x05\x06", "PK\x06\x06", "PK\x07\x08"} {
		requireCode(t, makeZIP(t, member{name: "plain.dat", data: []byte(magic + "synthetic")}), "archive_nested")
	}
}

func TestReadZIPDetectsCorruptionAndHeaderDisagreement(t *testing.T) {
	t.Run("checksum", func(t *testing.T) {
		data := fixture(t)
		data[39] ^= 1
		requireCode(t, data, "archive_invalid")
	})
	t.Run("truncated_directory", func(t *testing.T) {
		data := fixture(t)
		requireCode(t, data[:len(data)-1], "archive_invalid")
	})
	t.Run("local_name", func(t *testing.T) {
		data := fixture(t)
		data[30] = 'x'
		requireCode(t, data, "archive_invalid")
	})
	t.Run("local_flags", func(t *testing.T) {
		data := fixture(t)
		data[6] = 1
		requireCode(t, data, "archive_invalid")
	})
	t.Run("claimed_size", func(t *testing.T) {
		data := fixture(t)
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint32(data[22:26], 20)
		binary.LittleEndian.PutUint32(data[c+24:c+28], 20)
		requireCode(t, data, "archive_invalid")
	})
	t.Run("directory_data", func(t *testing.T) {
		data := makeZIP(t, member{name: "a/"})
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint32(data[c+24:c+28], 1)
		requireCode(t, data, "archive_invalid")
	})
	t.Run("directory_crc", func(t *testing.T) {
		data := makeZIP(t, member{name: "a/"})
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint32(data[c+16:c+20], 1)
		requireCode(t, data, "archive_invalid")
	})
	t.Run("descriptor_size", func(t *testing.T) {
		data := makeZIP(t, member{name: "a", data: []byte("synthetic")})
		c := centralOffset(t, data)
		binary.LittleEndian.PutUint32(data[c-8:c-4], 1)
		requireCode(t, data, "archive_invalid")
	})
	t.Run("truncated_deflate_stream", func(t *testing.T) {
		data := makeZIP(t, member{name: "a", data: []byte("synthetic")})
		c := centralOffset(t, data)
		compressed := int(binary.LittleEndian.Uint32(data[c+20 : c+24]))
		// Preserve the central structure and declared length but destroy the
		// final byte of the DEFLATE stream before its data descriptor.
		data[31+compressed-1] ^= 0xff
		requireCode(t, data, "archive_invalid")
	})
}

func TestReadZIPAlwaysChecksPayloadCRC(t *testing.T) {
	data := fixture(t)
	c := centralOffset(t, data)
	binary.LittleEndian.PutUint32(data[14:18], 0)
	binary.LittleEndian.PutUint32(data[c+16:c+20], 0)
	data[39] ^= 1
	requireCode(t, data, "archive_invalid")

	// Independent Python zipfile fixture containing a nonempty literal whose
	// IEEE CRC32 is zero. Zero is a valid checksum and must still be checked.
	zero, err := hex.DecodeString("504b03041400000000000000215c000000000400000004000000080000007a65726f2e6461749d0ad96d504b010214031400000000000000215c0000000004000000040000000800000000000000000000008081000000007a65726f2e646174504b05060000000001000100360000002a0000000000")
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadZIP(zero)
	if err != nil || !bytes.Equal(got["zero.dat"], []byte{0x9d, 0x0a, 0xd9, 0x6d}) {
		t.Fatal("legitimate zero CRC payload was rejected or changed", err)
	}
	zero[38] ^= 1
	requireCode(t, zero, "archive_invalid")
}

func TestReadZIPRejectsUnconsumedCompressedBytes(t *testing.T) {
	data := makeZIP(t, member{name: "a", data: []byte("synthetic")})
	c := centralOffset(t, data)
	compressed := binary.LittleEndian.Uint32(data[c+20 : c+24])
	junk := []byte("unindexed synthetic payload")
	split := 31 + int(compressed)
	out := append([]byte(nil), data[:split]...)
	out = append(out, junk...)
	out = append(out, data[split:]...)
	c += len(junk)
	binary.LittleEndian.PutUint32(out[c+20:c+24], compressed+uint32(len(junk)))
	binary.LittleEndian.PutUint32(out[c-8:c-4], compressed+uint32(len(junk)))
	e := len(out) - 22
	binary.LittleEndian.PutUint32(out[e+16:e+20], uint32(c))
	requireCode(t, out, "archive_invalid")
}

func TestReadZIPLimits(t *testing.T) {
	t.Run("compressed", func(t *testing.T) {
		requireCode(t, make([]byte, MaxCompressedBytes+1), "archive_input_limit")
	})
	t.Run("entries", func(t *testing.T) {
		members := make([]member, MaxEntries+1)
		for i := range members {
			members[i].name = fmt.Sprintf("file_%d", i)
		}
		data := makeZIP(t, members...)
		requireCode(t, data, "archive_entry_limit")
		// A small declared EOCD count must not let archive/zip allocate one
		// File per actual central-directory record beyond our entry budget.
		e := len(data) - 22
		binary.LittleEndian.PutUint16(data[e+8:e+10], 1)
		binary.LittleEndian.PutUint16(data[e+10:e+12], 1)
		requireCode(t, data, "archive_entry_limit")
	})
	t.Run("exact_compressed", func(t *testing.T) {
		var out bytes.Buffer
		w := zip.NewWriter(&out)
		f, err := w.CreateHeader(&zip.FileHeader{Name: "a", Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		payload := bytes.Repeat([]byte{'x'}, MaxCompressedBytes-116)
		if _, err := f.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if out.Len() != MaxCompressedBytes {
			t.Fatal("fixture did not hit exact compressed-byte boundary")
		}
		got, err := ReadZIP(out.Bytes())
		if err != nil || !bytes.Equal(got["a"], payload) {
			t.Fatal("exact compressed-byte budget not preserved", err)
		}
	})
	t.Run("total_expansion", func(t *testing.T) {
		data := bytes.Repeat([]byte{'x'}, MaxExpandedBytes/2+1)
		requireCode(t, makeZIP(t, member{name: "a", data: data}, member{name: "b", data: data}), "archive_expanded_limit")
	})
	t.Run("single_expansion", func(t *testing.T) {
		data := bytes.Repeat([]byte{'x'}, MaxExpandedBytes+1)
		requireCode(t, makeZIP(t, member{name: "a", data: data}), "archive_expanded_limit")
	})
	t.Run("exact_total_expansion", func(t *testing.T) {
		data := bytes.Repeat([]byte{'x'}, MaxExpandedBytes)
		got, err := ReadZIP(makeZIP(t, member{name: "a", data: data}))
		if err != nil || !bytes.Equal(got["a"], data) {
			t.Fatal("exact expansion budget not preserved", err)
		}
	})
}

func TestReadZIPBadEOCDAndBoundedActualEntryCount(t *testing.T) {
	data := fixture(t)
	e := len(data) - 22
	binary.LittleEndian.PutUint16(data[e+10:e+12], MaxEntries+1)
	requireCode(t, data, "archive_entry_limit")
	data = fixture(t)
	e = len(data) - 22
	data[e+4] = 1 // multi-disk archives are unsupported and invalid here.
	requireCode(t, data, "archive_invalid")
	data = append(fixture(t), []byte("unexpected trailing data")...)
	requireCode(t, data, "archive_invalid")
}

func TestReadZIPEmptyAndZIP64Metadata(t *testing.T) {
	empty := makeZIP(t)
	got, err := ReadZIP(empty)
	if err != nil || len(got) != 0 || got == nil {
		t.Fatal("valid empty archive rejected", err)
	}
	data := fixture(t)
	e := len(data) - 22
	var records [76]byte
	binary.LittleEndian.PutUint32(records[0:4], 0x06064b50)
	binary.LittleEndian.PutUint64(records[4:12], 44)
	binary.LittleEndian.PutUint16(records[12:14], 45)
	binary.LittleEndian.PutUint16(records[14:16], 45)
	binary.LittleEndian.PutUint64(records[24:32], 1)
	binary.LittleEndian.PutUint64(records[32:40], 1)
	binary.LittleEndian.PutUint64(records[40:48], 55)
	binary.LittleEndian.PutUint64(records[48:56], 60)
	binary.LittleEndian.PutUint32(records[56:60], 0x07064b50)
	binary.LittleEndian.PutUint64(records[64:72], uint64(e))
	binary.LittleEndian.PutUint32(records[72:76], 1)
	end := append([]byte(nil), data[e:]...)
	binary.LittleEndian.PutUint16(end[8:10], 0xffff)
	binary.LittleEndian.PutUint16(end[10:12], 0xffff)
	binary.LittleEndian.PutUint32(end[12:16], 0xffffffff)
	binary.LittleEndian.PutUint32(end[16:20], 0xffffffff)
	data = append(append(append([]byte(nil), data[:e]...), records[:]...), end...)
	got, err = ReadZIP(data)
	if err != nil || string(got["data.json"]) != " {\"synthetic\":true}\r\n" {
		t.Fatal("bounded single-disk ZIP64 metadata rejected", err)
	}
	// Python zipfile force_zip64 writes ZIP64 local size fields even for a
	// small stored member, while keeping its central directory ordinary.
	local64, err := hex.DecodeString("504b03042d00000000000000215c3a7b4182ffffffffffffffff09001400646174612e6a736f6e0100100015000000000000001500000000000000207b2273796e746865746963223a747275657d0d0a504b01022d032d00000000000000215c3a7b41821500000015000000090000000000000000000000808100000000646174612e6a736f6e504b0506000000000100010037000000500000000000")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ReadZIP(local64)
	if err != nil || string(got["data.json"]) != " {\"synthetic\":true}\r\n" {
		t.Fatal("bounded ZIP64 local header rejected", err)
	}
}

func FuzzReadZIP(f *testing.F) {
	seed, err := hex.DecodeString(storedFixture)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := ReadZIP(data)
		if err != nil {
			var safe *Error
			if got != nil || !errors.As(err, &safe) || safe.Error() != safe.Code {
				t.Fatal("failure leaked partial output or unsafe error")
			}
			return
		}
		if len(got) > MaxEntries {
			t.Fatal("entry budget exceeded")
		}
		total := 0
		for name, content := range got {
			if strings.HasSuffix(name, "/") {
				t.Fatal("directory returned as a file")
			}
			total += len(content)
		}
		if total > MaxExpandedBytes {
			t.Fatal("actual expansion budget exceeded")
		}
	})
}

func TestErrorRedactsUnknownCodes(t *testing.T) {
	for _, err := range []*Error{nil, {}, {Code: "private-name: private-value"}} {
		if err.Error() != "archive_invalid" {
			t.Fatal("untrusted error code escaped allowlist")
		}
	}
	for _, code := range []string{"archive_input_limit", "archive_entry_limit", "archive_expanded_limit", "archive_path", "archive_conflict", "archive_special", "archive_encrypted", "archive_compression", "archive_nested"} {
		if (&Error{Code: code}).Error() != code || strings.ContainsAny(code, "\r\n") {
			t.Fatal("fixed code did not survive allowlist")
		}
	}
}
