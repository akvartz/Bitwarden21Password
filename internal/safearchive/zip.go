// Package safearchive reads bounded archives without extracting paths.
package safearchive

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"io"
	"io/fs"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxCompressedBytes = 32 << 20
	MaxExpandedBytes   = 32 << 20
	MaxEntries         = 10000
	MaxPathDepth       = 8
)

// Error exposes an allowlisted code and never an archive name or parser error.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e != nil {
		switch e.Code {
		case "archive_invalid", "archive_input_limit", "archive_entry_limit", "archive_expanded_limit",
			"archive_path", "archive_conflict", "archive_special", "archive_encrypted",
			"archive_compression", "archive_nested":
			return e.Code
		}
	}
	return "archive_invalid"
}

// ReadZIP returns owned file contents after validating the entire archive.
func ReadZIP(data []byte) (map[string][]byte, error) {
	if len(data) > MaxCompressedBytes {
		return nil, failure("archive_input_limit")
	}
	entries, directoryStart, err := preflight(data)
	if err != nil {
		return nil, err
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && err != zip.ErrInsecurePath {
		return nil, failure("archive_invalid")
	}
	if zr == nil || len(zr.File) != len(entries) {
		return nil, failure("archive_invalid")
	}
	names := make(map[string]nameState)
	spans := make([]span, 0, len(entries))
	payloads := make([][]byte, len(entries))
	for i, f := range zr.File {
		if err := validateName(f.Name, names); err != nil {
			return nil, err
		}
		if !regularOrDirectory(f) {
			return nil, failure("archive_special")
		}
		if f.Mode().IsDir() != strings.HasSuffix(f.Name, "/") {
			return nil, failure("archive_special")
		}
		if f.Flags&(1|1<<6|1<<13) != 0 {
			return nil, failure("archive_encrypted")
		}
		if f.Method != zip.Store && f.Method != zip.Deflate {
			return nil, failure("archive_compression")
		}
		if f.UncompressedSize64 > MaxExpandedBytes {
			return nil, failure("archive_expanded_limit")
		}
		s, ok := validateLocal(data, f, entries[i], directoryStart)
		if !ok {
			return nil, failure("archive_invalid")
		}
		spans = append(spans, s)
		payloads[i] = data[s.body:s.payloadEnd]
	}
	// Disallow overlapping members and unindexed local payloads. The supported
	// format is an ordinary single-disk ZIP, without a self-extracting preamble,
	// padding, or extra records between members and the central directory.
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	end := 0
	for _, s := range spans {
		if s.start != end {
			return nil, failure("archive_invalid")
		}
		end = s.end
	}
	if end != directoryStart {
		return nil, failure("archive_invalid")
	}
	files := make(map[string][]byte, len(entries))
	total := 0
	for i, f := range zr.File {
		if f.Mode().IsDir() {
			continue
		}
		// bytes.Reader implements io.ByteReader. DEFLATE therefore cannot
		// hide unconsumed payload bytes in an internal read-ahead buffer.
		compressed := bytes.NewReader(payloads[i])
		var r io.ReadCloser = io.NopCloser(compressed)
		if f.Method == zip.Deflate {
			r = flate.NewReader(compressed)
		}
		b, readErr := io.ReadAll(io.LimitReader(r, int64(MaxExpandedBytes-total)+1))
		closeErr := r.Close()
		if len(b) > MaxExpandedBytes-total {
			return nil, failure("archive_expanded_limit")
		}
		if readErr != nil || closeErr != nil || compressed.Len() != 0 || uint64(len(b)) != f.UncompressedSize64 || crc32.ChecksumIEEE(b) != f.CRC32 {
			return nil, failure("archive_invalid")
		}
		if nestedZIP(b) {
			return nil, failure("archive_nested")
		}
		total += len(b)
		files[f.Name] = b
	}
	return files, nil
}

func failure(code string) error { return &Error{Code: code} }

func regularOrDirectory(f *zip.File) bool {
	if f.Mode()&fs.ModeType & ^fs.ModeDir != 0 {
		return false
	}
	switch f.CreatorVersion >> 8 {
	case 3, 19: // Unix and macOS: reject unknown type tags, too.
		switch (f.ExternalAttrs >> 16) & 0xf000 {
		case 0, 0x8000, 0x4000:
		default:
			return false
		}
	case 0, 10, 14: // FAT, NTFS, VFAT: volume labels and device records.
		if f.ExternalAttrs&(0x08|0x40) != 0 {
			return false
		}
	}
	return true
}

type nameState struct {
	original string
	dir      bool
	explicit bool
}

func validateName(name string, names map[string]nameState) error {
	if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "\\\x00:") || strings.HasPrefix(name, "/") {
		return failure("archive_path")
	}
	dir := strings.HasSuffix(name, "/")
	clean := strings.TrimSuffix(name, "/")
	parts := strings.Split(clean, "/")
	if len(parts) > MaxPathDepth {
		return failure("archive_path")
	}
	for i, p := range parts {
		if p == "" || p == "." || p == ".." {
			return failure("archive_path")
		}
		path := strings.Join(parts[:i+1], "/")
		key := foldName(path)
		isDir := i < len(parts)-1 || dir
		explicit := i == len(parts)-1
		if old, exists := names[key]; exists {
			if old.original != path || old.dir != isDir || old.explicit && explicit {
				return failure("archive_conflict")
			}
			explicit = explicit || old.explicit
		}
		names[key] = nameState{original: path, dir: isDir, explicit: explicit}
	}
	return nil
}

// Canonicalize each Unicode SimpleFold cycle, including final sigma and Kelvin
// sign. strings.ToLower alone does not detect all EqualFold name conflicts.
func foldName(s string) string {
	return strings.Map(func(r rune) rune {
		lowest := r
		for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
			if next < lowest {
				lowest = next
			}
		}
		return lowest
	}, s)
}

func nestedZIP(b []byte) bool {
	if len(b) < 4 || b[0] != 'P' || b[1] != 'K' {
		return false
	}
	switch binary.LittleEndian.Uint16(b[2:4]) {
	case 0x0403, 0x0605, 0x0606, 0x0807:
		return true
	}
	return false
}

type centralEntry struct {
	offset     uint64
	zip64Sizes bool
}

// Preflight counts actual central-directory records before archive/zip can
// allocate one File per record. EOCD's declared count alone is insufficient:
// archive/zip checks counts modulo 65536 for historical compatibility.
func preflight(data []byte) ([]centralEntry, int, error) {
	invalid := func() ([]centralEntry, int, error) { return nil, 0, failure("archive_invalid") }
	if len(data) < 22 {
		return invalid()
	}
	e := -1
	minimum := max(0, len(data)-22-65535)
	for i := len(data) - 22; i >= minimum; i-- {
		if u32(data[i:i+4]) == 0x06054b50 && i+22+int(u16(data[i+20:i+22])) == len(data) {
			e = i
			break
		}
	}
	if e < 0 || u16(data[e+4:e+6]) != 0 || u16(data[e+6:e+8]) != 0 {
		return invalid()
	}
	count := uint64(u16(data[e+10 : e+12]))
	diskCount := uint64(u16(data[e+8 : e+10]))
	size := uint64(u32(data[e+12 : e+16]))
	offset := uint64(u32(data[e+16 : e+20]))
	end := e
	if count == 0xffff || diskCount == 0xffff || size == 0xffffffff || offset == 0xffffffff {
		if e < 20 || u32(data[e-20:e-16]) != 0x07064b50 || u32(data[e-16:e-12]) != 0 || u32(data[e-4:e]) != 1 {
			return invalid()
		}
		z := u64(data[e-12 : e-4])
		if z > uint64(e-20) || uint64(e-20)-z < 56 {
			return invalid()
		}
		p := int(z)
		if u32(data[p:p+4]) != 0x06064b50 || u64(data[p+4:p+12]) != uint64(e-20-p-12) || u32(data[p+16:p+20]) != 0 || u32(data[p+20:p+24]) != 0 {
			return invalid()
		}
		diskCount = u64(data[p+24 : p+32])
		count = u64(data[p+32 : p+40])
		size = u64(data[p+40 : p+48])
		offset = u64(data[p+48 : p+56])
		end = p
	}
	if count > MaxEntries || diskCount > MaxEntries {
		return nil, 0, failure("archive_entry_limit")
	}
	if count != diskCount || offset > uint64(end) || size != uint64(end)-offset {
		return invalid()
	}
	start := int(offset)
	entries := make([]centralEntry, 0, int(count))
	for p := start; p < end; {
		if len(entries) >= MaxEntries {
			return nil, 0, failure("archive_entry_limit")
		}
		if end-p < 46 || u32(data[p:p+4]) != 0x02014b50 || u16(data[p+34:p+36]) != 0 {
			return invalid()
		}
		names := int(u16(data[p+28 : p+30]))
		extras := int(u16(data[p+30 : p+32]))
		comments := int(u16(data[p+32 : p+34]))
		next := p + 46 + names + extras + comments
		if next > end {
			return invalid()
		}
		local := uint64(u32(data[p+42 : p+46]))
		uncompressed64 := u32(data[p+24:p+28]) == 0xffffffff
		compressed64 := u32(data[p+20:p+24]) == 0xffffffff
		if local == 0xffffffff {
			skip := 0
			if uncompressed64 {
				skip += 8
			}
			if compressed64 {
				skip += 8
			}
			x, ok := zip64Extra(data[p+46+names : p+46+names+extras])
			if !ok || len(x) < skip+8 {
				return invalid()
			}
			local = u64(x[skip : skip+8])
		}
		if local >= uint64(start) {
			return invalid()
		}
		entries = append(entries, centralEntry{offset: local, zip64Sizes: uncompressed64 || compressed64})
		p = next
	}
	if uint64(len(entries)) != count {
		return invalid()
	}
	return entries, start, nil
}

func zip64Extra(extra []byte) ([]byte, bool) {
	for len(extra) > 0 {
		if len(extra) < 4 {
			return nil, false
		}
		n := int(u16(extra[2:4]))
		if n > len(extra)-4 {
			return nil, false
		}
		if u16(extra[:2]) == 1 {
			return extra[4 : 4+n], true
		}
		extra = extra[4+n:]
	}
	return nil, false
}

type span struct{ start, end, body, payloadEnd int }

func validateLocal(data []byte, f *zip.File, entry centralEntry, directoryStart int) (span, bool) {
	bad := func() (span, bool) { return span{}, false }
	if entry.offset > uint64(directoryStart) || uint64(directoryStart)-entry.offset < 30 {
		return bad()
	}
	p := int(entry.offset)
	if u32(data[p:p+4]) != 0x04034b50 || u16(data[p+6:p+8]) != f.Flags || u16(data[p+8:p+10]) != f.Method {
		return bad()
	}
	n := int(u16(data[p+26 : p+28]))
	x := int(u16(data[p+28 : p+30]))
	body := p + 30 + n + x
	if body > directoryStart || string(data[p+30:p+30+n]) != f.Name || f.CompressedSize64 > uint64(directoryStart-body) {
		return bad()
	}
	if f.Mode().IsDir() && (f.CompressedSize64 != 0 || f.UncompressedSize64 != 0 || f.CRC32 != 0) {
		return bad()
	}
	crc := u32(data[p+14 : p+18])
	compressed := uint64(u32(data[p+18 : p+22]))
	expanded := uint64(u32(data[p+22 : p+26]))
	if compressed == 0xffffffff || expanded == 0xffffffff {
		v, ok := zip64Extra(data[p+30+n : body])
		if !ok {
			return bad()
		}
		if expanded == 0xffffffff {
			if len(v) < 8 {
				return bad()
			}
			expanded, v = u64(v[:8]), v[8:]
		}
		if compressed == 0xffffffff {
			if len(v) < 8 {
				return bad()
			}
			compressed = u64(v[:8])
		}
	}
	payloadEnd := body + int(f.CompressedSize64)
	end := payloadEnd
	if f.Flags&8 == 0 {
		if crc != f.CRC32 || compressed != f.CompressedSize64 || expanded != f.UncompressedSize64 {
			return bad()
		}
	} else {
		if crc != 0 && crc != f.CRC32 || compressed != 0 && compressed != f.CompressedSize64 || expanded != 0 && expanded != f.UncompressedSize64 {
			return bad()
		}
		if directoryStart-end < 4 {
			return bad()
		}
		if u32(data[end:end+4]) == 0x08074b50 {
			end += 4
		}
		length := 12
		if entry.zip64Sizes {
			length = 20
		}
		if directoryStart-end < length || u32(data[end:end+4]) != f.CRC32 {
			return bad()
		}
		var c, u uint64
		if entry.zip64Sizes {
			c, u = u64(data[end+4:end+12]), u64(data[end+12:end+20])
		} else {
			c, u = uint64(u32(data[end+4:end+8])), uint64(u32(data[end+8:end+12]))
		}
		if c != f.CompressedSize64 || u != f.UncompressedSize64 {
			return bad()
		}
		end += length
	}
	return span{start: p, end: end, body: body, payloadEnd: payloadEnd}, true
}

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }
func u64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }
