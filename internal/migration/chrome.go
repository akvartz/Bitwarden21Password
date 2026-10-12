package migration

import (
	"bytes"
	"strings"
)

func (d *Document) parseChrome() error {
	data := bytes.TrimPrefix(d.source, []byte{0xef, 0xbb, 0xbf})
	if len(data) == 0 {
		return &SafeError{Code: "missing_header"}
	}
	headers, offset, err := readCSVRecord(data, 0, 0)
	if err != nil {
		return err
	}
	d.chromeOriginalHeaders = append([]string{}, headers...)
	d.chromeHeaders = make([]string, len(headers))
	seen := make(map[string]bool, len(headers))
	for i, header := range headers {
		normalized := normalizeHeader(header)
		if normalized == "" {
			return &SafeError{Code: "empty_header", Column: i + 1}
		}
		if seen[normalized] {
			return &SafeError{Code: "duplicate_header", Column: i + 1}
		}
		seen[normalized] = true
		d.chromeHeaders[i] = normalized
	}
	for _, required := range []string{"name", "url", "username", "password"} {
		if !seen[required] {
			return &SafeError{Code: "missing_header"}
		}
	}
	d.chromeRows = make([][]string, 0)
	fields := 0
	for offset < len(data) {
		record := len(d.chromeRows) + 1
		if record > MaxRecords {
			return &SafeError{Code: "record_limit", Record: record}
		}
		row, next, err := readCSVRecord(data, offset, record)
		if err != nil {
			return err
		}
		if len(row) != len(headers) {
			return &SafeError{Code: "uneven_row", Record: record}
		}
		if fields > MaxFields-len(row) {
			return &SafeError{Code: "field_limit", Record: record}
		}
		fields += len(row)
		d.chromeRows = append(d.chromeRows, row)
		offset = next
	}
	d.inventory = newInventory(ChromeCSV)
	d.inventory.Records = len(d.chromeRows)
	d.inventory.Fields = fields
	d.inventory.Kinds["login"] = len(d.chromeRows)
	d.inventory.DuplicateDetection = "exact_name_url_username"
	d.inventory.DuplicateGroups = d.chromeDuplicateGroups()
	d.inventory.Caveats = append(d.inventory.Caveats, "chrome_csv_limited_export")
	return nil
}

// A custom first CSV header may begin with a JSON delimiter. Recognize the
// required CSV schema before using that delimiter as a detection hint.
func hasChromeSchema(data []byte) bool {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if len(data) == 0 {
		return false
	}
	headers, _, err := readCSVRecord(data, 0, 0)
	if err != nil {
		return false
	}
	found := make(map[string]bool, 4)
	for _, raw := range headers {
		header := normalizeHeader(raw)
		switch header {
		case "name", "url", "username", "password":
			found[header] = true
		}
	}
	return len(found) == 4
}

// Header normalization is for schema matching only; source labels and cells remain intact.
func normalizeHeader(header string) string {
	data := []byte(strings.TrimSpace(header))
	for i, b := range data {
		if b >= 'A' && b <= 'Z' {
			data[i] += 'a' - 'A'
		}
	}
	return string(data)
}

// readCSVRecord deliberately avoids encoding/csv, whose CRLF normalization and
// skipped blank lines would change credentials or conceal malformed records.
func readCSVRecord(data []byte, offset, record int) ([]string, int, error) {
	if data[offset] == '\n' || isCRLF(data, offset) {
		return nil, offset, &SafeError{Code: "invalid_csv", Record: record}
	}
	row := make([]string, 0, 4)
	for {
		column := len(row) + 1
		if column > MaxCSVColumns {
			return nil, offset, &SafeError{Code: "column_limit", Record: record, Column: column}
		}
		var cell string
		if offset < len(data) && data[offset] == '"' {
			offset++
			start := offset
			var value strings.Builder
			closed := false
			for offset < len(data) {
				if data[offset] != '"' {
					offset++
					continue
				}
				value.Write(data[start:offset])
				if offset+1 < len(data) && data[offset+1] == '"' {
					value.WriteByte('"')
					offset += 2
					start = offset
					continue
				}
				offset++
				closed = true
				break
			}
			if !closed {
				return nil, offset, &SafeError{Code: "invalid_csv", Record: record, Column: column}
			}
			if offset < len(data) && data[offset] != ',' && data[offset] != '\n' && !isCRLF(data, offset) {
				return nil, offset, &SafeError{Code: "invalid_csv", Record: record, Column: column}
			}
			cell = value.String()
		} else {
			start := offset
			for offset < len(data) && data[offset] != ',' && data[offset] != '\n' && !isCRLF(data, offset) {
				if data[offset] == '"' {
					return nil, offset, &SafeError{Code: "invalid_csv", Record: record, Column: column}
				}
				offset++
			}
			cell = string(data[start:offset])
		}
		row = append(row, cell)
		if offset == len(data) {
			return row, offset, nil
		}
		if data[offset] == ',' {
			offset++
			continue
		}
		if isCRLF(data, offset) {
			return row, offset + 2, nil
		}
		return row, offset + 1, nil
	}
}

func isCRLF(data []byte, offset int) bool {
	return offset+1 < len(data) && data[offset] == '\r' && data[offset+1] == '\n'
}

func (d *Document) chromeDuplicateGroups() [][]int {
	indexes := make(map[string]int, len(d.chromeHeaders))
	for i, header := range d.chromeHeaders {
		indexes[header] = i
	}
	// A tuple avoids ambiguous delimiter concatenation. It never leaves private memory.
	type key struct{ name, url, username string }
	positions := make(map[key]int)
	groups := make([][]int, 0)
	for i, row := range d.chromeRows {
		k := key{row[indexes["name"]], row[indexes["url"]], row[indexes["username"]]}
		group, exists := positions[k]
		if !exists {
			group = len(groups)
			positions[k] = group
			groups = append(groups, nil)
		}
		groups[group] = append(groups[group], i+1)
	}
	duplicates := make([][]int, 0)
	for _, group := range groups {
		if len(group) > 1 {
			duplicates = append(duplicates, group)
		}
	}
	return duplicates
}
