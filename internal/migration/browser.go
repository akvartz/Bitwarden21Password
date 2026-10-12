package migration

import (
	"bytes"
	"strconv"
)

// The native schemas come from Mozilla's exporter and Apple's Safari export
// documentation. They have no CSV version column. Do not infer a browser from
// a filename or from the three credential columns shared by multiple products.
func browserRequiredHeaders(format Format) []string {
	switch format {
	case FirefoxCSV:
		return []string{"url", "username", "password", "httprealm", "formactionorigin", "guid", "timecreated", "timelastused", "timepasswordchanged"}
	case SafariCSV:
		return []string{"title", "url", "username", "password", "notes", "otpauth"}
	case ChromeCSV:
		return []string{"name", "url", "username", "password"}
	default:
		return nil
	}
}

// These aliases affect schema slots only. The original source labels and all
// cells stay intact. Chrome/Firefox extras named title/notes/otpauth acquire no
// Safari semantics.
func browserHeader(format Format, raw string) string {
	header := normalizeHeader(raw)
	if format == SafariCSV {
		switch header {
		case "title":
			return "name"
		case "notes":
			return "note"
		case "otpauth":
			return "totp"
		}
	}
	return header
}

func (d *Document) parseBrowserCSV() error {
	if d == nil || (d.format != FirefoxCSV && d.format != SafariCSV) {
		return &SafeError{Code: "unknown_format"}
	}
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
	rawSeen := make(map[string]bool, len(headers))
	for column, raw := range headers {
		header := browserHeader(d.format, raw)
		if header == "" {
			return &SafeError{Code: "empty_header", Column: column + 1}
		}
		if seen[header] {
			return &SafeError{Code: "duplicate_header", Column: column + 1}
		}
		seen[header] = true
		rawSeen[normalizeHeader(raw)] = true
		if d.format == FirefoxCSV {
			switch header {
			case "url", "username", "password":
			default:
				// Firefox has no native title/notes/TOTP columns. An unknown
				// column with one of those labels stays a concealed custom
				// field; its exact original label supplies the output name.
				header = "browser-extra-" + strconv.Itoa(column+1)
			}
		}
		d.chromeHeaders[column] = header
	}
	for _, required := range browserRequiredHeaders(d.format) {
		if !rawSeen[required] {
			return &SafeError{Code: "missing_header"}
		}
	}
	d.browserNameFromURL = d.format == FirefoxCSV
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
	d.inventory = newInventory(d.format)
	d.inventory.Records = len(d.chromeRows)
	d.inventory.Fields = fields
	d.inventory.Kinds["login"] = len(d.chromeRows)
	if d.format == FirefoxCSV {
		d.inventory.DuplicateDetection = "exact_url_username"
		d.inventory.DuplicateGroups = d.firefoxDuplicateGroups()
		d.inventory.Caveats = append(d.inventory.Caveats, "firefox_csv_limited_export", "firefox_csv_title_from_url")
	} else {
		d.inventory.DuplicateDetection = "exact_name_url_username"
		d.inventory.DuplicateGroups = d.chromeDuplicateGroups()
		d.inventory.Caveats = append(d.inventory.Caveats, "safari_csv_limited_export")
	}
	return nil
}

// Detection requires exactly one complete native schema, including original
// Safari aliases. A mixed or malformed header must not select an adapter by
// whichever arbitrary custom column happens to appear first.
func detectBrowserCSV(data []byte) Format {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if len(data) == 0 {
		return ""
	}
	headers, _, err := readCSVRecord(data, 0, 0)
	if err != nil {
		return ""
	}
	seen := make(map[string]bool, len(headers))
	for _, raw := range headers {
		header := normalizeHeader(raw)
		if header == "" || seen[header] {
			return ""
		}
		seen[header] = true
	}
	var found Format
	for _, format := range []Format{ChromeCSV, FirefoxCSV, SafariCSV} {
		complete := true
		for _, required := range browserRequiredHeaders(format) {
			if !seen[required] {
				complete = false
				break
			}
		}
		if complete {
			if found != "" {
				return ""
			}
			found = format
		}
	}
	if found == SafariCSV {
		aliases := make(map[string]bool, len(headers))
		for _, raw := range headers {
			header := browserHeader(SafariCSV, raw)
			if aliases[header] {
				return ""
			}
			aliases[header] = true
		}
	}
	return found
}

func (d *Document) firefoxDuplicateGroups() [][]int {
	indexes := make(map[string]int, len(d.chromeHeaders))
	for column, header := range d.chromeHeaders {
		indexes[header] = column
	}
	// Exact source tuples remain private; passwords are not duplicate keys.
	type key struct{ url, username string }
	positions := make(map[key]int)
	groups := make([][]int, 0)
	for rowIndex, row := range d.chromeRows {
		k := key{row[indexes["url"]], row[indexes["username"]]}
		group, exists := positions[k]
		if !exists {
			group = len(groups)
			positions[k] = group
			groups = append(groups, nil)
		}
		groups[group] = append(groups[group], rowIndex+1)
	}
	duplicates := make([][]int, 0)
	for _, group := range groups {
		if len(group) > 1 {
			duplicates = append(duplicates, group)
		}
	}
	return duplicates
}
