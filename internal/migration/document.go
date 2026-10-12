// Package migration inventories exports and protects reviewed output without exposing vault data in reports.
package migration

import (
	"bytes"
	"unicode/utf8"
)

type Format string

const (
	ChromeCSV         Format = "chrome-csv"
	BitwardenJSON     Format = "bitwarden-json"
	MaxInputBytes            = 32 << 20
	MaxRecords               = 50000
	MaxJSONDepth             = 64
	MaxJSONContainers        = 250000
	MaxFields                = 1000000
	MaxCSVColumns            = 1024
)

// Document owns source bytes and parsed values. Only redacted reports leave this type.
type Document struct {
	source                []byte
	format                Format
	chromeHeaders         []string
	chromeOriginalHeaders []string
	chromeRows            [][]string
	bitwardenRoot         map[string]any
	inventory             Inventory
}

// Parse copies the source and rejects the whole input if it violates a limit or schema.
// An empty source format enables detection; format strings are never echoed in errors.
func Parse(data []byte, source Format) (*Document, error) {
	if len(data) > MaxInputBytes {
		return nil, &SafeError{Code: "input_limit"}
	}
	if !utf8.Valid(data) {
		return nil, &SafeError{Code: "invalid_utf8"}
	}
	if source != "" && source != ChromeCSV && source != BitwardenJSON {
		return nil, &SafeError{Code: "unknown_format"}
	}
	snapshot := bytes.Clone(data)
	detected := source == ""
	if detected {
		trimmed := bytes.TrimSpace(snapshot)
		if len(trimmed) == 0 {
			return nil, &SafeError{Code: "unknown_format"}
		}
		if (trimmed[0] == '{' || trimmed[0] == '[') && !hasChromeSchema(snapshot) {
			source = BitwardenJSON
		} else {
			source = ChromeCSV
		}
	}
	d := &Document{source: snapshot, format: source}
	var err error
	switch source {
	case ChromeCSV:
		err = d.parseChrome()
		if detected && err != nil {
			if safe, ok := err.(*SafeError); ok && safe.Code == "missing_header" {
				err = &SafeError{Code: "unknown_format"}
			}
		}
	case BitwardenJSON:
		err = d.parseBitwarden(detected)
	}
	if err != nil {
		return nil, err
	}
	return d, nil
}
