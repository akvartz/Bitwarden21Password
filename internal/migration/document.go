// Package migration inventories exports and protects reviewed output without exposing vault data in reports.
package migration

import (
	"bytes"
	"unicode/utf8"

	"github.com/akvartz/Bitwarden21Password/internal/safearchive"
)

type Format string

const (
	ChromeCSV         Format = "chrome-csv"
	FirefoxCSV        Format = "firefox-csv"
	SafariCSV         Format = "safari-csv"
	BitwardenJSON     Format = "bitwarden-json"
	OnePassword1PUX   Format = "onepassword-1pux"
	ProtonPassZIP     Format = "proton-pass-zip"
	MaxInputBytes            = 32 << 20
	MaxRecords               = 50000
	MaxJSONDepth             = 64
	MaxJSONContainers        = 250000
	MaxFields                = 1000000
	MaxCSVColumns            = 1024
	MaxFieldPathBytes        = 32 << 20
)

// Document owns source bytes and parsed values. Only redacted reports leave this type.
type Document struct {
	source                []byte
	original              []byte
	format                Format
	chromeHeaders         []string
	chromeOriginalHeaders []string
	chromeRows            [][]string
	browserNameFromURL    bool
	bitwardenRoot         map[string]any
	provider              *providerData
	inventory             Inventory
}

// Parse copies the source and rejects the whole input if it violates a limit or schema.
// An empty source format enables detection; format strings are never echoed in errors.
func Parse(data []byte, source Format) (*Document, error) {
	if len(data) > MaxInputBytes {
		return nil, &SafeError{Code: "input_limit"}
	}
	if source != "" && !KnownFormat(source) {
		return nil, &SafeError{Code: "unknown_format"}
	}
	snapshot := bytes.Clone(data)
	detected := source == ""
	if detected {
		if browser := detectBrowserCSV(snapshot); browser != "" {
			source = browser
		}
	}
	if detected && bytes.HasPrefix(snapshot, []byte{'P', 'K', 3, 4}) {
		files, err := safearchive.ReadZIP(snapshot)
		if err != nil {
			return nil, &SafeError{Code: "invalid_archive"}
		}
		_, op := files["export.attributes"]
		_, pp := files["Proton Pass/data.json"]
		_, pe := files["Proton Pass/data.pgp"]
		if op && (pp || pe) {
			return nil, &SafeError{Code: "unknown_format"}
		}
		switch {
		case op:
			source = OnePassword1PUX
		case pp || pe:
			source = ProtonPassZIP
		default:
			return nil, &SafeError{Code: "unknown_format"}
		}
	}
	if source != OnePassword1PUX && source != ProtonPassZIP && !utf8.Valid(snapshot) {
		return nil, &SafeError{Code: "invalid_utf8"}
	}
	if source == "" {
		// A complete Chrome schema with no unique detection result contains
		// conflicting browser schemas or malformed headers. Require an explicit
		// source rather than assigning semantics from an arbitrary extra column.
		if hasChromeSchema(snapshot) {
			return nil, &SafeError{Code: "unknown_format"}
		}
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
	d := &Document{source: snapshot, original: snapshot, format: source}
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
	case FirefoxCSV, SafariCSV:
		err = d.parseBrowserCSV()
	case OnePassword1PUX:
		d.provider, err = parseOnePassword(snapshot)
	case ProtonPassZIP:
		d.provider, err = parseProton(snapshot)
	}
	if err != nil {
		return nil, err
	}
	if source == OnePassword1PUX || source == ProtonPassZIP {
		if !validProviderFields(d.provider) {
			return nil, &SafeError{Code: "field_path_limit"}
		}
		d.inventory = newInventory(source)
		d.inventory.Records = len(d.provider.records)
		d.inventory.MetadataFields = len(d.provider.metadata)
		d.inventory.Caveats = append(d.inventory.Caveats, d.provider.caveats...)
		for _, record := range d.provider.records {
			d.inventory.Fields += len(record.fields)
			d.inventory.Kinds[record.kind]++
		}
	}
	if d.provider != nil {
		if err := d.inventoryProviderDuplicates(); err != nil {
			return nil, err
		}
	}
	return d, nil
}
