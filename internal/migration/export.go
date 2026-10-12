package migration

import "encoding/json"

const maxOutputBytes = 32 << 20

// outputBuffer checks each escaped string's exact size before json.Marshal can
// allocate it. Incremental fields/items avoid materializing header amplification.
type outputBuffer struct {
	data []byte
	err  error
}

func (b *outputBuffer) literal(value string) {
	if b.err != nil {
		return
	}
	if len(value) > maxOutputBytes-len(b.data) {
		b.err = &SafeError{Code: "output_limit"}
		return
	}
	b.data = append(b.data, value...)
}

func (b *outputBuffer) text(value string) {
	if b.err != nil {
		return
	}
	remaining := maxOutputBytes - len(b.data)
	size := len(value) + 2
	if size > remaining {
		b.err = &SafeError{Code: "output_limit"}
		return
	}
	// Match encoding/json's default string escaping, including HTML and the
	// JavaScript line separators. Source strings have already passed UTF-8 checks.
	for _, r := range value {
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			size++
		case '<', '>', '&':
			size += 5
		case '\u2028', '\u2029':
			size += 3
		default:
			if r < 0x20 {
				size += 5
			}
		}
		if size > remaining {
			b.err = &SafeError{Code: "output_limit"}
			return
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) != size {
		b.err = &SafeError{Code: "output_validation"}
		return
	}
	b.data = append(b.data, encoded...)
}

func exportChrome(d *Document, selected []int) ([]byte, error) {
	if d == nil || !IsBrowserFormat(d.format) {
		return nil, &SafeError{Code: "output_validation"}
	}
	indexes := make(map[string]int, len(d.chromeHeaders))
	for column, header := range d.chromeHeaders {
		indexes[header] = column
	}
	nameIndex := indexes["name"]
	if d.browserNameFromURL {
		nameIndex = indexes["url"]
	}
	var b outputBuffer
	b.literal(`{"encrypted":false,"folders":[],"items":[`)
	for index, record := range selected {
		if record <= 0 || record > len(d.chromeRows) {
			return nil, &SafeError{Code: "output_validation"}
		}
		row := d.chromeRows[record-1]
		if index != 0 {
			b.literal(",")
		}
		b.literal(`{"type":1,"name":`)
		b.text(row[nameIndex])
		if column, present := indexes["note"]; present {
			b.literal(`,"notes":`)
			b.text(row[column])
		}
		b.literal(`,"login":{"username":`)
		b.text(row[indexes["username"]])
		b.literal(`,"password":`)
		b.text(row[indexes["password"]])
		if column, present := indexes["totp"]; present && d.format == SafariCSV {
			b.literal(`,"totp":`)
			b.text(row[column])
		}
		b.literal(`,"uris":[{"uri":`)
		b.text(row[indexes["url"]])
		b.literal(`}]},"fields":[`)
		custom := 0
		for column, header := range d.chromeHeaders {
			if header == "totp" && d.format == SafariCSV {
				continue
			}
			switch header {
			case "name", "url", "username", "password", "note":
				continue
			}
			if custom != 0 {
				b.literal(",")
			}
			b.literal(`{"name":`)
			b.text(d.chromeOriginalHeaders[column])
			b.literal(`,"value":`)
			b.text(row[column])
			b.literal(`,"type":1}`)
			custom++
		}
		b.literal(`]}`)
		if b.err != nil {
			return nil, b.err
		}
	}
	b.literal(`]}`)
	if b.err != nil {
		return nil, b.err
	}
	if err := validateChromeExport(d, selected, b.data); err != nil {
		return nil, err
	}
	return b.data, nil
}

// Validation uses the strict parser's generic tree, then walks source columns
// independently of the encoder's output construction. It checks shape as well as
// exact strings, so a self-roundtrip alone can never authorize an export.
func validateChromeExport(d *Document, selected []int, payload []byte) error {
	invalid := &SafeError{Code: "output_validation"}
	if d == nil || !IsBrowserFormat(d.format) || len(payload) > maxOutputBytes {
		return invalid
	}
	decoded, err := Parse(payload, BitwardenJSON)
	if err != nil {
		return invalid
	}
	root := decoded.bitwardenRoot
	folders, ok := root["folders"].([]any)
	if !ok || len(root) != 3 || root["encrypted"] != false || len(folders) != 0 {
		return invalid
	}
	items, ok := root["items"].([]any)
	if !ok || len(items) != len(selected) {
		return invalid
	}
	notePresent := false
	customCount := 0
	for _, header := range d.chromeHeaders {
		if header == "totp" && d.format == SafariCSV {
			continue
		}
		switch header {
		case "note":
			notePresent = true
		case "name", "url", "username", "password":
		default:
			customCount++
		}
	}
	for index, record := range selected {
		if record <= 0 || record > len(d.chromeRows) {
			return invalid
		}
		item, ok := items[index].(map[string]any)
		if !ok || !isOne(item["type"]) {
			return invalid
		}
		expectedKeys := 4
		if notePresent {
			expectedKeys++
		}
		if len(item) != expectedKeys {
			return invalid
		}
		if _, present := item["notes"]; present != notePresent {
			return invalid
		}
		login, ok := item["login"].(map[string]any)
		expectedLoginKeys := 3
		if d.format == SafariCSV {
			for _, header := range d.chromeHeaders {
				if header == "totp" {
					expectedLoginKeys++
				}
			}
		}
		if !ok || len(login) != expectedLoginKeys {
			return invalid
		}
		uris, ok := login["uris"].([]any)
		if !ok || len(uris) != 1 {
			return invalid
		}
		uri, ok := uris[0].(map[string]any)
		if !ok || len(uri) != 1 {
			return invalid
		}
		fields, ok := item["fields"].([]any)
		if !ok || len(fields) != customCount {
			return invalid
		}
		custom := 0
		if d.browserNameFromURL {
			for column, header := range d.chromeHeaders {
				if header == "url" && item["name"] != d.chromeRows[record-1][column] {
					return invalid
				}
			}
		}
		for column, header := range d.chromeHeaders {
			cell := d.chromeRows[record-1][column]
			var value any
			switch header {
			case "name":
				value = item["name"]
			case "note":
				value = item["notes"]
			case "username", "password":
				value = login[header]
			case "url":
				value = uri["uri"]
			case "totp":
				if d.format == SafariCSV {
					value = login["totp"]
					break
				}
				fallthrough
			default:
				field, ok := fields[custom].(map[string]any)
				if !ok || len(field) != 3 || !isOne(field["type"]) {
					return invalid
				}
				name, ok := field["name"].(string)
				if !ok || name != d.chromeOriginalHeaders[column] {
					return invalid
				}
				value = field["value"]
				custom++
			}
			text, ok := value.(string)
			if !ok || text != cell {
				return invalid
			}
		}
	}
	return nil
}

func isOne(value any) bool {
	number, ok := value.(json.Number)
	return ok && number.String() == "1"
}
