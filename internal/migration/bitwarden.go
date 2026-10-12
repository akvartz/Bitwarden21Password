package migration

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

func (d *Document) parseBitwarden(detected bool) error {
	// encoding/json replaces unpaired UTF-16 escapes. Reject them before decoding
	// so no credential can silently acquire a replacement character.
	if !validJSONSurrogates(d.source) {
		return &SafeError{Code: "invalid_json"}
	}
	decoder := json.NewDecoder(bytes.NewReader(d.source))
	decoder.UseNumber()
	parser := strictJSON{decoder: decoder}
	value, err := parser.readValue(0, false)
	if err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return &SafeError{Code: "invalid_json"}
	}
	if !fieldPathBudget(value, 0) {
		return &SafeError{Code: "field_path_limit"}
	}
	envelopeCode := "invalid_json"
	if detected {
		envelopeCode = "unknown_format"
	}
	root, ok := value.(map[string]any)
	if !ok {
		return &SafeError{Code: envelopeCode}
	}
	encrypted, ok := root["encrypted"].(bool)
	if !ok {
		return &SafeError{Code: envelopeCode}
	}
	if encrypted {
		return &SafeError{Code: "unsupported_encrypted"}
	}
	items, ok := root["items"].([]any)
	if !ok {
		return &SafeError{Code: envelopeCode}
	}
	d.inventory = newInventory(BitwardenJSON)
	d.inventory.Records = len(items)
	d.inventory.DuplicateDetection = "not_evaluated"
	d.inventory.Caveats = append(d.inventory.Caveats,
		"bitwarden_export_coverage_limited", "bitwarden_duplicate_detection_not_evaluated")
	for key, value := range root {
		if key != "items" {
			d.inventory.MetadataFields += countJSONFields(value)
		}
	}
	for i, value := range items {
		item, ok := value.(map[string]any)
		if !ok {
			return &SafeError{Code: "invalid_item", Record: i + 1}
		}
		itemType, ok := item["type"].(json.Number)
		if !ok || strings.ContainsAny(itemType.String(), ".eE") {
			return &SafeError{Code: "invalid_item", Record: i + 1}
		}
		if _, ok := item["name"].(string); !ok {
			return &SafeError{Code: "invalid_item", Record: i + 1}
		}
		if loginValue, present := item["login"]; present && loginValue != nil {
			login, ok := loginValue.(map[string]any)
			if !ok {
				return &SafeError{Code: "invalid_item", Record: i + 1}
			}
			for _, field := range []string{"username", "password", "totp"} {
				if credential, present := login[field]; present && credential != nil {
					if _, ok := credential.(string); !ok {
						return &SafeError{Code: "invalid_item", Record: i + 1}
					}
				}
			}
		}
		kind := "unknown"
		switch itemType.String() {
		case "1":
			kind = "login"
		case "2":
			kind = "secure_note"
		case "3":
			kind = "card"
		case "4":
			kind = "identity"
		case "5":
			kind = "ssh_key"
		}
		d.inventory.Kinds[kind]++
		d.inventory.Fields += countJSONFields(item)
	}
	d.bitwardenRoot = root
	d.provider = bitwardenProvider(root)
	return nil
}

// strictJSON accounts for leaves while decoding and checks each object key before
// insertion. Numbers retain their original tokens instead of passing through float64.
type strictJSON struct {
	decoder    *json.Decoder
	fields     int
	containers int
}

func (p *strictJSON) addField() error {
	p.fields++
	if p.fields > MaxFields {
		return &SafeError{Code: "field_limit"}
	}
	return nil
}

func (p *strictJSON) readValue(parentDepth int, rootItems bool) (any, error) {
	token, err := p.decoder.Token()
	if err != nil {
		return nil, &SafeError{Code: "invalid_json"}
	}
	delimiter, container := token.(json.Delim)
	if !container {
		if err := p.addField(); err != nil {
			return nil, err
		}
		return token, nil
	}
	if delimiter != '{' && delimiter != '[' {
		return nil, &SafeError{Code: "invalid_json"}
	}
	depth := parentDepth + 1
	if depth > MaxJSONDepth {
		return nil, &SafeError{Code: "depth_limit"}
	}
	// Nonempty chains can allocate many containers while contributing just one
	// leaf. Bound every object/array, including root and empty items, before make.
	p.containers++
	if p.containers > MaxJSONContainers {
		return nil, &SafeError{Code: "container_limit"}
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for p.decoder.More() {
			token, err := p.decoder.Token()
			if err != nil {
				return nil, &SafeError{Code: "invalid_json"}
			}
			key, ok := token.(string)
			if !ok {
				return nil, &SafeError{Code: "invalid_json"}
			}
			if _, present := object[key]; present {
				return nil, &SafeError{Code: "duplicate_json_key"}
			}
			value, err := p.readValue(depth, depth == 1 && key == "items")
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if token, err := p.decoder.Token(); err != nil || token != json.Delim('}') {
			return nil, &SafeError{Code: "invalid_json"}
		}
		if len(object) == 0 {
			if err := p.addField(); err != nil {
				return nil, err
			}
		}
		return object, nil
	case '[':
		array := make([]any, 0)
		for p.decoder.More() {
			if rootItems && len(array) >= MaxRecords {
				return nil, &SafeError{Code: "record_limit", Record: len(array) + 1}
			}
			value, err := p.readValue(depth, false)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if token, err := p.decoder.Token(); err != nil || token != json.Delim(']') {
			return nil, &SafeError{Code: "invalid_json"}
		}
		// The empty root items array represents zero records, not a metadata field.
		if len(array) == 0 && !rootItems {
			if err := p.addField(); err != nil {
				return nil, err
			}
		}
		return array, nil
	default:
		return nil, &SafeError{Code: "invalid_json"}
	}
}

func countJSONFields(value any) int {
	switch value := value.(type) {
	case map[string]any:
		if len(value) == 0 {
			return 1
		}
		total := 0
		for _, child := range value {
			total += countJSONFields(child)
		}
		return total
	case []any:
		if len(value) == 0 {
			return 1
		}
		total := 0
		for _, child := range value {
			total += countJSONFields(child)
		}
		return total
	default:
		return 1
	}
}

func validJSONSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		code, ok := hexCodeUnit(data, i+1)
		if !ok {
			return false
		}
		i += 4
		switch {
		case code >= 0xd800 && code <= 0xdbff:
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, ok := hexCodeUnit(data, i+3)
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		case code >= 0xdc00 && code <= 0xdfff:
			return false
		}
	}
	return true
}

func hexCodeUnit(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var result uint16
	for _, b := range data[start : start+4] {
		var digit byte
		switch {
		case b >= '0' && b <= '9':
			digit = b - '0'
		case b >= 'a' && b <= 'f':
			digit = b - 'a' + 10
		case b >= 'A' && b <= 'F':
			digit = b - 'A' + 10
		default:
			return 0, false
		}
		result = result*16 + uint16(digit)
	}
	return result, true
}
