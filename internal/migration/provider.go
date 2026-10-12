package migration

import (
	"bytes"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

func parseStrictJSON(data []byte) (any, error) {
	if len(data) > MaxInputBytes {
		return nil, &SafeError{Code: "input_limit"}
	}
	if !utf8.Valid(data) {
		return nil, &SafeError{Code: "invalid_utf8"}
	}
	if !validJSONSurrogates(data) {
		return nil, &SafeError{Code: "invalid_json"}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	parser := strictJSON{decoder: decoder}
	value, err := parser.readValue(0, false)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, &SafeError{Code: "invalid_json"}
	}
	if !fieldPathBudget(value, 0) {
		return nil, &SafeError{Code: "field_path_limit"}
	}
	return value, nil
}

func flattenFields(value any, prefix string) []sourceField {
	if !fieldPathBudget(value, len(prefix)) {
		return []sourceField{{path: "", value: &SafeError{Code: "field_path_limit"}}}
	}
	fields := make([]sourceField, 0)
	var visit func(any, string)
	visit = func(value any, path string) {
		switch v := value.(type) {
		case map[string]any:
			if len(v) == 0 {
				fields = append(fields, sourceField{path, value})
				return
			}
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				visit(v[key], path+"/"+strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1"))
			}
		case []any:
			if len(v) == 0 {
				fields = append(fields, sourceField{path, value})
				return
			}
			for i, child := range v {
				visit(child, path+"/"+strconv.Itoa(i))
			}
		default:
			fields = append(fields, sourceField{path, value})
		}
	}
	visit(value, prefix)
	return fields
}

// Count path bytes before allocating any expanded paths. Long ancestor keys
// occur only once in input but would otherwise repeat in every descendant leaf.
func fieldPathBudget(value any, prefix int) bool {
	remaining := MaxFieldPathBytes
	var visit func(any, int) bool
	visit = func(value any, length int) bool {
		if length > remaining {
			return false
		}
		remaining -= length
		switch v := value.(type) {
		case map[string]any:
			if len(v) > 0 {
				for key, child := range v {
					encoded := len(key) + strings.Count(key, "~") + strings.Count(key, "/")
					if !visit(child, length+1+encoded) {
						return false
					}
				}
				return true
			}
		case []any:
			if len(v) > 0 {
				for i, child := range v {
					if !visit(child, length+1+len(strconv.Itoa(i))) {
						return false
					}
				}
				return true
			}
		}
		return true
	}
	return visit(value, prefix)
}

func validProviderFields(p *providerData) bool {
	if p == nil {
		return false
	}
	count := len(p.metadata)
	for _, field := range p.metadata {
		if _, bad := field.value.(*SafeError); bad {
			return false
		}
	}
	for _, record := range p.records {
		count += len(record.fields)
		for _, field := range record.fields {
			if _, bad := field.value.(*SafeError); bad {
				return false
			}
		}
	}
	return count <= MaxFields
}

// providerData owns complete parsed provider payloads. Source paths are private;
// public reports use only deterministic field and record ordinals.
type providerData struct {
	root        map[string]any
	records     []providerRecord
	vaultCount  int
	folderCount int
	metadata    []sourceField
	files       map[string][]byte
	caveats     []string
}

type providerRecord struct {
	value  map[string]any
	kind   string
	vault  int
	folder int
	fields []sourceField
}

type sourceField struct {
	path  string
	value any
}

type fieldMapping struct {
	disposition string
	target      string // fixed schema path; never arbitrary source/custom names
	concealed   bool
}

// A mapped item contains destination values and the private source-path map.
// Every source leaf, including empty containers, needs exactly one disposition.
type mappedRecord struct {
	value    map[string]any
	mappings map[string]fieldMapping
	issues   []string // fixed codes only, turned into exact issue IDs by the engine
}

func bitwardenProvider(root map[string]any) *providerData {
	p := &providerData{root: root, files: map[string][]byte{}, vaultCount: 1}
	metadata := make(map[string]any, len(root))
	for key, value := range root {
		if key != "items" {
			metadata[key] = value
		}
	}
	p.metadata = flattenFields(metadata, "")
	folders := map[string]int{}
	if values, ok := root["folders"].([]any); ok {
		p.folderCount = len(values)
		for i, value := range values {
			if folder, ok := value.(map[string]any); ok {
				if id, ok := folder["id"].(string); ok && id != "" {
					if _, exists := folders[id]; !exists {
						folders[id] = i + 1
					} else {
						folders[id] = 0
					}
				}
			}
		}
	}
	items, _ := root["items"].([]any)
	for _, value := range items {
		item := value.(map[string]any)
		kind := "unknown"
		if number, ok := item["type"].(json.Number); ok {
			switch number.String() {
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
		}
		folderID, _ := item["folderId"].(string)
		p.records = append(p.records, providerRecord{value: item, kind: kind, vault: 1, folder: folders[folderID], fields: flattenFields(item, "")})
	}
	return p
}
