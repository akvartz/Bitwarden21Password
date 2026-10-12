package migration

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"sort"
	"strings"

	"github.com/akvartz/Bitwarden21Password/internal/safearchive"
)

// parseOnePassword reads the documented v3 ZIP without extracting anything.
// Complete items, metadata and file bodies remain in the private snapshot.
func parseOnePassword(data []byte) (*providerData, error) {
	files, err := safearchive.ReadZIP(data)
	if err != nil {
		if len(data) > MaxInputBytes {
			return nil, &SafeError{Code: "input_limit"}
		}
		return nil, &SafeError{Code: "invalid_archive"}
	}
	attrsBytes, attrsPresent := files["export.attributes"]
	dataBytes, dataPresent := files["export.data"]
	if !attrsPresent || !dataPresent {
		return nil, &SafeError{Code: "invalid_archive"}
	}
	// Apply a shared budget before either JSON member allocates its tree.
	if onePasswordJSONContainers(attrsBytes)+onePasswordJSONContainers(dataBytes) > MaxJSONContainers {
		return nil, &SafeError{Code: "container_limit"}
	}
	attrsValue, err := parseStrictJSON(attrsBytes)
	if err != nil {
		return nil, err
	}
	attrs, ok := attrsValue.(map[string]any)
	if !ok {
		return nil, &SafeError{Code: "invalid_json"}
	}
	version, ok := attrs["version"].(json.Number)
	if !ok || version.String() != "3" {
		return nil, &SafeError{Code: "unsupported_version"}
	}
	if attrs["description"] != "1Password Unencrypted Export" {
		return nil, &SafeError{Code: "invalid_json"}
	}
	value, err := parseStrictJSON(dataBytes)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, &SafeError{Code: "invalid_json"}
	}
	accounts, ok := root["accounts"].([]any)
	if !ok {
		return nil, &SafeError{Code: "invalid_json"}
	}
	p := &providerData{root: root, files: files, caveats: []string{"onepassword_export_omits_passkeys", "onepassword_destination_import_not_verified"}}
	p.metadata = flattenFields(attrs, "/export.attributes")
	metadataRoot := make(map[string]any, len(root))
	for key, value := range root {
		if key != "accounts" {
			metadataRoot[key] = value
		}
	}
	metadataAccounts := make([]any, 0, len(accounts))
	for _, accountValue := range accounts {
		account, ok := accountValue.(map[string]any)
		if !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		if _, ok := account["attrs"].(map[string]any); !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		vaults, ok := account["vaults"].([]any)
		if !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		metadataAccount := make(map[string]any, len(account))
		for key, value := range account {
			if key != "vaults" {
				metadataAccount[key] = value
			}
		}
		metadataVaults := make([]any, 0, len(vaults))
		for _, vaultValue := range vaults {
			vault, ok := vaultValue.(map[string]any)
			if !ok {
				return nil, &SafeError{Code: "invalid_json"}
			}
			if _, ok := vault["attrs"].(map[string]any); !ok {
				return nil, &SafeError{Code: "invalid_json"}
			}
			items, ok := vault["items"].([]any)
			if !ok {
				return nil, &SafeError{Code: "invalid_json"}
			}
			p.vaultCount++
			metadataVault := make(map[string]any, len(vault))
			for key, value := range vault {
				if key != "items" {
					metadataVault[key] = value
				}
			}
			if len(items) == 0 {
				metadataVault["items"] = items
			}
			metadataVaults = append(metadataVaults, metadataVault)
			for _, itemValue := range items {
				if len(p.records) >= MaxRecords {
					return nil, &SafeError{Code: "record_limit", Record: len(p.records) + 1}
				}
				item, ok := itemValue.(map[string]any)
				if !ok || !onePasswordValidItem(item) {
					return nil, &SafeError{Code: "invalid_item", Record: len(p.records) + 1}
				}
				p.records = append(p.records, providerRecord{value: item, kind: onePasswordKind(item["categoryUuid"].(string)), vault: p.vaultCount, fields: flattenFields(item, "")})
			}
		}
		metadataAccount["vaults"] = metadataVaults
		metadataAccounts = append(metadataAccounts, metadataAccount)
	}
	metadataRoot["accounts"] = metadataAccounts
	p.metadata = append(p.metadata, flattenFields(metadataRoot, "/export.data")...)
	fileNames := make([]string, 0, len(files))
	for name := range files {
		if name != "export.attributes" && name != "export.data" {
			fileNames = append(fileNames, name)
		}
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		p.metadata = append(p.metadata, sourceField{path: "/files/" + strings.ReplaceAll(strings.ReplaceAll(name, "~", "~0"), "/", "~1"), value: files[name]})
	}
	fieldCount := len(p.metadata)
	for _, record := range p.records {
		fieldCount += len(record.fields)
		if fieldCount > MaxFields {
			return nil, &SafeError{Code: "field_limit"}
		}
	}
	if fieldCount > MaxFields {
		return nil, &SafeError{Code: "field_limit"}
	}
	if len(files) > 2 {
		p.caveats = append(p.caveats, "onepassword_files_retained_not_migrated")
	}
	return p, nil
}

func onePasswordValidItem(item map[string]any) bool {
	if _, ok := item["categoryUuid"].(string); !ok {
		return false
	}
	overview, ok := item["overview"].(map[string]any)
	if !ok {
		return false
	}
	if _, ok := overview["title"].(string); !ok {
		return false
	}
	details, ok := item["details"].(map[string]any)
	if !ok {
		return false
	}
	if fieldsValue, present := details["loginFields"]; present && fieldsValue != nil {
		fields, ok := fieldsValue.([]any)
		if !ok {
			return false
		}
		for _, fieldValue := range fields {
			field, ok := fieldValue.(map[string]any)
			if !ok {
				return false
			}
			if field["designation"] == "username" || field["designation"] == "password" {
				if value, present := field["value"]; present && value != nil {
					if _, ok := value.(string); !ok {
						return false
					}
				}
			}
		}
	}
	return true
}

func onePasswordKind(category string) string {
	switch category {
	case "001":
		return "login"
	case "002":
		return "card"
	case "003":
		return "secure_note"
	case "004":
		return "identity"
	case "114":
		return "ssh_key"
	default:
		return "unknown"
	}
}

// exportOnePassword emits v3 with one synthetic account/vault. Attachment
// references cannot be published by this item-only writer without their bodies.
func exportOnePassword(items []map[string]any) ([]byte, error) {
	if len(items) > MaxRecords {
		return nil, &SafeError{Code: "record_limit"}
	}
	accountUUID, err := onePasswordUUID()
	if err != nil {
		return nil, err
	}
	vaultUUID, err := onePasswordUUID()
	if err != nil {
		return nil, err
	}
	outputItems := make([]any, 0, len(items))
	for _, item := range items {
		if !onePasswordValidItem(item) {
			return nil, &SafeError{Code: "output_validation"}
		}
		details := item["details"].(map[string]any)
		if notes, present := details["notesPlain"]; present {
			if _, ok := notes.(string); !ok {
				return nil, &SafeError{Code: "output_validation"}
			}
		}
		if raw, present := details["loginFields"]; present {
			fields, ok := raw.([]any)
			if !ok {
				return nil, &SafeError{Code: "output_validation"}
			}
			for _, raw := range fields {
				field, ok := raw.(map[string]any)
				if !ok {
					return nil, &SafeError{Code: "output_validation"}
				}
				if _, ok := field["value"].(string); !ok {
					return nil, &SafeError{Code: "output_validation"}
				}
			}
		}
		if _, present := details["documentAttributes"]; present {
			return nil, &SafeError{Code: "output_validation"}
		}
		if onePasswordContainsFileReference(details) {
			return nil, &SafeError{Code: "output_validation"}
		}
		copyItem := make(map[string]any, len(item)+4)
		for key, value := range item {
			copyItem[key] = value
		}
		// Required schema display fields are generated without changing the
		// supplied item or manufacturing any source credential.
		originalOverview := item["overview"].(map[string]any)
		overview := make(map[string]any, len(originalOverview)+2)
		for key, value := range originalOverview {
			overview[key] = value
		}
		if _, present := overview["subtitle"]; !present {
			overview["subtitle"] = ""
		}
		if _, present := overview["url"]; !present {
			overview["url"] = ""
		}
		copyItem["overview"] = overview
		if _, present := copyItem["uuid"]; !present {
			uuid, err := onePasswordUUID()
			if err != nil {
				return nil, err
			}
			copyItem["uuid"] = uuid
		}
		for _, key := range []string{"createdAt", "updatedAt", "favIndex"} {
			if _, present := copyItem[key]; !present {
				copyItem[key] = json.Number("0")
			}
		}
		if _, present := copyItem["state"]; !present {
			copyItem["state"] = "active"
		}
		outputItems = append(outputItems, copyItem)
	}
	root := map[string]any{"accounts": []any{map[string]any{"attrs": map[string]any{"accountName": "pwmigrate", "name": "pwmigrate", "avatar": "", "email": "", "uuid": accountUUID, "domain": ""}, "vaults": []any{map[string]any{"attrs": map[string]any{"uuid": vaultUUID, "desc": "", "avatar": "", "name": "Imported", "type": "P"}, "items": outputItems}}}}}
	attrs := map[string]any{"version": json.Number("3"), "description": "1Password Unencrypted Export", "createdAt": json.Number("0")}
	encodedAttrs, err := marshalBounded(attrs)
	if err != nil {
		return nil, err
	}
	encodedData, err := marshalBounded(root)
	if err != nil {
		return nil, err
	}
	if len(encodedAttrs)+len(encodedData) > MaxInputBytes {
		return nil, &SafeError{Code: "output_limit"}
	}
	var output bytes.Buffer
	archive := zip.NewWriter(&output)
	for _, entry := range []struct {
		name string
		data []byte
	}{{"export.attributes", encodedAttrs}, {"export.data", encodedData}} {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(0600)
		writer, err := archive.CreateHeader(header)
		if err != nil {
			return nil, &SafeError{Code: "output_validation"}
		}
		if _, err := writer.Write(entry.data); err != nil {
			return nil, &SafeError{Code: "output_validation"}
		}
	}
	if err := archive.Close(); err != nil {
		return nil, &SafeError{Code: "output_validation"}
	}
	if output.Len() > MaxInputBytes {
		return nil, &SafeError{Code: "output_limit"}
	}
	return output.Bytes(), nil
}

func onePasswordUUID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", &SafeError{Code: "output_validation"}
	}
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(bytes[:])), nil
}

func onePasswordContainsFileReference(value any) bool {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "file" || key == "documentAttributes" {
				return true
			}
			if onePasswordContainsFileReference(child) {
				return true
			}
		}
	case []any:
		for _, child := range value {
			if onePasswordContainsFileReference(child) {
				return true
			}
		}
	}
	return false
}

// Counting delimiters outside strings is independent of JSON decoding. Invalid
// syntax is still rejected by the strict decoder; this preflight only bounds
// allocation across the separate v3 JSON members.
func onePasswordJSONContainers(data []byte) int {
	count := 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if b == '\\' {
				escaped = true
				continue
			}
			if b == '"' {
				inString = false
			}
			continue
		}
		if b == '"' {
			inString = true
			continue
		}
		if b == '{' || b == '[' {
			count++
			if count > MaxJSONContainers {
				return count
			}
		}
	}
	return count
}
