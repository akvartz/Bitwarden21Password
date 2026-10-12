package migration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/akvartz/Bitwarden21Password/internal/safearchive"
)

// Profile reviewed against Proton WebClients d70c6131012876da970d08f81fdcbb89723a88f1,
// whose Pass changelog declares 1.42.0. Generated files remain experimental.
const protonCompatibilityVersion = "1.42.0"

func parseProton(data []byte) (*providerData, error) {
	files, err := safearchive.ReadZIP(data)
	if err != nil {
		var archiveError *safearchive.Error
		if errors.As(err, &archiveError) && archiveError.Code == "archive_input_limit" {
			return nil, &SafeError{Code: "input_limit"}
		}
		return nil, &SafeError{Code: "invalid_archive"}
	}
	payload, plain := files["Proton Pass/data.json"]
	_, encrypted := files["Proton Pass/data.pgp"]
	if plain && encrypted {
		return nil, &SafeError{Code: "invalid_archive"}
	}
	if encrypted {
		return nil, &SafeError{Code: "unsupported_encrypted"}
	}
	if !plain {
		return nil, &SafeError{Code: "invalid_archive"}
	}
	value, err := parseStrictJSON(payload)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, &SafeError{Code: "invalid_json"}
	}
	if flag, present := root["encrypted"]; present {
		encrypted, ok := flag.(bool)
		if !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		if encrypted {
			return nil, &SafeError{Code: "unsupported_encrypted"}
		}
	}
	version, ok := root["version"].(string)
	if !ok || !protonSupportedVersion(version) {
		return nil, &SafeError{Code: "unsupported_version"}
	}
	if user, present := root["userId"]; present {
		if _, ok := user.(string); !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
	}
	vaults, ok := root["vaults"].(map[string]any)
	if !ok {
		return nil, &SafeError{Code: "invalid_json"}
	}
	d := &providerData{root: root, files: files, vaultCount: len(vaults), caveats: []string{
		"proton_export_coverage_limited", "proton_aliases_not_migrated", "proton_vault_relationships_not_migrated", "proton_passkeys_not_migrated", "proton_attachments_not_migrated",
	}}
	for key, child := range root {
		if key != "vaults" {
			d.metadata = append(d.metadata, flattenFields(child, "/"+protonEscapePointer(key))...)
		}
	}
	keys := make([]string, 0, len(vaults))
	for key := range vaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for vaultIndex, key := range keys {
		vault, ok := vaults[key].(map[string]any)
		if !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		if _, ok := vault["name"].(string); !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		items, ok := vault["items"].([]any)
		if !ok {
			return nil, &SafeError{Code: "invalid_json"}
		}
		prefix := "/vaults/" + protonEscapePointer(key)
		if len(items) == 0 {
			d.metadata = append(d.metadata, sourceField{path: prefix + "/items", value: items})
		}
		for field, child := range vault {
			if field != "items" {
				d.metadata = append(d.metadata, flattenFields(child, prefix+"/"+protonEscapePointer(field))...)
			}
		}
		folderOrdinals := make(map[string]int)
		if folders, present := vault["folders"]; present {
			array, ok := folders.([]any)
			if !ok {
				return nil, &SafeError{Code: "invalid_json"}
			}
			for _, entry := range array {
				folder, ok := entry.(map[string]any)
				if !ok {
					return nil, &SafeError{Code: "invalid_json"}
				}
				id, ok := folder["folderId"].(string)
				if !ok || id == "" {
					return nil, &SafeError{Code: "invalid_json"}
				}
				if _, exists := folderOrdinals[id]; exists {
					return nil, &SafeError{Code: "invalid_json"}
				}
				d.folderCount++
				folderOrdinals[id] = d.folderCount
			}
		}
		for _, entry := range items {
			if len(d.records) >= MaxRecords {
				return nil, &SafeError{Code: "record_limit", Record: len(d.records) + 1}
			}
			item, ok := entry.(map[string]any)
			if !ok {
				return nil, &SafeError{Code: "invalid_item", Record: len(d.records) + 1}
			}
			kind, err := protonValidateItem(item)
			if err != nil {
				return nil, &SafeError{Code: "invalid_item", Record: len(d.records) + 1}
			}
			folder := 0
			if id, present := item["folderId"]; present && id != nil {
				s, ok := id.(string)
				if !ok {
					return nil, &SafeError{Code: "invalid_item", Record: len(d.records) + 1}
				}
				folder = folderOrdinals[s]
			}
			d.records = append(d.records, providerRecord{value: item, kind: kind, vault: vaultIndex + 1, folder: folder, fields: flattenFields(item, "")})
		}
	}
	// Empty vault collections are source fields too. Empty item arrays describe
	// zero records, and are retained privately without inventing an empty record.
	if len(vaults) == 0 {
		d.metadata = append(d.metadata, sourceField{path: "/vaults", value: vaults})
	}
	for name, content := range files {
		if name != "Proton Pass/data.json" {
			d.metadata = append(d.metadata, sourceField{path: "/archive/" + protonEscapePointer(name), value: content})
		}
	}
	fieldCount := len(d.metadata)
	for _, record := range d.records {
		fieldCount += len(record.fields)
	}
	if fieldCount > MaxFields {
		return nil, &SafeError{Code: "field_limit"}
	}
	sort.Slice(d.metadata, func(i, j int) bool { return d.metadata[i].path < d.metadata[j].path })
	return d, nil
}

func protonEscapePointer(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

func protonSupportedVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	values := [3]int{}
	for i, part := range parts {
		if part == "" || len(part) > 6 {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return false
		}
		values[i] = n
	}
	return values[0] == 1 && values[1] >= 18
}

func protonValidateItem(item map[string]any) (string, error) {
	invalid := &SafeError{Code: "invalid_item"}
	d, ok := item["data"].(map[string]any)
	if !ok {
		return "", invalid
	}
	meta, ok := d["metadata"].(map[string]any)
	if !ok {
		return "", invalid
	}
	if _, ok := meta["name"].(string); !ok {
		return "", invalid
	}
	for _, key := range []string{"note", "itemUuid"} {
		if value, present := meta[key]; present {
			if _, ok := value.(string); !ok {
				return "", invalid
			}
		}
	}
	kind, ok := d["type"].(string)
	if !ok || kind == "" {
		return "", invalid
	}
	content, ok := d["content"].(map[string]any)
	if !ok {
		return "", invalid
	}
	if extra, present := d["extraFields"]; present {
		fields, ok := extra.([]any)
		if !ok {
			return "", invalid
		}
		for _, value := range fields {
			field, ok := value.(map[string]any)
			if !ok {
				return "", invalid
			}
			if _, ok := field["fieldName"].(string); !ok {
				return "", invalid
			}
			if _, ok := field["type"].(string); !ok {
				return "", invalid
			}
			fieldData, ok := field["data"].(map[string]any)
			if !ok {
				return "", invalid
			}
			if field["type"] == "text" || field["type"] == "hidden" {
				if _, ok := fieldData["content"].(string); !ok {
					return "", invalid
				}
			}
			if field["type"] == "totp" {
				if _, ok := fieldData["totpUri"].(string); !ok {
					return "", invalid
				}
			}
		}
	}
	stringsByKind := map[string][]string{
		"login":      {"itemUsername", "itemEmail", "password", "totpUri"},
		"creditCard": {"cardholderName", "number", "verificationNumber", "expirationDate", "pin"},
		"sshKey":     {"privateKey", "publicKey"},
		"identity":   {"fullName", "email", "phoneNumber", "firstName", "middleName", "lastName", "birthdate", "gender", "organization", "streetAddress", "zipOrPostalCode", "city", "stateOrProvince", "countryOrRegion", "floor", "county", "socialSecurityNumber", "passportNumber", "licenseNumber", "website", "xHandle", "secondPhoneNumber", "linkedin", "reddit", "facebook", "yahoo", "instagram", "company", "jobTitle", "personalWebsite", "workPhoneNumber", "workEmail"},
	}
	for _, key := range stringsByKind[kind] {
		if value, present := content[key]; present {
			if _, ok := value.(string); !ok {
				return "", invalid
			}
		}
	}
	if kind == "login" {
		if value, present := content["urls"]; present {
			urls, ok := value.([]any)
			if !ok {
				return "", invalid
			}
			for _, url := range urls {
				if _, ok := url.(string); !ok {
					return "", invalid
				}
			}
		}
		if value, present := content["autofillUrls"]; present {
			urls, ok := value.([]any)
			if !ok {
				return "", invalid
			}
			for _, value := range urls {
				url, ok := value.(map[string]any)
				if !ok {
					return "", invalid
				}
				if _, ok := url["url"].(string); !ok {
					return "", invalid
				}
				if _, ok := protonNumber(url["mode"]); !ok {
					return "", invalid
				}
			}
		}
	}
	if kind == "creditCard" {
		if value, present := content["cardType"]; present {
			if _, ok := protonNumber(value); !ok {
				return "", invalid
			}
		}
	}
	if kind == "sshKey" && !protonSSHSectionsValid(content["sections"], false) {
		return "", invalid
	}
	for _, key := range []string{"state", "contentFormatVersion", "createTime", "modifyTime", "shareCount"} {
		if value, present := item[key]; present {
			if _, ok := protonNumber(value); !ok {
				return "", invalid
			}
		}
	}
	if value, present := item["pinned"]; present {
		if _, ok := value.(bool); !ok {
			return "", invalid
		}
	}
	switch kind {
	case "login":
		return "login", nil
	case "note":
		return "secure_note", nil
	case "creditCard":
		return "card", nil
	case "identity":
		return "identity", nil
	case "sshKey":
		return "ssh_key", nil
	default:
		return "unknown", nil
	}
}

func exportProton(items []map[string]any) ([]byte, error) {
	if len(items) > MaxRecords {
		return nil, &SafeError{Code: "output_limit"}
	}
	values := make([]any, len(items))
	for i, item := range items {
		kind, err := protonValidateItem(item)
		if err != nil || (kind == "ssh_key" && !protonSSHOutputValid(item)) {
			return nil, &SafeError{Code: "output_validation"}
		}
		copy := make(map[string]any, len(item)+2)
		for key, value := range item {
			copy[key] = value
		}
		copy["itemId"] = "pwmigrate-item-" + strconv.Itoa(i+1)
		copy["shareId"] = "pwmigrate-vault-1"
		values[i] = copy
	}
	root := map[string]any{"version": protonCompatibilityVersion, "vaults": map[string]any{"pwmigrate-vault-1": map[string]any{"name": "Imported", "description": "", "display": map[string]any{"color": json.Number("0"), "icon": json.Number("0")}, "items": values}}}
	payload, err := marshalBounded(root)
	if err != nil {
		return nil, err
	}
	if len(payload) > maxOutputBytes {
		return nil, &SafeError{Code: "output_limit"}
	}
	if _, err := parseStrictJSON(payload); err != nil {
		return nil, &SafeError{Code: "output_limit"}
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	header := &zip.FileHeader{Name: "Proton Pass/data.json", Method: zip.Store}
	header.SetMode(0600)
	header.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	f, err := w.CreateHeader(header)
	if err != nil {
		return nil, &SafeError{Code: "output_validation"}
	}
	if _, err = f.Write(payload); err != nil {
		return nil, &SafeError{Code: "output_validation"}
	}
	if err = w.Close(); err != nil {
		return nil, &SafeError{Code: "output_validation"}
	}
	if b.Len() > maxOutputBytes {
		return nil, &SafeError{Code: "output_limit"}
	}
	return b.Bytes(), nil
}
