package migration

import (
	"encoding/json"
	"encoding/pem"
	"strconv"

	"golang.org/x/crypto/ssh"
)

// Primary profile: Proton WebClients d70c6131012876da970d08f81fdcbb89723a88f1,
// ItemSSHKey, importSshKeyItem, and extractBitwardenSSHSections. The native
// Bitwarden importer preserves raw private/public strings; its fingerprint
// becomes a hidden custom section. All key interpretation below delegates to
// the existing bounded x/crypto/ssh and crypto/x509 profile, never provider
// labels or user custom-field names.
func protonSSHCheckPair(private, public string, fingerprint *string) (any, string, string) {
	key, _, code := onePasswordSSHParse(private)
	if code != "" {
		return nil, "", code
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, "", "unsupported_ssh_key"
	}
	derived := ssh.FingerprintSHA256(signer.PublicKey())
	expected := derived
	if fingerprint != nil {
		expected = *fingerprint
	}
	if code := onePasswordSSHCheckPublic(signer.PublicKey(), public, expected); code != "" {
		return nil, "", code
	}
	return key, derived, ""
}

func protonMapBitwardenSSH(record providerRecord) (mappedRecord, error) {
	m := newProtonMapping(record)
	fail := func(code string) (mappedRecord, error) { m.issue(code); return m.finish(), nil }
	source, ok := record.value["sshKey"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_key")
	}
	private, privateOK := source["privateKey"].(string)
	public, publicOK := source["publicKey"].(string)
	fingerprint, fingerprintOK := source["keyFingerprint"].(string)
	if !privateOK || !publicOK || !fingerprintOK {
		return fail("unsupported_ssh_metadata")
	}
	if _, _, code := protonSSHCheckPair(private, public, &fingerprint); code != "" {
		return fail(code)
	}
	name, ok := record.value["name"].(string)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	content := map[string]any{"privateKey": private, "publicKey": public, "sections": []any{map[string]any{
		"sectionName": "Extra fields", "sectionFields": []any{map[string]any{"fieldName": "Key fingerprint", "type": "hidden", "data": map[string]any{"content": fingerprint}}},
	}}}
	metadata := map[string]any{"name": name, "note": "", "itemUuid": ""}
	data := map[string]any{"type": "sshKey", "metadata": metadata, "content": content, "extraFields": []any{}}
	m.value = map[string]any{"data": data, "state": json.Number("1"), "pinned": false, "files": []any{}, "contentFormatVersion": json.Number("1"), "shareCount": json.Number("0"), "createTime": json.Number("0"), "modifyTime": json.Number("0")}
	m.mark("/type", "transformed", "/data/type", false)
	m.mark("/name", "native", "/data/metadata/name", false)
	m.mark("/sshKey/privateKey", "native", "/data/content/privateKey", true)
	m.mark("/sshKey/publicKey", "native", "/data/content/publicKey", true)
	m.mark("/sshKey/keyFingerprint", "relocated", "/data/content/sections/sectionFields/data/content", true)
	m.string(record.value, "notes", metadata, "note", "/notes", "/data/metadata/note", "native", true)
	if favorite, ok := record.value["favorite"].(bool); ok {
		m.value["pinned"] = favorite
		m.issue("proton_favorite_import_not_supported")
	}
	m.mark("/id", "omitted", "", true)
	protonMapBitwardenTimestamp(m, record.value, "creationDate", "createTime")
	protonMapBitwardenTimestamp(m, record.value, "revisionDate", "modifyTime")
	if deleted, present := record.value["deletedDate"]; present {
		if deleted == nil {
			m.mark("/deletedDate", "transformed", "/state", false)
		} else {
			m.issue("trash_state_not_migrated")
		}
	}
	protonMapBitwardenCustom(m, record.value, data)
	m.issue("proton_import_semantics_unverified")
	return m.finish(), nil
}

func protonMapSSHToBitwarden(record providerRecord) (mappedRecord, error) {
	m := newProtonMapping(record)
	fail := func(code string) (mappedRecord, error) { m.issue(code); return m.finish(), nil }
	data, ok := record.value["data"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	metadata, ok := data["metadata"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	content, ok := data["content"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_key")
	}
	private, privateOK := content["privateKey"].(string)
	public, publicOK := content["publicKey"].(string)
	if !privateOK || !publicOK {
		return fail("unsupported_ssh_metadata")
	}
	key, fingerprint, code := protonSSHCheckPair(private, public, nil)
	if code != "" {
		return fail(code)
	}
	if !protonSSHSectionsValid(content["sections"], false) {
		return fail("unsupported_ssh_representation")
	}
	name, ok := metadata["name"].(string)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	block, code := onePasswordSSHPEM(private)
	if code != "" {
		return fail(code)
	}
	outputPrivate := private
	disposition := "native"
	if block.Type != "OPENSSH PRIVATE KEY" {
		openSSH, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			return fail("unsupported_ssh_key")
		}
		outputPrivate = string(pem.EncodeToMemory(openSSH))
		disposition = "transformed"
	}
	m.value = map[string]any{"type": json.Number("5"), "name": name, "sshKey": map[string]any{"privateKey": outputPrivate, "publicKey": public, "keyFingerprint": fingerprint}, "fields": []any{}}
	m.mark("/data/type", "transformed", "/type", false)
	m.mark("/data/metadata/name", "native", "/name", false)
	m.mark("/data/content/privateKey", disposition, "/sshKey/privateKey", true)
	m.mark("/data/content/publicKey", "native", "/sshKey/publicKey", true)
	m.string(metadata, "note", m.value, "notes", "/data/metadata/note", "/notes", "native", true)
	if favorite, ok := record.value["pinned"].(bool); ok {
		m.value["favorite"] = favorite
		m.mark("/pinned", "native", "/favorite", false)
	}
	for _, path := range []string{"/itemId", "/shareId", "/data/metadata/itemUuid", "/contentFormatVersion", "/shareCount"} {
		m.mark(path, "omitted", "", true)
	}
	if alias, present := record.value["aliasEmail"]; present && alias == nil {
		m.mark("/aliasEmail", "omitted", "", true)
	}
	if files, ok := record.value["files"].([]any); ok && len(files) == 0 {
		m.mark("/files", "omitted", "", false)
	}
	if state, ok := protonNumber(record.value["state"]); ok {
		if state == "1" {
			m.value["deletedDate"] = nil
			m.mark("/state", "transformed", "/deletedDate", false)
		} else {
			m.issue("trash_state_not_migrated")
		}
	}
	protonMapTimestamp(m, record.value, "createTime", "creationDate")
	protonMapTimestamp(m, record.value, "modifyTime", "revisionDate")
	protonSSHMapSections(m, content)
	protonMapCustom(m, data)
	m.issue("bitwarden_import_semantics_unverified")
	return m.finish(), nil
}

// A missing section array is an older structural omission, not a reason to
// invent custom fields. Unfamiliar field types retain their owned raw payload
// on input; generated output is limited to known typed structures.
func protonSSHSectionsValid(value any, output bool) bool {
	if value == nil {
		return !output
	}
	sections, ok := value.([]any)
	if !ok {
		return false
	}
	for _, entry := range sections {
		section, ok := entry.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := section["sectionName"].(string); !ok {
			return false
		}
		fields, ok := section["sectionFields"].([]any)
		if !ok {
			return false
		}
		for _, entry := range fields {
			field, ok := entry.(map[string]any)
			if !ok {
				return false
			}
			if _, ok := field["fieldName"].(string); !ok {
				return false
			}
			typ, ok := field["type"].(string)
			if !ok || typ == "" {
				return false
			}
			data, ok := field["data"].(map[string]any)
			if !ok {
				return false
			}
			switch typ {
			case "text", "hidden":
				if _, ok := data["content"].(string); !ok {
					return false
				}
			case "totp":
				if _, ok := data["totpUri"].(string); !ok {
					return false
				}
			case "timestamp": // This profile does not project timestamps.
			default:
				if output {
					return false
				}
			}
		}
	}
	return true
}

func protonSSHMapSections(m *protonMapping, content map[string]any) {
	sections, ok := content["sections"].([]any)
	if !ok {
		return
	}
	if len(sections) == 0 {
		m.mark("/data/content/sections", "transformed", "/fields", true)
	}
	for i, entry := range sections {
		section := entry.(map[string]any)
		fields := section["sectionFields"].([]any)
		prefix := "/data/content/sections/" + strconv.Itoa(i) + "/sectionFields"
		if len(fields) == 0 {
			m.mark(prefix, "transformed", "/fields", true)
		}
		for j, entry := range fields {
			field := entry.(map[string]any)
			typ := field["type"].(string)
			if typ != "text" && typ != "hidden" {
				continue
			}
			name := field["fieldName"].(string)
			data := field["data"].(map[string]any)
			value := data["content"].(string)
			kind := "0"
			if typ == "hidden" {
				kind = "1"
			}
			protonAppendBitwardenField(m.value, name, value, kind)
			path := prefix + "/" + strconv.Itoa(j)
			m.mark(path+"/fieldName", "relocated", "/fields/name", true)
			m.mark(path+"/type", "transformed", "/fields/type", false)
			m.mark(path+"/data/content", "relocated", "/fields/value", true)
		}
	}
}

func protonSSHOutputValid(item map[string]any) bool {
	data, ok := item["data"].(map[string]any)
	if !ok {
		return false
	}
	content, ok := data["content"].(map[string]any)
	if !ok {
		return false
	}
	private, privateOK := content["privateKey"].(string)
	public, publicOK := content["publicKey"].(string)
	if !privateOK || !publicOK {
		return false
	}
	if _, _, code := protonSSHCheckPair(private, public, nil); code != "" {
		return false
	}
	return protonSSHSectionsValid(content["sections"], true)
}
