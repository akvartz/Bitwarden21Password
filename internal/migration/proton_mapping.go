package migration

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// The primary schema basis is Proton WebClients d70c6131012876da970d08f81fdcbb89723a88f1:
// item-v1.ts, item-v1.static.ts, protonpass.json.reader.ts and transformers.ts.
// Unknown paths begin unsupported; individual known paths are then accounted
// only after the exact value has been copied or its transformation described.
type protonMapping struct{ mappedRecord }

func newProtonMapping(record providerRecord) *protonMapping {
	m := &protonMapping{mappedRecord: mappedRecord{mappings: make(map[string]fieldMapping, len(record.fields))}}
	for _, field := range record.fields {
		m.mappings[field.path] = fieldMapping{disposition: "unsupported", concealed: true}
	}
	return m
}

func (m *protonMapping) mark(path, disposition, target string, concealed bool) {
	if _, present := m.mappings[path]; present {
		m.mappings[path] = fieldMapping{disposition: disposition, target: target, concealed: concealed}
	}
}

func (m *protonMapping) issue(code string) {
	for _, existing := range m.issues {
		if existing == code {
			return
		}
	}
	m.issues = append(m.issues, code)
}

func (m *protonMapping) finish() mappedRecord {
	for _, mapping := range m.mappings {
		if mapping.disposition == "unsupported" {
			m.issue("unsupported_fields")
		}
		if mapping.disposition == "omitted" {
			m.issue("provider_metadata_not_migrated")
		}
	}
	return m.mappedRecord
}

func (m *protonMapping) string(src map[string]any, key string, dst map[string]any, dest, path, target, disposition string, concealed bool) bool {
	value, ok := src[key].(string)
	if !ok {
		return false
	}
	dst[dest] = value
	m.mark(path, disposition, target, concealed)
	return true
}

func protonNumber(value any) (string, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return "", false
	}
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return "", false
	}
	return s, true
}

func mapBitwardenToProton(record providerRecord) (mappedRecord, error) {
	m := newProtonMapping(record)
	var typ string
	switch record.kind {
	case "login":
		typ = "login"
	case "secure_note":
		typ = "note"
	case "card":
		typ = "creditCard"
	case "identity":
		typ = "identity"
	default:
		m.issue("unsupported_item_type")
		return m.finish(), nil
	}
	name, ok := record.value["name"].(string)
	if !ok {
		return mappedRecord{}, &SafeError{Code: "invalid_item"}
	}
	meta := map[string]any{"name": name, "note": "", "itemUuid": ""}
	m.mark("/name", "native", "/data/metadata/name", false)
	m.string(record.value, "notes", meta, "note", "/notes", "/data/metadata/note", "native", true)
	content := map[string]any{}
	d := map[string]any{"type": typ, "metadata": meta, "content": content, "extraFields": []any{}}
	m.value = map[string]any{"data": d, "state": json.Number("1"), "pinned": false, "files": []any{}, "contentFormatVersion": json.Number("1"), "shareCount": json.Number("0"), "createTime": json.Number("0"), "modifyTime": json.Number("0")}
	m.mark("/type", "transformed", "/data/type", false)
	if favorite, ok := record.value["favorite"].(bool); ok {
		m.value["pinned"] = favorite
		// The native JSON reader currently does not reconstruct pinned status.
		// Exact output bytes therefore cannot establish native favorite migration.
		m.issue("proton_favorite_import_not_supported")
	}
	for _, key := range []string{"id"} {
		m.mark("/"+key, "omitted", "", true)
	}
	protonMapBitwardenTimestamp(m, record.value, "creationDate", "createTime")
	protonMapBitwardenTimestamp(m, record.value, "revisionDate", "modifyTime")
	if value, present := record.value["deletedDate"]; present {
		if value == nil {
			m.mark("/deletedDate", "transformed", "/state", false)
		} else {
			m.issue("trash_state_not_migrated")
		}
	}
	if record.kind == "login" {
		content["itemUsername"] = ""
		content["itemEmail"] = ""
		content["password"] = ""
		content["totpUri"] = ""
		content["urls"] = []any{}
		content["passkeys"] = []any{}
		if login, ok := record.value["login"].(map[string]any); ok {
			m.string(login, "username", content, "itemUsername", "/login/username", "/data/content/itemUsername", "native", true)
			m.string(login, "password", content, "password", "/login/password", "/data/content/password", "native", true)
			m.string(login, "totp", content, "totpUri", "/login/totp", "/data/content/totpUri", "native", true)
			if urls, ok := login["uris"].([]any); ok {
				out := make([]any, 0, len(urls))
				if len(urls) == 0 {
					m.mark("/login/uris", "transformed", "/data/content/urls", true)
				}
				for i, value := range urls {
					url, ok := value.(map[string]any)
					if !ok {
						continue
					}
					if value, ok := url["uri"].(string); ok {
						out = append(out, value)
						m.mark("/login/uris/"+strconv.Itoa(i)+"/uri", "native", "/data/content/urls", true)
					}
				}
				content["urls"] = out
			}
		}
	} else if record.kind == "secure_note" {
		if note, ok := record.value["secureNote"].(map[string]any); ok {
			if typ, ok := protonNumber(note["type"]); ok && typ == "0" {
				m.mark("/secureNote/type", "transformed", "/data/type", false)
			}
		}
	} else if record.kind == "card" {
		content["cardType"] = json.Number("0")
		for _, key := range []string{"cardholderName", "number", "verificationNumber", "expirationDate", "pin"} {
			content[key] = ""
		}
		if card, ok := record.value["card"].(map[string]any); ok {
			for _, pair := range [][2]string{{"cardholderName", "cardholderName"}, {"number", "number"}, {"code", "verificationNumber"}} {
				m.string(card, pair[0], content, pair[1], "/card/"+pair[0], "/data/content/"+pair[1], "native", true)
			}
			if brand, ok := card["brand"].(string); ok {
				brands := map[string]string{"Visa": "2", "Mastercard": "3", "Amex": "4", "American Express": "4", "Other": "1", "": "0"}
				if code, ok := brands[brand]; ok {
					content["cardType"] = json.Number(code)
					m.mark("/card/brand", "transformed", "/data/content/cardType", false)
					m.issue("card_brand_transformed")
				}
			}
			month, mok := card["expMonth"].(string)
			year, yok := card["expYear"].(string)
			if mok && yok && protonMonthYear(month, year) {
				if len(month) == 1 {
					month = "0" + month
				}
				content["expirationDate"] = month + year
				m.mark("/card/expMonth", "transformed", "/data/content/expirationDate", true)
				m.mark("/card/expYear", "transformed", "/data/content/expirationDate", true)
				m.issue("card_expiration_transformed")
			} else if mok && yok && month == "" && year == "" {
				m.mark("/card/expMonth", "transformed", "/data/content/expirationDate", true)
				m.mark("/card/expYear", "transformed", "/data/content/expirationDate", true)
			}
		}
	} else if record.kind == "identity" {
		// Native identity content declares these strings and arrays. Empty
		// placeholders describe structural defaults, never invented source data.
		for _, key := range []string{"fullName", "email", "phoneNumber", "firstName", "middleName", "lastName", "birthdate", "gender", "organization", "streetAddress", "zipOrPostalCode", "city", "stateOrProvince", "countryOrRegion", "floor", "county", "socialSecurityNumber", "passportNumber", "licenseNumber", "website", "xHandle", "secondPhoneNumber", "linkedin", "reddit", "facebook", "yahoo", "instagram", "company", "jobTitle", "personalWebsite", "workPhoneNumber", "workEmail"} {
			content[key] = ""
		}
		for _, key := range []string{"extraPersonalDetails", "extraAddressDetails", "extraContactDetails", "extraWorkDetails", "extraSections"} {
			content[key] = []any{}
		}
		if identity, ok := record.value["identity"].(map[string]any); ok {
			for _, pair := range protonIdentityPairs {
				m.string(identity, pair[0], content, pair[1], "/identity/"+pair[0], "/data/content/"+pair[1], "native", true)
			}
			for _, key := range []string{"title", "address3", "username"} {
				if value, ok := identity[key].(string); ok {
					protonAppendExtra(d, "Bitwarden identity "+key, value, "text")
					m.mark("/identity/"+key, "relocated", "/data/extraFields", true)
					m.issue("identity_fields_relocated")
				}
			}
		}
	}
	protonMapBitwardenCustom(m, record.value, d)
	m.issue("proton_import_semantics_unverified")
	return m.finish(), nil
}

// These are declared provider fields with the same meaning. In particular,
// username is not reinterpreted as an X handle, and names are not concatenated.
var protonIdentityPairs = [][2]string{
	{"firstName", "firstName"}, {"middleName", "middleName"}, {"lastName", "lastName"},
	{"address1", "streetAddress"}, {"address2", "floor"}, {"city", "city"}, {"state", "stateOrProvince"},
	{"postalCode", "zipOrPostalCode"}, {"country", "countryOrRegion"}, {"company", "company"},
	{"email", "email"}, {"phone", "phoneNumber"}, {"ssn", "socialSecurityNumber"},
	{"passportNumber", "passportNumber"}, {"licenseNumber", "licenseNumber"},
}

func protonAppendExtra(data map[string]any, name, value, typ string) {
	fields := data["extraFields"].([]any)
	data["extraFields"] = append(fields, map[string]any{"fieldName": name, "type": typ, "data": map[string]any{"content": value}})
}

func protonMapBitwardenCustom(m *protonMapping, item, data map[string]any) {
	fields, ok := item["fields"].([]any)
	if !ok {
		return
	}
	if len(fields) == 0 {
		m.mark("/fields", "transformed", "/data/extraFields", true)
	}
	for i, value := range fields {
		field, ok := value.(map[string]any)
		if !ok {
			continue
		}
		name, nok := field["name"].(string)
		text, vok := field["value"].(string)
		typ, tok := protonNumber(field["type"])
		if !nok || !vok || !tok || (typ != "0" && typ != "1") {
			continue
		}
		kind := "text"
		if typ == "1" {
			kind = "hidden"
		}
		protonAppendExtra(data, name, text, kind)
		path := "/fields/" + strconv.Itoa(i)
		m.mark(path+"/name", "native", "/data/extraFields/fieldName", true)
		m.mark(path+"/value", "native", "/data/extraFields/data/content", true)
		m.mark(path+"/type", "transformed", "/data/extraFields/type", false)
	}
}

func protonMapBitwardenTimestamp(m *protonMapping, item map[string]any, source, dest string) {
	value, ok := item[source].(string)
	if !ok {
		return
	}
	timestamp, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || timestamp.Nanosecond() != 0 {
		return
	}
	m.value[dest] = json.Number(strconv.FormatInt(timestamp.Unix(), 10))
	m.mark("/"+source, "transformed", "/"+dest, false)
	m.issue("timestamp_transformed")
}

func mapProtonToBitwarden(record providerRecord) (mappedRecord, error) {
	m := newProtonMapping(record)
	var typ string
	switch record.kind {
	case "login":
		typ = "1"
	case "secure_note":
		typ = "2"
	case "card":
		typ = "3"
	case "identity":
		typ = "4"
	default:
		m.issue("unsupported_item_type")
		return m.finish(), nil
	}
	d, ok := record.value["data"].(map[string]any)
	if !ok {
		return mappedRecord{}, &SafeError{Code: "invalid_item"}
	}
	meta, ok := d["metadata"].(map[string]any)
	if !ok {
		return mappedRecord{}, &SafeError{Code: "invalid_item"}
	}
	name, ok := meta["name"].(string)
	if !ok {
		return mappedRecord{}, &SafeError{Code: "invalid_item"}
	}
	content, ok := d["content"].(map[string]any)
	if !ok {
		return mappedRecord{}, &SafeError{Code: "invalid_item"}
	}
	m.value = map[string]any{"type": json.Number(typ), "name": name, "fields": []any{}}
	m.mark("/data/type", "transformed", "/type", false)
	m.mark("/data/metadata/name", "native", "/name", false)
	m.string(meta, "note", m.value, "notes", "/data/metadata/note", "/notes", "native", true)
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
	if record.kind == "login" {
		login := map[string]any{"uris": []any{}}
		m.value["login"] = login
		m.string(content, "itemUsername", login, "username", "/data/content/itemUsername", "/login/username", "native", true)
		m.string(content, "password", login, "password", "/data/content/password", "/login/password", "native", true)
		m.string(content, "totpUri", login, "totp", "/data/content/totpUri", "/login/totp", "native", true)
		if email, ok := content["itemEmail"].(string); ok {
			protonAppendBitwardenField(m.value, "Proton Pass email", email, "0")
			m.mark("/data/content/itemEmail", "relocated", "/fields/value", true)
			m.issue("distinct_email_relocated")
		}
		protonMapURLs(m, content, login)
	} else if record.kind == "secure_note" {
		m.value["secureNote"] = map[string]any{"type": json.Number("0")}
		if len(content) == 0 {
			m.mark("/data/content", "transformed", "/secureNote/type", false)
		}
	} else if record.kind == "card" {
		card := map[string]any{}
		m.value["card"] = card
		for _, pair := range [][2]string{{"cardholderName", "cardholderName"}, {"number", "number"}, {"verificationNumber", "code"}} {
			m.string(content, pair[0], card, pair[1], "/data/content/"+pair[0], "/card/"+pair[1], "native", true)
		}
		if value, ok := protonNumber(content["cardType"]); ok {
			brands := map[string]string{"0": "", "1": "Other", "2": "Visa", "3": "Mastercard", "4": "Amex"}
			if brand, ok := brands[value]; ok {
				card["brand"] = brand
				m.mark("/data/content/cardType", "transformed", "/card/brand", false)
				m.issue("card_brand_transformed")
			}
		}
		if expiration, ok := content["expirationDate"].(string); ok {
			if len(expiration) == 6 && protonMonthYear(expiration[:2], expiration[2:]) {
				card["expMonth"] = expiration[:2]
				card["expYear"] = expiration[2:]
				m.mark("/data/content/expirationDate", "transformed", "/card/expMonth_and_expYear", true)
				m.issue("card_expiration_transformed")
			} else if expiration == "" {
				card["expMonth"] = ""
				card["expYear"] = ""
				m.mark("/data/content/expirationDate", "transformed", "/card/expMonth_and_expYear", true)
			}
		}
		if pin, ok := content["pin"].(string); ok {
			protonAppendBitwardenField(m.value, "Proton Pass card PIN", pin, "1")
			m.mark("/data/content/pin", "relocated", "/fields/value", true)
			m.issue("card_pin_relocated")
		}
	} else if record.kind == "identity" {
		identity := map[string]any{}
		m.value["identity"] = identity
		for _, pair := range protonIdentityPairs {
			m.string(content, pair[1], identity, pair[0], "/data/content/"+pair[1], "/identity/"+pair[0], "native", true)
		}
		for _, key := range []string{"fullName", "birthdate", "gender", "organization", "county", "website", "xHandle", "secondPhoneNumber", "linkedin", "reddit", "facebook", "yahoo", "instagram", "jobTitle", "personalWebsite", "workPhoneNumber", "workEmail"} {
			if value, ok := content[key].(string); ok {
				protonAppendBitwardenField(m.value, "Proton Pass identity "+key, value, "0")
				m.mark("/data/content/"+key, "relocated", "/fields/value", true)
				m.issue("identity_fields_relocated")
			}
		}
	}
	protonMapCustom(m, d)
	m.issue("bitwarden_import_semantics_unverified")
	return m.finish(), nil
}

func protonAppendBitwardenField(item map[string]any, name, value, typ string) {
	fields := item["fields"].([]any)
	item["fields"] = append(fields, map[string]any{"name": name, "value": value, "type": json.Number(typ)})
}

func protonMapCustom(m *protonMapping, data map[string]any) {
	fields, ok := data["extraFields"].([]any)
	if !ok {
		return
	}
	if len(fields) == 0 {
		m.mark("/data/extraFields", "transformed", "/fields", false)
	}
	for i, value := range fields {
		field, ok := value.(map[string]any)
		if !ok {
			continue
		}
		name, nok := field["fieldName"].(string)
		typ, tok := field["type"].(string)
		data, dok := field["data"].(map[string]any)
		if !nok || !tok || !dok || (typ != "text" && typ != "hidden") {
			continue
		}
		text, vok := data["content"].(string)
		if !vok {
			continue
		}
		kind := "0"
		if typ == "hidden" {
			kind = "1"
		}
		protonAppendBitwardenField(m.value, name, text, kind)
		path := "/data/extraFields/" + strconv.Itoa(i)
		m.mark(path+"/fieldName", "native", "/fields/name", true)
		m.mark(path+"/type", "transformed", "/fields/type", false)
		m.mark(path+"/data/content", "native", "/fields/value", true)
	}
}

func protonMapURLs(m *protonMapping, content, login map[string]any) {
	// Both old and new URL lists are retained as separate entries if present.
	// They can disagree, so collapsing them would discard source multiplicity.
	urls := make([]any, 0)
	if legacy, ok := content["urls"].([]any); ok {
		if len(legacy) == 0 {
			m.mark("/data/content/urls", "transformed", "/login/uris", true)
		}
		for i, value := range legacy {
			if url, ok := value.(string); ok {
				urls = append(urls, map[string]any{"uri": url})
				m.mark("/data/content/urls/"+strconv.Itoa(i), "native", "/login/uris/uri", true)
			}
		}
	}
	if current, ok := content["autofillUrls"].([]any); ok {
		if legacy, ok := content["urls"].([]any); ok && len(legacy) > 0 && len(current) > 0 {
			m.issue("uri_representations_combined")
		}
		if len(current) == 0 {
			m.mark("/data/content/autofillUrls", "transformed", "/login/uris", true)
		}
		for i, value := range current {
			entry, ok := value.(map[string]any)
			if !ok {
				continue
			}
			url, ok := entry["url"].(string)
			if !ok {
				continue
			}
			urls = append(urls, map[string]any{"uri": url})
			path := "/data/content/autofillUrls/" + strconv.Itoa(i)
			m.mark(path+"/url", "native", "/login/uris/uri", true)
			// Provider matching policies have different definitions. No numeric
			// enum cast establishes equivalent behavior in Bitwarden.
			if _, present := entry["mode"]; present {
				m.issue("uri_match_policy_not_migrated")
			}
		}
	}
	login["uris"] = urls
}

func protonMapTimestamp(m *protonMapping, item map[string]any, source, dest string) {
	value, ok := protonNumber(item[source])
	if !ok {
		return
	}
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return
	}
	timestamp := time.Unix(seconds, 0).UTC()
	if timestamp.Year() < 1 || timestamp.Year() > 9999 {
		return
	}
	m.value[dest] = timestamp.Format(time.RFC3339)
	m.mark("/"+source, "transformed", "/"+dest, false)
	m.issue("timestamp_transformed")
}

func protonMonthYear(month, year string) bool {
	if (len(month) != 1 && len(month) != 2) || len(year) != 4 {
		return false
	}
	for _, c := range month + year {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(month)
	return err == nil && n >= 1 && n <= 12
}
