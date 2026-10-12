package migration

import (
	"encoding/json"
	"strconv"
)

func mapBitwardenToOnePassword(record providerRecord) (mappedRecord, error) {
	if record.kind == "ssh_key" {
		return onePasswordMapBitwardenToSSH(record)
	}
	m := onePasswordMappingStart(record)
	category := ""
	switch record.kind {
	case "login":
		category = "001"
	case "secure_note":
		category = "003"
	case "card":
		category = "002"
	case "identity":
		category = "004"
	default:
		onePasswordIssue(&m, "unsupported_item_type")
		if record.kind == "ssh_key" {
			onePasswordIssue(&m, "unsupported_ssh_key")
		}
		return m, nil
	}
	source := record.value
	name, ok := source["name"].(string)
	if !ok {
		return m, &SafeError{Code: "invalid_item"}
	}
	overview := map[string]any{"title": name, "subtitle": "", "url": ""}
	details := map[string]any{}
	m.value = map[string]any{"categoryUuid": category, "overview": overview, "details": details, "state": "active", "favIndex": json.Number("0"), "createdAt": json.Number("0"), "updatedAt": json.Number("0")}
	onePasswordMark(&m, "/type", "transformed", "categoryUuid", false)
	onePasswordMark(&m, "/name", "native", "overview.title", false)
	if notes, present := source["notes"]; present {
		if text, ok := notes.(string); ok {
			details["notesPlain"] = text
			onePasswordMark(&m, "/notes", "native", "details.notesPlain", false)
		}
	}
	if favorite, ok := source["favorite"].(bool); ok {
		index := json.Number("0")
		if favorite {
			index = json.Number("1")
		}
		m.value["favIndex"] = index
		onePasswordMark(&m, "/favorite", "transformed", "favIndex", false)
	}
	if record.kind == "secure_note" {
		if note, ok := source["secureNote"].(map[string]any); ok {
			if number, ok := note["type"].(json.Number); ok && number.String() == "0" {
				onePasswordMark(&m, "/secureNote/type", "transformed", "categoryUuid", false)
			}
		}
	}
	if record.kind == "login" {
		if login, ok := source["login"].(map[string]any); ok {
			loginFields := make([]any, 0, 2)
			for _, key := range []string{"username", "password"} {
				if text, ok := login[key].(string); ok {
					fieldType := "T"
					if key == "password" {
						fieldType = "P"
					}
					loginFields = append(loginFields, map[string]any{"id": key, "name": key, "designation": key, "fieldType": fieldType, "value": text})
					onePasswordMark(&m, "/login/"+key, "native", "details.loginFields.value", key == "password")
				}
			}
			if len(loginFields) > 0 {
				details["loginFields"] = loginFields
			}
			if totp, ok := login["totp"].(string); ok {
				onePasswordAppendField(details, "totp", "One-time password", map[string]any{"totp": totp})
				onePasswordMark(&m, "/login/totp", "native", "details.sections.fields.value.totp", true)
			}
			if uris, ok := login["uris"].([]any); ok {
				urls := make([]any, 0, len(uris))
				for i, raw := range uris {
					if uri, ok := raw.(map[string]any); ok {
						if text, ok := uri["uri"].(string); ok {
							urls = append(urls, map[string]any{"label": "", "url": text})
							onePasswordMark(&m, "/login/uris/"+strconv.Itoa(i)+"/uri", "native", "overview.urls.url", false)
						}
					}
				}
				overview["urls"] = urls
				if len(uris) == 0 {
					onePasswordMark(&m, "/login/uris", "native", "overview.urls", false)
				}
			}
			if value, present := login["fido2Credentials"]; present && onePasswordNonempty(value) {
				onePasswordIssue(&m, "unsupported_passkeys")
			}
		}
	}
	if record.kind == "card" {
		onePasswordMapBitwardenCard(&m, source, details)
	}
	if record.kind == "identity" {
		onePasswordMapBitwardenIdentity(&m, source, details)
	}
	onePasswordMapBitwardenCustom(&m, source, details)
	if value, present := source["attachments"]; present && onePasswordNonempty(value) {
		onePasswordIssue(&m, "unsupported_attachments")
	}
	return m, nil
}

func mapOnePasswordToBitwarden(record providerRecord) (mappedRecord, error) {
	if record.kind == "ssh_key" {
		return onePasswordMapSSHToBitwarden(record)
	}
	m := onePasswordMappingStart(record)
	itemType := json.Number("0")
	switch record.kind {
	case "login":
		itemType = "1"
	case "secure_note":
		itemType = "2"
	case "card":
		itemType = "3"
	case "identity":
		itemType = "4"
	default:
		onePasswordIssue(&m, "unsupported_item_type")
		if record.kind == "ssh_key" {
			onePasswordIssue(&m, "unsupported_ssh_key")
		}
		return m, nil
	}
	source := record.value
	overview, ok := source["overview"].(map[string]any)
	if !ok {
		return m, &SafeError{Code: "invalid_item"}
	}
	name, ok := overview["title"].(string)
	if !ok {
		return m, &SafeError{Code: "invalid_item"}
	}
	details, ok := source["details"].(map[string]any)
	if !ok {
		return m, &SafeError{Code: "invalid_item"}
	}
	m.value = map[string]any{"type": itemType, "name": name}
	onePasswordMark(&m, "/categoryUuid", "transformed", "type", false)
	onePasswordMark(&m, "/overview/title", "native", "name", false)
	if notes, present := details["notesPlain"]; present {
		if _, ok := notes.(string); ok || notes == nil {
			m.value["notes"] = notes
			onePasswordMark(&m, "/details/notesPlain", "native", "notes", false)
		}
	}
	if index, ok := source["favIndex"].(json.Number); ok {
		if integer, err := strconv.ParseInt(index.String(), 10, 64); err == nil && integer >= 0 {
			m.value["favorite"] = integer > 0
			onePasswordMark(&m, "/favIndex", "transformed", "favorite", false)
		}
	}
	if record.kind == "secure_note" {
		m.value["secureNote"] = map[string]any{"type": json.Number("0")}
	}
	if record.kind == "login" {
		onePasswordMapLogin(&m, details, overview)
	}
	fields := onePasswordSectionFields(details)
	if record.kind == "card" {
		m.value["card"] = map[string]any{}
		onePasswordMapCard(&m, fields)
	}
	if record.kind == "identity" {
		m.value["identity"] = map[string]any{}
		onePasswordMapIdentity(&m, fields)
	}
	if record.kind == "login" {
		candidates := []onePasswordField{}
		for _, field := range fields {
			if len(field.value) == 1 {
				if _, present := field.value["totp"]; present {
					candidates = append(candidates, field)
				}
			}
		}
		if len(candidates) == 1 {
			field := candidates[0]
			if text, ok := field.value["totp"].(string); ok {
				m.value["login"].(map[string]any)["totp"] = text
				onePasswordMark(&m, field.path+"/value/totp", "native", "login.totp", true)
				onePasswordMark(&m, field.path+"/id", "transformed", "login.totp", false)
			}
		}
		if len(candidates) > 1 {
			onePasswordIssue(&m, "unsupported_duplicate_credentials")
		}
	}
	for _, field := range fields {
		onePasswordMapCustom(&m, field, record.kind)
	}
	if value, present := details["documentAttributes"]; present && onePasswordNonempty(value) {
		onePasswordIssue(&m, "unsupported_attachments")
	}
	return m, nil
}

func onePasswordMappingStart(record providerRecord) mappedRecord {
	m := mappedRecord{mappings: map[string]fieldMapping{}}
	fields := record.fields
	if fields == nil {
		fields = flattenFields(record.value, "")
	}
	for _, field := range fields {
		m.mappings[field.path] = fieldMapping{disposition: "unsupported"}
	}
	return m
}

func onePasswordMark(m *mappedRecord, path, disposition, target string, concealed bool) {
	if _, present := m.mappings[path]; present {
		m.mappings[path] = fieldMapping{disposition: disposition, target: target, concealed: concealed}
	}
}

func onePasswordIssue(m *mappedRecord, code string) {
	for _, existing := range m.issues {
		if existing == code {
			return
		}
	}
	m.issues = append(m.issues, code)
}

func onePasswordNonempty(value any) bool {
	switch value := value.(type) {
	case nil:
		return false
	case []any:
		return len(value) > 0
	case map[string]any:
		return len(value) > 0
	default:
		return true
	}
}

func onePasswordAppendField(details map[string]any, id, title string, value map[string]any) {
	sections, _ := details["sections"].([]any)
	if len(sections) == 0 {
		sections = []any{map[string]any{"name": "", "title": "", "fields": []any{}}}
		details["sections"] = sections
	}
	section := sections[0].(map[string]any)
	fields, _ := section["fields"].([]any)
	section["fields"] = append(fields, map[string]any{"id": id, "title": title, "value": value})
}

func onePasswordMapBitwardenCustom(m *mappedRecord, source, details map[string]any) {
	fields, ok := source["fields"].([]any)
	if !ok {
		return
	}
	if len(fields) == 0 {
		onePasswordMark(m, "/fields", "transformed", "details.sections.fields", false)
		return
	}
	for i, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, nameOK := field["name"].(string)
		text, valueOK := field["value"].(string)
		kind, kindOK := field["type"].(json.Number)
		if !nameOK || !valueOK || !kindOK {
			continue
		}
		tag := "string"
		concealed := false
		switch kind.String() {
		case "0":
		case "1":
			tag = "concealed"
			concealed = true
		case "2":
			onePasswordIssue(m, "unsupported_custom_boolean_semantics")
		default:
			continue
		}
		onePasswordAppendField(details, "pwmigrate.custom."+strconv.Itoa(i+1), name, map[string]any{tag: text})
		path := "/fields/" + strconv.Itoa(i)
		onePasswordMark(m, path+"/name", "relocated", "details.sections.fields.title", false)
		onePasswordMark(m, path+"/value", "relocated", "details.sections.fields.value", concealed)
		onePasswordMark(m, path+"/type", "transformed", "details.sections.fields.value", concealed)
	}
}

func onePasswordMapBitwardenCard(m *mappedRecord, source, details map[string]any) {
	card, ok := source["card"].(map[string]any)
	if !ok {
		return
	}
	for _, field := range []struct {
		source, id, title, tag string
		concealed              bool
	}{{"cardholderName", "cardholder", "Cardholder", "string", false}, {"number", "ccnum", "Number", "creditCardNumber", true}, {"code", "cvv", "CVV", "concealed", true}} {
		if text, ok := card[field.source].(string); ok {
			onePasswordAppendField(details, field.id, field.title, map[string]any{field.tag: text})
			onePasswordMark(m, "/card/"+field.source, "native", "details.sections.fields.value", field.concealed)
		}
	}
	month, monthOK := card["expMonth"].(string)
	year, yearOK := card["expYear"].(string)
	if monthOK && yearOK && len(year) == 4 && len(month) >= 1 && len(month) <= 2 {
		yearN, yearErr := strconv.Atoi(year)
		monthN, monthErr := strconv.Atoi(month)
		if yearErr == nil && monthErr == nil && yearN >= 1000 && yearN <= 9999 && monthN >= 1 && monthN <= 12 && onePasswordDigits(year) && onePasswordDigits(month) {
			onePasswordAppendField(details, "expiry", "Expiry", map[string]any{"monthYear": json.Number(strconv.Itoa(yearN*100 + monthN))})
			onePasswordMark(m, "/card/expMonth", "transformed", "details.sections.fields.value.monthYear", false)
			onePasswordMark(m, "/card/expYear", "transformed", "details.sections.fields.value.monthYear", false)
		}
	}
	// No complete independently documented creditCardType enum is available.
	// Retain the exact provider brand as text, with relocation clearly reported.
	if brand, ok := card["brand"].(string); ok {
		onePasswordAppendField(details, "pwmigrate.card.brand", "Brand", map[string]any{"string": brand})
		onePasswordMark(m, "/card/brand", "relocated", "details.sections.fields.value.string", false)
	}
}

func onePasswordDigits(text string) bool {
	if text == "" {
		return false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func onePasswordMapBitwardenIdentity(m *mappedRecord, source, details map[string]any) {
	identity, ok := source["identity"].(map[string]any)
	if !ok {
		return
	}
	for _, field := range []struct{ source, id, tag string }{{"firstName", "firstname", "string"}, {"lastName", "lastname", "string"}, {"middleName", "initial", "string"}, {"phone", "defphone", "phone"}, {"company", "company", "string"}, {"username", "username", "string"}} {
		if text, ok := identity[field.source].(string); ok {
			onePasswordAppendField(details, field.id, field.source, map[string]any{field.tag: text})
			onePasswordMark(m, "/identity/"+field.source, "native", "details.sections.fields.value", false)
		}
	}
	if email, ok := identity["email"].(string); ok {
		onePasswordAppendField(details, "email", "Email", map[string]any{"email": map[string]any{"email_address": email, "provider": ""}})
		onePasswordMark(m, "/identity/email", "native", "details.sections.fields.value.email.email_address", false)
	}
	address := map[string]any{}
	for _, field := range []struct{ source, target string }{{"address1", "street"}, {"city", "city"}, {"state", "state"}, {"postalCode", "zip"}, {"country", "country"}} {
		if text, ok := identity[field.source].(string); ok {
			address[field.target] = text
			onePasswordMark(m, "/identity/"+field.source, "native", "details.sections.fields.value.address", false)
		}
	}
	if len(address) > 0 {
		onePasswordAppendField(details, "address", "Address", map[string]any{"address": address})
	}
	for _, field := range []struct {
		source, title string
		concealed     bool
	}{{"title", "Title", false}, {"address2", "Address 2", false}, {"address3", "Address 3", false}, {"ssn", "Social security number", true}, {"passportNumber", "Passport number", true}, {"licenseNumber", "License number", true}} {
		if text, ok := identity[field.source].(string); ok {
			tag := "string"
			if field.concealed {
				tag = "concealed"
			}
			onePasswordAppendField(details, "pwmigrate.identity."+field.source, field.title, map[string]any{tag: text})
			onePasswordMark(m, "/identity/"+field.source, "relocated", "details.sections.fields.value", field.concealed)
		}
	}
}

func onePasswordMapLogin(m *mappedRecord, details, overview map[string]any) {
	login := map[string]any{}
	m.value["login"] = login
	fields, _ := details["loginFields"].([]any)
	counts := map[string]int{}
	for _, raw := range fields {
		if field, ok := raw.(map[string]any); ok {
			if designation, ok := field["designation"].(string); ok && (designation == "username" || designation == "password") {
				counts[designation]++
			}
		}
	}
	for i, raw := range fields {
		field, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		designation, ok := field["designation"].(string)
		if !ok || (designation != "username" && designation != "password") {
			continue
		}
		if counts[designation] != 1 {
			onePasswordIssue(m, "unsupported_duplicate_credentials")
			continue
		}
		value, present := field["value"]
		if !present {
			continue
		}
		if _, ok := value.(string); !ok && value != nil {
			continue
		}
		login[designation] = value
		path := "/details/loginFields/" + strconv.Itoa(i)
		onePasswordMark(m, path+"/value", "native", "login."+designation, designation == "password")
		onePasswordMark(m, path+"/designation", "transformed", "login."+designation, false)
		if kind, ok := field["fieldType"].(string); ok {
			if (designation == "password" && kind == "P") || (designation == "username" && (kind == "T" || kind == "E")) {
				onePasswordMark(m, path+"/fieldType", "transformed", "login."+designation, false)
			}
		}
	}
	if urls, ok := overview["urls"].([]any); ok {
		uris := make([]any, 0, len(urls))
		for i, raw := range urls {
			if url, ok := raw.(map[string]any); ok {
				if text, ok := url["url"].(string); ok {
					uris = append(uris, map[string]any{"uri": text, "match": nil})
					onePasswordMark(m, "/overview/urls/"+strconv.Itoa(i)+"/url", "native", "login.uris.uri", false)
				}
			}
		}
		login["uris"] = uris
		if len(urls) == 0 {
			onePasswordMark(m, "/overview/urls", "native", "login.uris", false)
		}
	} else if url, ok := overview["url"].(string); ok {
		login["uris"] = []any{map[string]any{"uri": url, "match": nil}}
		onePasswordMark(m, "/overview/url", "native", "login.uris.uri", false)
	}
}

type onePasswordField struct {
	field, value    map[string]any
	path, id, title string
}

func onePasswordSectionFields(details map[string]any) []onePasswordField {
	result := []onePasswordField{}
	sections, _ := details["sections"].([]any)
	for i, raw := range sections {
		section, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		fields, _ := section["fields"].([]any)
		for j, raw := range fields {
			field, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			value, ok := field["value"].(map[string]any)
			if !ok {
				continue
			}
			id, _ := field["id"].(string)
			title, _ := field["title"].(string)
			result = append(result, onePasswordField{field: field, value: value, id: id, title: title, path: "/details/sections/" + strconv.Itoa(i) + "/fields/" + strconv.Itoa(j)})
		}
	}
	return result
}

func onePasswordFieldCounts(fields []onePasswordField) map[string]int {
	counts := map[string]int{}
	for _, field := range fields {
		counts[field.id]++
	}
	return counts
}

func onePasswordMapCard(m *mappedRecord, fields []onePasswordField) {
	card := m.value["card"].(map[string]any)
	counts := onePasswordFieldCounts(fields)
	for _, field := range fields {
		if counts[field.id] != 1 {
			onePasswordIssue(m, "unsupported_duplicate_fields")
			continue
		}
		if len(field.value) != 1 {
			continue
		}
		target, tag := "", ""
		switch field.id {
		case "ccnum":
			target = "number"
			tag = "creditCardNumber"
		case "cvv":
			target = "code"
			tag = "concealed"
		case "cardholder":
			target = "cardholderName"
			tag = "string"
		case "expiry":
			if number, ok := field.value["monthYear"].(json.Number); ok {
				text := number.String()
				if len(text) == 6 && onePasswordDigits(text) {
					year, yearErr := strconv.Atoi(text[:4])
					month, monthErr := strconv.Atoi(text[4:])
					if yearErr == nil && monthErr == nil && year >= 1000 && month >= 1 && month <= 12 {
						card["expYear"] = text[:4]
						card["expMonth"] = strconv.Itoa(month)
						onePasswordMark(m, field.path+"/value/monthYear", "transformed", "card.expMonth", false)
						onePasswordMark(m, field.path+"/id", "transformed", "card.expMonth", false)
					}
				}
			}
			continue
		default:
			continue
		}
		if text, ok := field.value[tag].(string); ok {
			card[target] = text
			onePasswordMark(m, field.path+"/value/"+tag, "native", "card."+target, target == "number" || target == "code")
			onePasswordMark(m, field.path+"/id", "transformed", "card."+target, false)
		}
	}
}

func onePasswordMapIdentity(m *mappedRecord, fields []onePasswordField) {
	identity := m.value["identity"].(map[string]any)
	counts := onePasswordFieldCounts(fields)
	for _, field := range fields {
		if counts[field.id] != 1 {
			onePasswordIssue(m, "unsupported_duplicate_fields")
			continue
		}
		if len(field.value) != 1 {
			continue
		}
		target, tag := "", "string"
		switch field.id {
		case "firstname":
			target = "firstName"
		case "lastname":
			target = "lastName"
		case "initial":
			target = "middleName"
		case "defphone":
			target = "phone"
			tag = "phone"
		case "company":
			target = "company"
		case "username":
			target = "username"
		case "email":
			if email, ok := field.value["email"].(map[string]any); ok {
				if text, ok := email["email_address"].(string); ok {
					identity["email"] = text
					onePasswordMark(m, field.path+"/value/email/email_address", "native", "identity.email", false)
					onePasswordMark(m, field.path+"/id", "transformed", "identity.email", false)
				}
			}
			continue
		case "address":
			if address, ok := field.value["address"].(map[string]any); ok {
				for _, part := range []struct{ source, target string }{{"street", "address1"}, {"city", "city"}, {"state", "state"}, {"zip", "postalCode"}, {"country", "country"}} {
					if text, ok := address[part.source].(string); ok {
						identity[part.target] = text
						onePasswordMark(m, field.path+"/value/address/"+part.source, "native", "identity."+part.target, false)
					}
				}
				onePasswordMark(m, field.path+"/id", "transformed", "identity.address1", false)
			}
			continue
		default:
			continue
		}
		if text, ok := field.value[tag].(string); ok {
			identity[target] = text
			onePasswordMark(m, field.path+"/value/"+tag, "native", "identity."+target, false)
			onePasswordMark(m, field.path+"/id", "transformed", "identity."+target, false)
		}
	}
}

func onePasswordMapCustom(m *mappedRecord, field onePasswordField, kind string) {
	if len(field.value) != 1 {
		return
	}
	if kind == "login" {
		if _, present := field.value["totp"]; present {
			return
		}
	}
	if _, present := field.field["title"]; !present {
		return
	}
	if _, ok := field.field["title"].(string); !ok {
		return
	}
	for _, tag := range []string{"string", "concealed", "creditCardType", "creditCardNumber", "phone", "url", "menu", "gender"} {
		value, ok := field.value[tag].(string)
		if !ok {
			continue
		}
		path := field.path + "/value/" + tag
		if mapping, ok := m.mappings[path]; ok && mapping.disposition != "unsupported" {
			return
		}
		// Canonical card/identity IDs occurring more than once are deliberately
		// retained as independent custom values rather than choosing a winner.
		concealed := tag == "concealed" || tag == "creditCardNumber"
		typeNumber := json.Number("0")
		if concealed {
			typeNumber = "1"
		}
		custom, _ := m.value["fields"].([]any)
		m.value["fields"] = append(custom, map[string]any{"name": field.title, "value": value, "type": typeNumber})
		disposition := "relocated"
		if tag != "string" && tag != "concealed" {
			disposition = "transformed"
		}
		onePasswordMark(m, path, disposition, "fields.value", concealed)
		onePasswordMark(m, field.path+"/title", "relocated", "fields.name", false)
		return
	}
}
