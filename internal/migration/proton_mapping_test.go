package migration

import (
	"encoding/json"
	"testing"
)

func protonTestRecord(t *testing.T, literal string, kind string) providerRecord {
	t.Helper()
	value, err := parseStrictJSON([]byte(literal))
	if err != nil {
		t.Fatal(err)
	}
	item := value.(map[string]any)
	return providerRecord{value: item, kind: kind, fields: flattenFields(item, "")}
}

func protonRequireAccounting(t *testing.T, record providerRecord, mapped mappedRecord) {
	t.Helper()
	if len(mapped.mappings) != len(record.fields) {
		t.Fatal("not every source field was accounted")
	}
	for _, field := range record.fields {
		mapping, ok := mapped.mappings[field.path]
		if !ok || mapping.disposition == "" {
			t.Fatal("missing source-field disposition")
		}
	}
}

func TestProtonToBitwardenDistinctEmailExactCredentialsAndUnknownData(t *testing.T) {
	r := protonTestRecord(t, `{"data":{"type":"login","metadata":{"name":" title ","note":" untouched\r\n ","itemUuid":"id"},"content":{"itemUsername":" username ","itemEmail":" email ","password":" password\r\n ","totpUri":" seed ","urls":[" https://synthetic.invalid/ "],"passkeys":[{"content":"private blob"}],"future":"private unknown"},"extraFields":[{"fieldName":" custom ","type":"hidden","data":{"content":" custom secret\n "}}]},"pinned":true,"state":1}`, "login")
	m, err := mapProtonToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, r, m)
	if m.value["name"] != " title " || m.value["notes"] != " untouched\r\n " || m.value["favorite"] != true {
		t.Fatal("metadata value changed")
	}
	l := m.value["login"].(map[string]any)
	if l["username"] != " username " || l["password"] != " password\r\n " || l["totp"] != " seed " {
		t.Fatal("credentials changed")
	}
	f := m.value["fields"].([]any)
	if len(f) != 2 {
		t.Fatal("email or typed custom field disappeared")
	}
	if f[0].(map[string]any)["value"] != " email " || f[1].(map[string]any)["name"] != " custom " || f[1].(map[string]any)["value"] != " custom secret\n " || f[1].(map[string]any)["type"] != json.Number("1") {
		t.Fatal("exact custom values or hidden type changed")
	}
	if m.mappings["/data/content/passkeys/0/content"].disposition != "unsupported" || m.mappings["/data/content/future"].disposition != "unsupported" {
		t.Fatal("unsupported source fields falsely migrated")
	}
}

func TestBitwardenToProtonPreservesExactLoginAndTypedFields(t *testing.T) {
	r := protonTestRecord(t, `{"type":1,"name":" title ","notes":" \r\n ","favorite":false,"login":{"username":" username ","password":" secret\n ","totp":" raw seed ","uris":[{"uri":" https://synthetic.invalid/ ","match":0}],"fido2Credentials":[{"keyValue":"private"}]},"fields":[{"name":" text ","value":" value ","type":0},{"name":" hidden ","value":" secret ","type":1},{"name":" boolean ","value":"true","type":2},{"name":" linked ","value":null,"type":3,"linkedId":100}]}`, "login")
	m, err := mapBitwardenToProton(r)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, r, m)
	d := m.value["data"].(map[string]any)
	meta := d["metadata"].(map[string]any)
	c := d["content"].(map[string]any)
	if meta["name"] != " title " || meta["note"] != " \r\n " || c["itemUsername"] != " username " || c["password"] != " secret\n " || c["totpUri"] != " raw seed " {
		t.Fatal("native destination changed exact source values")
	}
	extra := d["extraFields"].([]any)
	if len(extra) != 2 || extra[0].(map[string]any)["type"] != "text" || extra[1].(map[string]any)["type"] != "hidden" {
		t.Fatal("custom provider types were coerced")
	}
	for _, path := range []string{"/fields/2/value", "/fields/3/linkedId", "/login/uris/0/match", "/login/fido2Credentials/0/keyValue"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("unsupported policy falsely mapped")
		}
	}
	if m.mappings["/favorite"].disposition != "unsupported" {
		t.Fatal("native reader's ignored pinned flag was claimed migrated")
	}
}

func TestProtonUnknownTypesCannotBecomeLogins(t *testing.T) {
	for _, tc := range []struct {
		raw, kind  string
		fromProton bool
	}{
		{`{"data":{"type":"alias","metadata":{"name":"alias"},"content":{}},"aliasEmail":"email"}`, "alias", true},
		{`{"data":{"type":"future","metadata":{"name":"unknown"},"content":{"private":"value"}}}`, "unknown", true},
		{`{"type":5,"name":"ssh","sshKey":{"privateKey":"key"}}`, "ssh_key", false},
	} {
		r := protonTestRecord(t, tc.raw, tc.kind)
		var m mappedRecord
		var err error
		if tc.fromProton {
			m, err = mapProtonToBitwarden(r)
		} else {
			m, err = mapBitwardenToProton(r)
		}
		if err != nil {
			t.Fatal(err)
		}
		protonRequireAccounting(t, r, m)
		if m.value != nil || len(m.issues) == 0 {
			t.Fatal("unsupported item generated destination credential")
		}
	}
}

func TestProtonCardAndIdentityUseDeclaredNativeFields(t *testing.T) {
	card := protonTestRecord(t, `{"type":3,"name":" card ","card":{"cardholderName":" holder ","number":" 1234 ","brand":"Visa","expMonth":"01","expYear":"2030","code":" 123 "}}`, "card")
	m, err := mapBitwardenToProton(card)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, card, m)
	c := m.value["data"].(map[string]any)["content"].(map[string]any)
	if c["cardType"] != json.Number("2") || c["expirationDate"] != "012030" || c["number"] != " 1234 " || c["verificationNumber"] != " 123 " {
		t.Fatal("native card schema or values changed")
	}
	if m.mappings["/card/expMonth"].disposition != "transformed" {
		t.Fatal("card expiration transformation not disclosed")
	}
	identity := protonTestRecord(t, `{"data":{"type":"identity","metadata":{"name":" identity ","note":" note "},"content":{"firstName":" First ","middleName":" Middle ","lastName":" Last ","fullName":" Full ","streetAddress":" address1 ","floor":" address2 ","socialSecurityNumber":" ssn ","company":" company ","email":" email ","phoneNumber":" phone ","birthdate":"2020-01-01","extraPersonalDetails":[{"fieldName":"unknown","type":"future","data":{"private":"value"}}]}}}`, "identity")
	m, err = mapProtonToBitwarden(identity)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, identity, m)
	i := m.value["identity"].(map[string]any)
	if i["firstName"] != " First " || i["middleName"] != " Middle " || i["lastName"] != " Last " || i["address1"] != " address1 " || i["address2"] != " address2 " || i["ssn"] != " ssn " {
		t.Fatal("identity fields changed or conflated")
	}
	if m.value["notes"] != " note " || m.mappings["/data/content/extraPersonalDetails/0/data/private"].disposition != "unsupported" {
		t.Fatal("unfamiliar identity payload was coerced")
	}
}

func TestProtonCustomTOTPAndTimestampAreNotCoercedIntoText(t *testing.T) {
	r := protonTestRecord(t, `{"data":{"type":"note","metadata":{"name":"note","note":"original"},"content":{},"extraFields":[{"fieldName":"otp","type":"totp","data":{"totpUri":"otp value"}},{"fieldName":"date","type":"timestamp","data":{"timestamp":{"seconds":123,"nanos":4}}}]}}`, "secure_note")
	m, err := mapProtonToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, r, m)
	if len(m.value["fields"].([]any)) != 0 || m.value["notes"] != "original" {
		t.Fatal("unsupported custom types were coerced")
	}
	for _, path := range []string{"/data/extraFields/0/type", "/data/extraFields/0/data/totpUri", "/data/extraFields/1/data/timestamp/seconds"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("unsupported custom semantics falsely claimed native")
		}
	}
}

func TestProtonURLRepresentationsRetainMultiplicityAndRejectPolicyCoercion(t *testing.T) {
	r := protonTestRecord(t, `{"data":{"type":"login","metadata":{"name":"n"},"content":{"itemUsername":"","itemEmail":"","password":"","totpUri":"","urls":["https://synthetic.invalid/"],"autofillUrls":[{"url":"https://synthetic.invalid/","mode":0},{"url":" https://second.invalid/ ","mode":2}]},"extraFields":[]}}`, "login")
	m, err := mapProtonToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	protonRequireAccounting(t, r, m)
	urls := m.value["login"].(map[string]any)["uris"].([]any)
	if len(urls) != 3 || urls[0].(map[string]any)["uri"] != "https://synthetic.invalid/" || urls[1].(map[string]any)["uri"] != "https://synthetic.invalid/" || urls[2].(map[string]any)["uri"] != " https://second.invalid/ " {
		t.Fatal("URL strings or duplicated source multiplicity changed")
	}
	if m.mappings["/data/content/autofillUrls/0/mode"].disposition != "unsupported" || m.mappings["/data/content/autofillUrls/1/mode"].disposition != "unsupported" {
		t.Fatal("provider policy enums were treated as equivalent")
	}
	combined := false
	for _, code := range m.issues {
		if code == "uri_representations_combined" {
			combined = true
		}
	}
	if !combined {
		t.Fatal("combining legacy and current URL representations was not disclosed")
	}
}
