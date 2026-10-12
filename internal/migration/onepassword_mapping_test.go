package migration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func onePasswordLiteralRecord(t *testing.T, kind, literal string) providerRecord {
	t.Helper()
	d := json.NewDecoder(bytes.NewBufferString(literal))
	d.UseNumber()
	var item map[string]any
	if err := d.Decode(&item); err != nil {
		t.Fatal(err)
	}
	return providerRecord{value: item, kind: kind, fields: flattenFields(item, "")}
}

func TestBitwardenToOnePasswordLiteralCredentialsAndDispositions(t *testing.T) {
	r := onePasswordLiteralRecord(t, "login", `{"type":1,"name":"  title Ω  ","notes":"literal\\n\r\nlast","login":{"username":"  user  ","password":"  pass\r\nlast  ","totp":"  otpauth://literal  ","uris":[{"uri":"https://synthetic.invalid/","match":2},{"uri":"https://synthetic.invalid/","match":null}],"fido2Credentials":[{"credentialId":"synthetic-passkey"}]},"id":"synthetic-id","folderId":"synthetic-folder","creationDate":"2026-10-11T00:00:00Z","fields":[{"name":"  custom  ","value":"  secret  ","type":1},{"name":"bool","value":"false","type":2},{"name":"null","value":null,"type":0}]}`)
	m, err := mapBitwardenToOnePassword(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value["categoryUuid"] != "001" || m.value["overview"].(map[string]any)["title"] != "  title Ω  " {
		t.Fatal("item type or title changed")
	}
	details := m.value["details"].(map[string]any)
	if details["notesPlain"] != "literal\\n\r\nlast" {
		t.Fatal("arbitrary notes reinterpreted")
	}
	fields := details["loginFields"].([]any)
	if len(fields) != 2 || fields[0].(map[string]any)["value"] != "  user  " || fields[1].(map[string]any)["value"] != "  pass\r\nlast  " {
		t.Fatal("credentials changed")
	}
	urls := m.value["overview"].(map[string]any)["urls"].([]any)
	if len(urls) != 2 || urls[0].(map[string]any)["url"] != urls[1].(map[string]any)["url"] {
		t.Fatal("duplicate URI multiplicity changed")
	}
	for _, path := range []string{"/id", "/folderId", "/creationDate", "/login/uris/0/match", "/login/uris/1/match", "/login/fido2Credentials/0/credentialId", "/fields/2/value"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("unsupported field falsely mapped")
		}
	}
	if m.mappings["/login/password"].disposition != "native" || m.mappings["/fields/0/value"].disposition != "relocated" || !m.mappings["/fields/0/value"].concealed {
		t.Fatal("mapping disposition incorrect")
	}
	if m.mappings["/fields/1/type"].disposition != "transformed" {
		t.Fatal("boolean custom type degradation undisclosed")
	}
	if len(m.mappings) != len(r.fields) {
		t.Fatal("source leaf missing disposition")
	}
}

func TestOnePasswordToBitwardenLiteralRichValues(t *testing.T) {
	r := onePasswordLiteralRecord(t, "login", `{"categoryUuid":"001","uuid":"synthetic-id","createdAt":9007199254740993,"state":"archived","overview":{"title":"  title  ","tags":["a","a"],"urls":[{"label":"synthetic","url":" https://synthetic.invalid/ "},{"label":"","url":" https://synthetic.invalid/ "}]},"details":{"notesPlain":"\r\n  note  ","loginFields":[{"designation":"username","fieldType":"T","value":"  user  "},{"designation":"password","fieldType":"P","value":"  pass  "}],"sections":[{"name":"","title":"","fields":[{"id":"totp","title":"TOTP","value":{"totp":" otpauth://synthetic "}},{"id":"custom","title":" custom ","value":{"concealed":" secret "}}]}]}}`)
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	login := m.value["login"].(map[string]any)
	if login["username"] != "  user  " || login["password"] != "  pass  " || login["totp"] != " otpauth://synthetic " || m.value["notes"] != "\r\n  note  " {
		t.Fatal("literal credentials or notes changed")
	}
	uris := login["uris"].([]any)
	if len(uris) != 2 || uris[0].(map[string]any)["uri"] != " https://synthetic.invalid/ " {
		t.Fatal("URL or multiplicity changed")
	}
	custom := m.value["fields"].([]any)[0].(map[string]any)
	if custom["name"] != " custom " || custom["value"] != " secret " || custom["type"] != json.Number("1") {
		t.Fatal("concealed custom field changed")
	}
	for _, path := range []string{"/uuid", "/createdAt", "/state", "/overview/tags/0", "/overview/tags/1", "/overview/urls/0/label"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("metadata loss undisclosed")
		}
	}
	if len(m.mappings) != len(r.fields) {
		t.Fatal("source field disposition missing")
	}
}

func TestOnePasswordDuplicateCredentialsAreNotCollapsed(t *testing.T) {
	r := onePasswordLiteralRecord(t, "login", `{"categoryUuid":"001","overview":{"title":"x"},"details":{"loginFields":[{"designation":"username","value":"first"},{"designation":"username","value":"second"},{"designation":"password","value":"pass"}]}}`)
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	login := m.value["login"].(map[string]any)
	if _, present := login["username"]; present {
		t.Fatal("ambiguous username selected")
	}
	for _, path := range []string{"/details/loginFields/0/value", "/details/loginFields/1/value"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("duplicate credential dropped without issue")
		}
	}
	if !reflect.DeepEqual(m.issues, []string{"unsupported_duplicate_credentials"}) {
		t.Fatal("duplicate credential issue missing")
	}
}

func TestOnePasswordNullAbsentAndEmptyCredentials(t *testing.T) {
	r := onePasswordLiteralRecord(t, "login", `{"categoryUuid":"001","overview":{"title":""},"details":{"loginFields":[{"designation":"username","value":null},{"designation":"password","value":""}],"notesPlain":null}}`)
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	login := m.value["login"].(map[string]any)
	if login["username"] != nil || login["password"] != "" {
		t.Fatal("null or empty credential changed")
	}
	if value, present := m.value["notes"]; !present || value != nil {
		t.Fatal("null note distinction lost")
	}
	r = onePasswordLiteralRecord(t, "login", `{"categoryUuid":"001","overview":{"title":""},"details":{}}`)
	m, err = mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := m.value["notes"]; present {
		t.Fatal("absent notes manufactured")
	}
	if _, present := m.value["login"].(map[string]any)["username"]; present {
		t.Fatal("absent username manufactured")
	}
}

func TestBitwardenOnePasswordCardAndIdentityLiteralMapping(t *testing.T) {
	r := onePasswordLiteralRecord(t, "card", `{"type":3,"name":"card","card":{"cardholderName":"  holder  ","number":"00001234","code":"009","expMonth":"02","expYear":"2030","brand":"Visa"}}`)
	m, err := mapBitwardenToOnePassword(r)
	if err != nil {
		t.Fatal(err)
	}
	sections := m.value["details"].(map[string]any)["sections"].([]any)
	fields := sections[0].(map[string]any)["fields"].([]any)
	values := map[string]any{}
	for _, raw := range fields {
		f := raw.(map[string]any)
		values[f["id"].(string)] = f["value"]
	}
	if !reflect.DeepEqual(values["ccnum"], map[string]any{"creditCardNumber": "00001234"}) || !reflect.DeepEqual(values["expiry"], map[string]any{"monthYear": json.Number("203002")}) {
		t.Fatal("card schema or value incorrect")
	}
	if m.mappings["/card/expMonth"].disposition != "transformed" {
		t.Fatal("card expiration representation change undisclosed")
	}
	r = onePasswordLiteralRecord(t, "identity", `{"categoryUuid":"004","overview":{"title":"id"},"details":{"sections":[{"fields":[{"id":"firstname","value":{"string":"  first  "}},{"id":"email","value":{"email":{"email_address":"exact@example.invalid","provider":"other"}}},{"id":"address","value":{"address":{"street":"line 1\r\nline 2","city":" city ","state":" st ","zip":"00001","country":"xx"}}}]}]}}`)
	m, err = mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	id := m.value["identity"].(map[string]any)
	if id["firstName"] != "  first  " || id["address1"] != "line 1\r\nline 2" || id["country"] != "xx" || id["postalCode"] != "00001" {
		t.Fatal("identity values normalized")
	}
	if m.mappings["/details/sections/0/fields/1/value/email/provider"].disposition != "unsupported" {
		t.Fatal("email provider metadata loss undisclosed")
	}
}

func TestOnePasswordUnknownAndSSHRecordsBlockOutput(t *testing.T) {
	for _, kind := range []string{"unknown", "ssh_key"} {
		r := onePasswordLiteralRecord(t, kind, `{"categoryUuid":"114","overview":{"title":"synthetic"},"details":{"opaque":{}}}`)
		m, err := mapOnePasswordToBitwarden(r)
		if err != nil {
			t.Fatal(err)
		}
		if m.value != nil {
			t.Fatal("unsupported functional item emitted")
		}
		for _, mapping := range m.mappings {
			if mapping.disposition != "unsupported" {
				t.Fatal("unsupported kind falsely migrated")
			}
		}
	}
}

func TestOnePasswordWriterRejectsUnaccompaniedAttachment(t *testing.T) {
	_, err := exportOnePassword([]map[string]any{{"categoryUuid": "006", "overview": map[string]any{"title": "document"}, "details": map[string]any{"documentAttributes": map[string]any{"fileName": "synthetic.bin"}}}})
	if safe, ok := err.(*SafeError); !ok || safe.Code != "output_validation" {
		t.Fatal("attachment reference silently published without body")
	}
}

func TestBitwardenOnePasswordProjectionContainsGeneratedDefaults(t *testing.T) {
	r := onePasswordLiteralRecord(t, "login", `{"type":1,"name":"synthetic","login":{"username":"exact"}}`)
	m, err := mapBitwardenToOnePassword(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value["state"] != "active" || m.value["favIndex"] != json.Number("0") {
		t.Fatal("writer meaningful defaults absent from expected projection")
	}
	overview := m.value["overview"].(map[string]any)
	if overview["url"] != "" || overview["subtitle"] != "" {
		t.Fatal("required display defaults absent from expected projection")
	}
	if _, present := r.value["favorite"]; present {
		t.Fatal("source default manufactured")
	}
}
