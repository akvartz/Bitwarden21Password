package migration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func onePasswordZIP(t *testing.T, attrs, data string, extra map[string][]byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for name, content := range map[string][]byte{"export.attributes": []byte(attrs), "export.data": []byte(data)} {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range extra {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

const onePasswordAttrs = `{"version":3,"description":"1Password Unencrypted Export","createdAt":9007199254740993}`

func TestOnePasswordRetainsWholeItemsMetadataAndFiles(t *testing.T) {
	data := `{"sentinel":{"empty":[],"null":null},"accounts":[{"attrs":{"uuid":"account","unknown":9007199254740993},"vaults":[{"attrs":{"uuid":"vault","name":"synthetic"},"items":[{"uuid":"item","categoryUuid":"001","state":"active","overview":{"title":"  title Ω  ","unknown":{}},"details":{"loginFields":[{"designation":"username","value":"  user  "},{"designation":"password","value":"  pass\r\nlast  "}],"notesPlain":null,"unknown":{"empty":[],"null":null}}},{"categoryUuid":"003","overview":{"title":""},"details":{}},{"categoryUuid":"900","overview":{"title":"unknown"},"details":{"opaque":900719925474099312345}}]}]}]}`
	file := []byte{0, 255, 1, 2}
	p, err := parseOnePassword(onePasswordZIP(t, onePasswordAttrs, data, map[string][]byte{"files/synthetic.bin": file}))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.records) != 3 || p.records[0].kind != "login" || p.records[1].kind != "secure_note" || p.records[2].kind != "unknown" {
		t.Fatal("record kinds or multiplicity changed")
	}
	if p.records[0].vault != 1 {
		t.Fatal("vault relationship was not inventoried")
	}
	fields := p.records[0].value["details"].(map[string]any)["loginFields"].([]any)
	if fields[0].(map[string]any)["value"] != "  user  " || fields[1].(map[string]any)["value"] != "  pass\r\nlast  " {
		t.Fatal("credential bytes changed")
	}
	if p.records[2].value["details"].(map[string]any)["opaque"].(json.Number).String() != "900719925474099312345" {
		t.Fatal("integer precision changed")
	}
	if !bytes.Equal(p.files["files/synthetic.bin"], file) {
		t.Fatal("archive payload changed")
	}
	foundFile := false
	for _, field := range p.metadata {
		if field.path == "/files/files~1synthetic.bin" {
			foundFile = bytes.Equal(field.value.([]byte), file)
		}
	}
	if !foundFile {
		t.Fatal("archive file missing explicit field disposition")
	}
	wanted := map[string]any{"/details/notesPlain": nil, "/details/unknown/empty": []any{}, "/overview/unknown": map[string]any{}}
	for _, field := range p.records[0].fields {
		if value, present := wanted[field.path]; present {
			if !reflect.DeepEqual(field.value, value) {
				t.Fatal("null or empty value changed")
			}
			delete(wanted, field.path)
		}
	}
	if len(wanted) != 0 {
		t.Fatal("complete item leaves not inventoried")
	}
	for _, field := range p.metadata {
		if field.path == "/export.data/accounts/0/vaults/0/items/0/uuid" {
			t.Fatal("record field double counted as metadata")
		}
	}
}

func TestOnePasswordRejectsUnsupportedOrMalformedEnvelopes(t *testing.T) {
	for _, tc := range []struct{ name, attrs, data, code string }{
		{"version", `{"version":4,"description":"1Password Unencrypted Export"}`, `{"accounts":[]}`, "unsupported_version"},
		{"fractional_version", `{"version":3.0,"description":"1Password Unencrypted Export"}`, `{"accounts":[]}`, "unsupported_version"},
		{"description", `{"version":3,"description":"other"}`, `{"accounts":[]}`, "invalid_json"},
		{"missing_accounts", onePasswordAttrs, `{}`, "invalid_json"},
		{"null_accounts", onePasswordAttrs, `{"accounts":null}`, "invalid_json"},
		{"invalid_account", onePasswordAttrs, `{"accounts":[null]}`, "invalid_json"},
		{"missing_vaults", onePasswordAttrs, `{"accounts":[{"attrs":{}}]}`, "invalid_json"},
		{"invalid_vault", onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":null}]}]}`, "invalid_json"},
		{"invalid_item", onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[null]}]}]}`, "invalid_item"},
		{"missing_category", onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[{"overview":{"title":"x"},"details":{}}]}]}]}`, "invalid_item"},
		{"nonstring_title", onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[{"categoryUuid":"001","overview":{"title":null},"details":{}}]}]}]}`, "invalid_item"},
		{"duplicate", onePasswordAttrs, `{"accounts":[],"accounts":[]}`, "duplicate_json_key"},
		{"surrogate", onePasswordAttrs, `{"accounts":[],"x":"\uD800"}`, "invalid_json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOnePassword(onePasswordZIP(t, tc.attrs, tc.data, nil))
			safe, ok := err.(*SafeError)
			if !ok || safe.Code != tc.code {
				t.Fatalf("unexpected safe result: %v", err)
			}
		})
	}
}

func TestOnePasswordWriterLiteralV3Envelope(t *testing.T) {
	item := map[string]any{"categoryUuid": "003", "overview": map[string]any{"title": "  note  "}, "details": map[string]any{"notesPlain": "literal\\n\r\n"}}
	data, err := exportOnePassword([]map[string]any{item, item})
	if err != nil {
		t.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var attrs map[string]any
	var root map[string]any
	for _, file := range archive.File {
		r, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		d := json.NewDecoder(r)
		d.UseNumber()
		switch file.Name {
		case "export.attributes":
			err = d.Decode(&attrs)
		case "export.data":
			err = d.Decode(&root)
		default:
			t.Fatal("unexpected writer file")
		}
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if attrs["version"] != json.Number("3") || attrs["description"] != "1Password Unencrypted Export" {
		t.Fatal("writer does not use literal v3 envelope")
	}
	accounts := root["accounts"].([]any)
	vaults := accounts[0].(map[string]any)["vaults"].([]any)
	items := vaults[0].(map[string]any)["items"].([]any)
	if len(items) != 2 {
		t.Fatal("writer changed duplicate multiplicity")
	}
	for _, raw := range items {
		got := raw.(map[string]any)
		if got["categoryUuid"] != "003" || got["overview"].(map[string]any)["title"] != "  note  " || !reflect.DeepEqual(got["details"], item["details"]) {
			t.Fatal("writer changed supplied item values")
		}
		if uuid, ok := got["uuid"].(string); !ok || len(uuid) != 26 {
			t.Fatal("writer missing documented item identifier")
		}
	}
	if items[0].(map[string]any)["uuid"] == items[1].(map[string]any)["uuid"] {
		t.Fatal("duplicate items assigned same generated identifier")
	}
}

func TestOnePasswordAggregateContainerBudget(t *testing.T) {
	attrs := `{"version":3,"description":"1Password Unencrypted Export","forest":[` + strings.Repeat("{},", 249989) + `{}]}`
	data := `{"accounts":[],"opaque":[` + strings.Repeat("{},", 9) + `{}]}`
	_, err := parseOnePassword(onePasswordZIP(t, attrs, data, nil))
	if safe, ok := err.(*SafeError); !ok || safe.Code != "container_limit" {
		t.Fatal("archive JSON members bypass combined container budget")
	}
}

func TestOnePasswordEmptyVaultAccountsMetadataFields(t *testing.T) {
	p, err := parseOnePassword(onePasswordZIP(t, onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[]}]}]}`, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.vaultCount != 1 || len(p.records) != 0 {
		t.Fatal("empty vault relationship lost")
	}
	if len(p.metadata) != 6 {
		t.Fatal("empty items/attrs containers not completely inventoried")
	}
}

func TestOnePasswordWriterBoundsEscapingBeforeMarshal(t *testing.T) {
	item := map[string]any{"categoryUuid": "003", "overview": map[string]any{"title": "synthetic"}, "details": map[string]any{"notesPlain": strings.Repeat("\x00", 6<<20)}}
	_, err := exportOnePassword([]map[string]any{item})
	if safe, ok := err.(*SafeError); !ok || safe.Code != "output_limit" {
		t.Fatal("escaping amplification was not bounded")
	}
}

func TestOnePasswordWriterRejectsNonstringCredential(t *testing.T) {
	item := map[string]any{"categoryUuid": "001", "overview": map[string]any{"title": "synthetic"}, "details": map[string]any{"loginFields": []any{map[string]any{"id": "password", "name": "password", "fieldType": "P", "designation": "password", "value": nil}}}}
	_, err := exportOnePassword([]map[string]any{item})
	if safe, ok := err.(*SafeError); !ok || safe.Code != "output_validation" {
		t.Fatal("writer published undocumented null credential shape")
	}
}
