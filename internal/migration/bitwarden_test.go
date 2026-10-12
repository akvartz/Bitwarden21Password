package migration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBitwardenRetainsAllFieldsAndIntegerPrecision(t *testing.T) {
	data := []byte(`{
 "encrypted": false,
 "customRootSentinel": {"large":900719925474099312345,"empty":[],"null":null},
 "items":[
  {"type":1,"name":"  title Ω  ","login":{"username":"  user  ","password":"  pass\r\nline\nlast  ","totp":null,"uris":[],"fido2Credentials":[{"credentialId":"synthetic-passkey","counter":9007199254740993}]},"customItemSentinel":{"value":"literal\\n","absentMarker":{}}},
  {"type":2,"name":"","notes":null},
  {"type":3,"name":"card","card":{"number":"0000"}},
  {"type":4,"name":"identity","identity":{"title":"","firstName":"x","customNested":[null,{}]}},
  {"type":5,"name":"ssh","sshKey":{"privateKey":"synthetic-key","publicKey":"synthetic-public","keyFingerprint":"synthetic-fingerprint"}},
  {"type":900719925474099312345,"name":"unknown","opaque":[{},[],null]}
 ]
}`)
	d := mustParse(t, data, BitwardenJSON)
	if !bytes.Equal(d.source, data) {
		t.Fatal("Bitwarden source snapshot differs from supplied bytes")
	}
	root := d.bitwardenRoot
	metadata := root["customRootSentinel"].(map[string]any)
	if metadata["large"].(json.Number).String() != "900719925474099312345" {
		t.Fatal("root integer precision changed")
	}
	items := root["items"].([]any)
	item := items[0].(map[string]any)
	login := item["login"].(map[string]any)
	if login["username"] != "  user  " || login["password"] != "  pass\r\nline\nlast  " || login["totp"] != nil {
		t.Fatal("known login values changed")
	}
	creds := login["fido2Credentials"].([]any)[0].(map[string]any)
	if creds["counter"].(json.Number).String() != "9007199254740993" || creds["credentialId"] != "synthetic-passkey" {
		t.Fatal("passkey payload changed")
	}
	custom := item["customItemSentinel"].(map[string]any)
	if custom["value"] != "literal\\n" || len(custom["absentMarker"].(map[string]any)) != 0 {
		t.Fatal("unknown data changed")
	}
	if items[5].(map[string]any)["type"].(json.Number).String() != "900719925474099312345" {
		t.Fatal("unknown integer type changed")
	}
	if len(items[3].(map[string]any)["identity"].(map[string]any)) != 3 {
		t.Fatal("identity payload dropped")
	}
	if len(items[4].(map[string]any)["sshKey"].(map[string]any)) != 3 {
		t.Fatal("SSH payload dropped")
	}
	inv := d.Inspect()
	if inv.Records != 6 || inv.Fields != 32 || inv.MetadataFields != 4 {
		t.Fatalf("unexpected safe counts: records=%d fields=%d metadata=%d", inv.Records, inv.Fields, inv.MetadataFields)
	}
	if !reflect.DeepEqual(inv.Kinds, map[string]int{"login": 1, "secure_note": 1, "card": 1, "identity": 1, "ssh_key": 1, "unknown": 1}) {
		t.Fatal("kind counts changed")
	}
	if inv.DuplicateDetection != "exact_provider_content_v1" || len(inv.DuplicateGroups) != 0 {
		t.Fatal("conservative Bitwarden duplicate rule or counts changed")
	}
}

func TestBitwardenNullEmptyAndAbsentValues(t *testing.T) {
	data := []byte(`{"encrypted":false,"items":[{"type":1,"name":"","login":{"username":null,"password":"","totp":"   "}},{"type":1,"name":"null","login":null},{"type":1,"name":"absent"}]}`)
	d := mustParse(t, data, BitwardenJSON)
	items := d.bitwardenRoot["items"].([]any)
	first := items[0].(map[string]any)["login"].(map[string]any)
	if first["username"] != nil || first["password"] != "" || first["totp"] != "   " {
		t.Fatal("null or empty credential was changed")
	}
	if _, present := items[2].(map[string]any)["login"]; present {
		t.Fatal("absent field was manufactured")
	}
	inv := d.Inspect()
	if inv.Fields != 10 || inv.MetadataFields != 1 {
		t.Fatal("null, empty, and absent field accounting changed")
	}
}

func TestBitwardenEmptyExportMetadataAccounting(t *testing.T) {
	d := mustParse(t, []byte(`{"encrypted":false,"items":[],"folders":[],"collections":{},"unknown":{"array":[null,true,0],"empty":{}}}`), BitwardenJSON)
	inv := d.Inspect()
	if inv.Records != 0 || inv.Fields != 0 || inv.MetadataFields != 8 {
		t.Fatalf("incorrect empty-export counts: records=%d fields=%d metadata=%d", inv.Records, inv.Fields, inv.MetadataFields)
	}
}

func TestBitwardenEmptyItemsIsMetadataWithoutInventingOrDoubleCountingRecords(t *testing.T) {
	for _, tc := range []struct {
		items, record int
		literal       string
	}{
		{0, 0, `[]`},
		{1, 1, `[{"type":2,"name":"synthetic"}]`},
	} {
		d := mustParse(t, []byte(`{"encrypted":false,"items":`+tc.literal+`}`), BitwardenJSON)
		wantMetadata := 1
		if tc.items == 0 {
			wantMetadata = 2
		}
		if d.Inspect().Records != tc.record || d.Inspect().MetadataFields != wantMetadata || len(d.provider.metadata) != wantMetadata {
			t.Fatal("empty item array was lost or nonempty record fields were double counted")
		}
		foundItems := false
		for _, field := range d.provider.metadata {
			if field.path == "/items" {
				foundItems = reflect.DeepEqual(field.value, []any{})
			}
		}
		if foundItems != (tc.items == 0) {
			t.Fatal("private metadata inventory did not retain exactly the empty items container")
		}
		plan, err := d.Plan(OnePassword1PUX, nil)
		if err != nil || len(plan.Metadata) != wantMetadata {
			t.Fatal("empty items container lacked a metadata disposition")
		}
	}
}

func TestBitwardenStrictEnvelopeAndItemRejections(t *testing.T) {
	tests := []struct{ name, data, code string }{
		{"encrypted", `{"encrypted":true,"items":[]}`, "unsupported_encrypted"},
		{"missing_encrypted", `{"items":[]}`, "invalid_json"},
		{"invalid_encrypted_type", `{"encrypted":"TypeSentinel","items":[]}`, "invalid_json"},
		{"missing_items", `{"encrypted":false}`, "invalid_json"},
		{"null_items", `{"encrypted":false,"items":null}`, "invalid_json"},
		{"object_items", `{"encrypted":false,"items":{}}`, "invalid_json"},
		{"root_array", `[]`, "invalid_json"},
		{"null_item", `{"encrypted":false,"items":[null]}`, "invalid_item"},
		{"array_item", `{"encrypted":false,"items":[[]]}`, "invalid_item"},
		{"missing_type", `{"encrypted":false,"items":[{"name":"x"}]}`, "invalid_item"},
		{"string_type", `{"encrypted":false,"items":[{"type":"TypeSentinel","name":"x"}]}`, "invalid_item"},
		{"fractional_type", `{"encrypted":false,"items":[{"type":1.5,"name":"x"}]}`, "invalid_item"},
		{"decimal_integer_type", `{"encrypted":false,"items":[{"type":1.0,"name":"x"}]}`, "invalid_item"},
		{"exponential_type", `{"encrypted":false,"items":[{"type":1e0,"name":"x"}]}`, "invalid_item"},
		{"missing_name", `{"encrypted":false,"items":[{"type":1}]}`, "invalid_item"},
		{"null_name", `{"encrypted":false,"items":[{"type":1,"name":null}]}`, "invalid_item"},
		{"invalid_login", `{"encrypted":false,"items":[{"type":1,"name":"x","login":[]}]}`, "invalid_item"},
		{"invalid_username", `{"encrypted":false,"items":[{"type":1,"name":"x","login":{"username":1}}]}`, "invalid_item"},
		{"invalid_password", `{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":false}}]}`, "invalid_item"},
		{"invalid_totp", `{"encrypted":false,"items":[{"type":1,"name":"x","login":{"totp":{}}}]}`, "invalid_item"},
		{"duplicate_root", `{"encrypted":false,"encrypted":false,"items":[]}`, "duplicate_json_key"},
		{"duplicate_item", `{"encrypted":false,"items":[{"type":1,"name":"x","name":"y"}]}`, "duplicate_json_key"},
		{"duplicate_unknown_nested", `{"encrypted":false,"items":[],"opaque":{"KeySentinel":0,"KeySentinel":1}}`, "duplicate_json_key"},
		{"decoded_key_collision", `{"encrypted":false,"items":[],"opaque":{"KeySentinel":0,"\u004beySentinel":1}}`, "duplicate_json_key"},
		{"malformed", `{"encrypted":false,"items":[}`, "invalid_json"},
		{"trailing_document", `{"encrypted":false,"items":[]} {}`, "invalid_json"},
		{"trailing_garbage", `{"encrypted":false,"items":[]} xyz`, "invalid_json"},
		{"invalid_utf8", "{\"encrypted\":false,\"items\":[],\"x\":\"\xff\"}", "invalid_utf8"},
		{"unpaired_high_password", `{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":"\uD800"}}]}`, "invalid_json"},
		{"unpaired_low_password", `{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":"\uDC00"}}]}`, "invalid_json"},
		{"unpaired_high_key", `{"encrypted":false,"items":[],"\uD800":0}`, "invalid_json"},
		{"high_then_non_surrogate", `{"encrypted":false,"items":[],"x":"\uD800\u0041"}`, "invalid_json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireSafeCode(t, []byte(tc.data), BitwardenJSON, tc.code) })
	}
}

func TestBitwardenValidSurrogatePairAndLiteralEscape(t *testing.T) {
	d := mustParse(t, []byte(`{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":"\uD83D\uDD10","username":"\\uD800"}}]}`), BitwardenJSON)
	login := d.bitwardenRoot["items"].([]any)[0].(map[string]any)["login"].(map[string]any)
	if login["password"] != "🔐" || login["username"] != `\uD800` {
		t.Fatal("valid Unicode or literal escaped text changed")
	}
}

func TestBitwardenLimits(t *testing.T) {
	t.Run("input_bytes", func(t *testing.T) {
		requireSafeCode(t, bytes.Repeat([]byte{' '}, MaxInputBytes+1), BitwardenJSON, "input_limit")
	})
	t.Run("depth_boundary", func(t *testing.T) {
		data := `{"encrypted":false,"items":[],"deep":` + strings.Repeat("[", MaxJSONDepth-1) + "null" + strings.Repeat("]", MaxJSONDepth-1) + "}"
		d := mustParse(t, []byte(data), BitwardenJSON)
		if d.Inspect().MetadataFields != 3 {
			t.Fatal("deep field count changed")
		}
		data = `{"encrypted":false,"items":[],"deep":` + strings.Repeat("[", MaxJSONDepth) + "null" + strings.Repeat("]", MaxJSONDepth) + "}"
		requireSafeCode(t, []byte(data), BitwardenJSON, "depth_limit")
	})
	t.Run("record_boundary", func(t *testing.T) {
		item := `{"type":1,"name":""}`
		data := `{"encrypted":false,"items":[` + strings.Repeat(item+",", MaxRecords-1) + item + "]}"
		d := mustParse(t, []byte(data), BitwardenJSON)
		if d.Inspect().Records != MaxRecords || d.Inspect().Fields != MaxRecords*2 {
			t.Fatal("record boundary count changed")
		}
		data = `{"encrypted":false,"items":[` + strings.Repeat(item+",", MaxRecords) + item + "]}"
		requireSafeCode(t, []byte(data), BitwardenJSON, "record_limit")
	})
	t.Run("field_boundary", func(t *testing.T) {
		data := `{"encrypted":false,"items":[],"bulk":[` + strings.Repeat("0,", MaxFields-3) + "0]}"
		d := mustParse(t, []byte(data), BitwardenJSON)
		if d.Inspect().MetadataFields != MaxFields {
			t.Fatal("metadata field boundary count changed")
		}
		data = `{"encrypted":false,"items":[],"bulk":[` + strings.Repeat("0,", MaxFields-2) + "0]}"
		requireSafeCode(t, []byte(data), BitwardenJSON, "field_limit")
	})
	t.Run("combined_metadata_and_items", func(t *testing.T) {
		data := `{"encrypted":false,"bulk":[` + strings.Repeat("0,", MaxFields-3) + `0],"items":[{"type":1,"name":""}]}`
		requireSafeCode(t, []byte(data), BitwardenJSON, "field_limit")
	})
}

func TestBitwardenJSONContainerBoundary(t *testing.T) {
	// The root object, empty items array, and metadata array contribute three
	// containers independently of the empty-object leaves and their field count.
	for _, tc := range []struct {
		name                 string
		containers, metadata int
		reject               bool
	}{
		{"below", 249999, 249998, false},
		{"at", 250000, 249999, false},
		{"over", 250001, 250000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaves := tc.containers - 3
			data := []byte(`{"encrypted":false,"items":[],"forest":[` + strings.Repeat("{},", leaves-1) + "{}]}")
			if tc.reject {
				requireSafeCode(t, data, BitwardenJSON, "container_limit")
				return
			}
			inv := mustParse(t, data, BitwardenJSON).Inspect()
			if inv.Records != 0 || inv.Fields != 0 || inv.MetadataFields != tc.metadata {
				t.Fatal("container budget changed source-field accounting")
			}
		})
	}
}

func TestBitwardenCompactDeepForestContainerLimit(t *testing.T) {
	// Each independent branch adds sixty nonempty objects but only one field.
	// Depth is 62 including the envelope and array; source remains below 2 MiB.
	chain := strings.Repeat(`{"x":`, 60) + "0" + strings.Repeat("}", 60)
	for _, tc := range []struct {
		name               string
		branches, metadata int
		reject             bool
	}{
		{"below_budget", 4096, 4098, false},
		{"over_budget", 4167, 4169, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"encrypted":false,"items":[],"forest":[` + strings.Repeat(chain+",", tc.branches-1) + chain + "]}")
			if len(data) > 2<<20 {
				t.Fatal("deep-forest regression exceeds its bounded fixture size")
			}
			if tc.reject {
				requireSafeCode(t, data, BitwardenJSON, "container_limit")
				return
			}
			inv := mustParse(t, data, BitwardenJSON).Inspect()
			if inv.Records != 0 || inv.Fields != 0 || inv.MetadataFields != tc.metadata {
				t.Fatal("deep-forest field accounting changed")
			}
		})
	}
}

func TestContainerLimitErrorUsesFixedCode(t *testing.T) {
	if got := (&SafeError{Code: "container_limit"}).Error(); got != "container_limit" {
		t.Fatal("new fixed code was not retained safely")
	}
}
