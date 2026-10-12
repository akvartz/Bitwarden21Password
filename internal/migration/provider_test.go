package migration

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestProviderStrictJSONAndDeterministicPrivatePaths(t *testing.T) {
	for _, text := range []string{`{"x":1,"x":2}`, `{"x":"\ud800"}`, `{} {}`, `{"x":"` + string([]byte{0xff}) + `"}`} {
		if _, err := parseStrictJSON([]byte(text)); err == nil {
			t.Fatal("unsafe JSON accepted")
		}
	}
	v, err := parseStrictJSON([]byte(`{"z":[],"a/b":{"~":null},"arr":[" exact ",{}],"n":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	f := flattenFields(v, "")
	want := []sourceField{{"/a~1b/~0", nil}, {"/arr/0", " exact "}, {"/arr/1", map[string]any{}}, {"/n", json.Number("9007199254740993")}, {"/z", []any{}}}
	if !reflect.DeepEqual(f, want) {
		t.Fatal("field ordinals or exact values changed")
	}
}

func TestProviderRejectsAmplifiedPrivateFieldPaths(t *testing.T) {
	data := []byte(`{"` + strings.Repeat("x", 65536) + `":[` + strings.Repeat(`0,`, 1024) + `0]}`)
	if _, err := parseStrictJSON(data); err == nil {
		t.Fatal("private path amplification accepted")
	}
}

func TestBitwardenPrivateProviderSnapshotRetainsAllFieldsAndFolders(t *testing.T) {
	d := mustParse(t, []byte(`{"encrypted":false,"folders":[{"id":"synthetic-folder","name":"SYNTHETIC_LABEL"}],"items":[{"type":1,"name":"SYNTHETIC_TITLE","folderId":"synthetic-folder","login":{"password":" exact \r\n"},"opaque":[]}],"unknown":null}`), BitwardenJSON)
	if d.provider == nil || len(d.provider.records) != 1 {
		t.Fatal("complete private snapshot missing")
	}
	r := d.provider.records[0]
	if r.folder != 1 || r.vault != 1 || d.provider.folderCount != 1 || d.provider.vaultCount != 1 {
		t.Fatal("relationships unaccounted")
	}
	if len(r.fields) != 5 || len(d.provider.metadata) != 4 || r.kind != "login" {
		t.Fatal("private field inventory incomplete")
	}
	if r.value["login"].(map[string]any)["password"] != " exact \r\n" {
		t.Fatal("credential changed")
	}
}
