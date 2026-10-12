package migration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// These synthetic native export literals are independent of the writer.
const protonLiteralExport = `{"version":"1.31.0","userId":"synthetic-user","vaults":{"z":{"name":"second","description":"","display":{"color":0,"icon":0},"items":[{"itemId":"b","shareId":"z","data":{"type":"note","metadata":{"name":" note ","note":"body\r\n","itemUuid":"uuid-b"},"content":{},"extraFields":[]},"state":1,"pinned":false,"contentFormatVersion":6}]},"a":{"name":"first","items":[{"itemId":"a","shareId":"a","data":{"type":"login","metadata":{"name":" login ","note":" \n ","itemUuid":"uuid-a"},"content":{"itemUsername":" user ","itemEmail":" email ","password":" secret\r\n ","totpUri":" seed ","urls":[" https://synthetic.invalid/ "]},"extraFields":[]},"state":1,"pinned":true,"files":[],"future":{"hidden":" unknown "}}]}}}`

func protonTestZIP(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, content := range entries {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestProtonNativeZIPInventoryAndExactValues(t *testing.T) {
	d, err := parseProton(protonTestZIP(t, map[string][]byte{
		"Proton Pass/data.json":     []byte(protonLiteralExport),
		"Proton Pass/files/file-id": []byte("synthetic attachment"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.records) != 2 || d.records[0].kind != "login" || d.records[1].kind != "secure_note" || d.records[0].vault != 1 || d.records[1].vault != 2 {
		t.Fatal("record order, types, or vault ordinals changed")
	}
	content := d.records[0].value["data"].(map[string]any)["content"].(map[string]any)
	if content["password"] != " secret\r\n " || content["itemUsername"] != " user " || content["itemEmail"] != " email " {
		t.Fatal("credential bytes changed")
	}
	if d.records[0].value["future"].(map[string]any)["hidden"] != " unknown " {
		t.Fatal("unfamiliar source data disappeared")
	}
	if string(d.files["Proton Pass/files/file-id"]) != "synthetic attachment" || len(d.metadata) == 0 {
		t.Fatal("archive or metadata inventory disappeared")
	}
	for _, field := range d.metadata {
		if field.path == "/vaults/a/items/0/data/content/password" {
			t.Fatal("record credentials duplicated into metadata")
		}
	}
}

func TestProtonRejectsEncryptedAmbiguousAndMalformedNativeData(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries map[string][]byte
		code    string
	}{
		{"encrypted", map[string][]byte{"Proton Pass/data.pgp": []byte("ciphertext")}, "unsupported_encrypted"},
		{"ambiguous", map[string][]byte{"Proton Pass/data.pgp": []byte("ciphertext"), "Proton Pass/data.json": []byte(protonLiteralExport)}, "invalid_archive"},
		{"missing", map[string][]byte{"unrelated": []byte("private label")}, "invalid_archive"},
		{"duplicate", map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.31.0","version":"private label","vaults":{}}`)}, "duplicate_json_key"},
		{"malformeditem", map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.31.0","vaults":{"v":{"name":"v","items":[{"data":{"type":"login","metadata":{"name":"n"},"content":{"password":7}}}]}}}`)}, "invalid_item"},
		{"root", map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.31.0","vaults":[]}`)}, "invalid_json"},
		{"customcredential", map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.31.0","vaults":{"v":{"name":"v","items":[{"data":{"type":"note","metadata":{"name":"n"},"content":{},"extraFields":[{"fieldName":"f","type":"hidden","data":{"content":7}}]}}]}}}`)}, "invalid_item"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := parseProton(protonTestZIP(t, tc.entries))
			var safe *SafeError
			if d != nil || !errors.As(err, &safe) || safe.Code != tc.code || bytes.Contains([]byte(err.Error()), []byte("private label")) {
				t.Fatal("unsafe parse result")
			}
		})
	}
}

func TestProtonPreservesUnfamiliarTypeAsUnknown(t *testing.T) {
	d, err := parseProton(protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.31.0","vaults":{"v":{"name":"v","items":[{"data":{"type":"future-secret","metadata":{"name":"n"},"content":{"private":"value"}}}]}}}`)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.records) != 1 || d.records[0].kind != "unknown" || d.records[0].value["data"].(map[string]any)["type"] != "future-secret" {
		t.Fatal("unfamiliar type was reinterpreted")
	}
}

func TestProtonWriterUsesNativeArchiveAndVersionedLiteralSchema(t *testing.T) {
	item := map[string]any{"data": map[string]any{"type": "note", "metadata": map[string]any{"name": " title ", "note": " body\r\n ", "itemUuid": "synthetic-uuid"}, "content": map[string]any{}, "extraFields": []any{}}, "state": json.Number("1"), "pinned": false}
	payload, err := exportProton([]map[string]any{item})
	if err != nil {
		t.Fatal(err)
	}
	r, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.File) != 1 || r.File[0].Name != "Proton Pass/data.json" || r.File[0].Mode().Perm() != 0600 {
		t.Fatal("unexpected archive member or mode")
	}
	f, err := r.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	native, err := io.ReadAll(f)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("unable to read synthetic output")
	}
	var root map[string]any
	if err := json.Unmarshal(native, &root); err != nil {
		t.Fatal(err)
	}
	if root["version"] != "1.42.0" || root["userId"] != nil {
		t.Fatal("wrong versioned native envelope")
	}
	vault := root["vaults"].(map[string]any)["pwmigrate-vault-1"].(map[string]any)
	if vault["name"] != "Imported" || len(vault["items"].([]any)) != 1 {
		t.Fatal("native vault/item layout changed")
	}
	metadata := vault["items"].([]any)[0].(map[string]any)["data"].(map[string]any)["metadata"].(map[string]any)
	if metadata["name"] != " title " || metadata["note"] != " body\r\n " {
		t.Fatal("writer changed exact credential-adjacent strings")
	}
}

func TestProtonWriterEscapingAndContainerLimitFailBeforeOutput(t *testing.T) {
	item := map[string]any{"data": map[string]any{"type": "note", "metadata": map[string]any{"name": "n", "note": strings.Repeat("<", maxOutputBytes/6+1)}, "content": map[string]any{}, "extraFields": []any{}}}
	output, err := exportProton([]map[string]any{item})
	var safe *SafeError
	if output != nil || !errors.As(err, &safe) || safe.Code != "output_limit" {
		t.Fatal("escaped output amplification did not fail closed")
	}
}

func TestProtonEmptyVaultsAndFolderOrdinalsAreInventoried(t *testing.T) {
	literal := `{"version":"1.42.0","vaults":{"b":{"name":"empty","items":[]},"a":{"name":"with-folders","folders":[{"folderId":"f2","parentFolderId":null,"name":"second"},{"folderId":"f1","parentFolderId":"f2","name":"first"}],"items":[{"folderId":"f1","data":{"type":"note","metadata":{"name":"n"},"content":{}}}]}}}`
	d, err := parseProton(protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": []byte(literal)}))
	if err != nil {
		t.Fatal(err)
	}
	if d.vaultCount != 2 || d.folderCount != 2 || len(d.records) != 1 || d.records[0].vault != 1 || d.records[0].folder != 2 {
		t.Fatal("empty vault or source-order folder ordinal disappeared")
	}
	found := false
	for _, field := range d.metadata {
		if field.path == "/vaults/b/items" {
			found = true
		}
	}
	if !found {
		t.Fatal("empty native source container was not inventoried")
	}
}
