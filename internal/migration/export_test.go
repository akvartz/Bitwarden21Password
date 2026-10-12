package migration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func requireErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	safe, ok := err.(*SafeError)
	if !ok || safe.Code != code {
		t.Fatalf("expected safe code %s; got %v", code, err)
	}
}

func decodeLiteralJSON(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal("test JSON did not decode")
	}
	return value
}

func TestExportPreservesEveryLiteralCellAndOriginalCustomHeader(t *testing.T) {
	// Trimming, CRLF normalization, note-marker interpretation, and normalized
	// custom labels would each fail these independent literal expectations.
	d := mustParse(t, []byte(" Password ,USERNAME,URL, Name ,NoTe, CustomSentinelA ,É,é\r\n"+
		"\"  pass\r\nline\nlast  \",  user  ,https://example.invalid/é,  title Ω  ,\"---- pwmigrate extras ----\\nopaque\r\nnotes\",literal\\n,,Unicode Ω\r\n"), ChromeCSV)
	payload, err := exportChrome(d, []int{1})
	if err != nil {
		t.Fatalf("exact export failed with safe code: %v", err)
	}
	want := []byte(`{"encrypted":false,"folders":[],"items":[{"type":1,"name":"  title Ω  ","notes":"---- pwmigrate extras ----\\nopaque\r\nnotes","login":{"username":"  user  ","password":"  pass\r\nline\nlast  ","uris":[{"uri":"https://example.invalid/é"}]},"fields":[{"name":" CustomSentinelA ","value":"literal\\n","type":1},{"name":"É","value":"","type":1},{"name":"é","value":"Unicode Ω","type":1}]}]}`)
	if !reflect.DeepEqual(decodeLiteralJSON(t, payload), decodeLiteralJSON(t, want)) {
		t.Fatal("decoded output changed a cell, original label, or required structure")
	}
	if err := validateChromeExport(d, []int{1}, payload); err != nil {
		t.Fatalf("independent validation rejected exact output: %v", err)
	}
}

func TestExportDistinguishesAbsentNotesFromEmptyNotes(t *testing.T) {
	for _, tc := range []struct{ name, source, literal string }{
		{"absent", "name,url,username,password\n,,,\n", `{"encrypted":false,"folders":[],"items":[{"type":1,"name":"","login":{"username":"","password":"","uris":[{"uri":""}]},"fields":[]}]}`},
		{"empty", "name,url,username,password,note\n,,,,\n", `{"encrypted":false,"folders":[],"items":[{"type":1,"name":"","notes":"","login":{"username":"","password":"","uris":[{"uri":""}]},"fields":[]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, []byte(tc.source), ChromeCSV)
			payload, err := exportChrome(d, []int{1})
			if err != nil {
				t.Fatalf("export failed with safe code: %v", err)
			}
			if !reflect.DeepEqual(decodeLiteralJSON(t, payload), decodeLiteralJSON(t, []byte(tc.literal))) {
				t.Fatal("empty cells or absent notes changed")
			}
		})
	}
}

func TestExportPreservesDuplicateMultiplicityAndSelectedOrder(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\nsame,url,user,first\nother,url,user,excluded\nsame,url,user,third\n"), ChromeCSV)
	payload, err := exportChrome(d, []int{1, 3})
	if err != nil {
		t.Fatalf("export failed with safe code: %v", err)
	}
	want := []byte(`{"encrypted":false,"folders":[],"items":[{"type":1,"name":"same","login":{"username":"user","password":"first","uris":[{"uri":"url"}]},"fields":[]},{"type":1,"name":"same","login":{"username":"user","password":"third","uris":[{"uri":"url"}]},"fields":[]}]}`)
	if !reflect.DeepEqual(decodeLiteralJSON(t, payload), decodeLiteralJSON(t, want)) {
		t.Fatal("selected order or duplicate multiplicity changed")
	}
}

func TestExportValidatorRejectsStructuralAndCellTampering(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,note, Custom \nfirst,url,user,password,,value\nsecond,url,user,password,,value\n"), ChromeCSV)
	const original = `{"encrypted":false,"folders":[],"items":[{"type":1,"name":"first","notes":"","login":{"username":"user","password":"password","uris":[{"uri":"url"}]},"fields":[{"name":" Custom ","value":"value","type":1}]},{"type":1,"name":"second","notes":"","login":{"username":"user","password":"password","uris":[{"uri":"url"}]},"fields":[{"name":" Custom ","value":"value","type":1}]}]}`
	if err := validateChromeExport(d, []int{1, 2}, []byte(original)); err != nil {
		t.Fatalf("literal exact output rejected: %v", err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"credential", `"password":"password"`, `"password":"changed"`},
		{"name", `"name":"first"`, `"name":"second"`},
		{"notes_absent", `"notes":"",`, ``},
		{"notes_null", `"notes":""`, `"notes":null`},
		{"uri_absent", `"uris":[{"uri":"url"}]`, `"uris":[]`},
		{"uri_policy", `{"uri":"url"}`, `{"uri":"url","match":0}`},
		{"custom_label", `"name":" Custom "`, `"name":"custom"`},
		{"custom_type", `"value":"value","type":1`, `"value":"value","type":0`},
		{"custom_omitted", `"fields":[{"name":" Custom ","value":"value","type":1}]`, `"fields":[]`},
		{"extra_metadata", `"encrypted":false`, `"accountId":"invented","encrypted":false`},
		{"folders", `"folders":[]`, `"folders":[{}]`},
		{"encrypted", `"encrypted":false`, `"encrypted":true`},
		{"duplicate_key", `"encrypted":false`, `"encrypted":false,"encrypted":false`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(strings.Replace(original, tc.old, tc.replacement, 1))
			requireErrorCode(t, validateChromeExport(d, []int{1, 2}, payload), "output_validation")
		})
	}
	requireErrorCode(t, validateChromeExport(d, []int{2, 1}, []byte(original)), "output_validation")
	requireErrorCode(t, validateChromeExport(d, []int{1}, []byte(original)), "output_validation")
}

func TestExportLimitsHeaderAmplificationAndJSONEscaping(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"repeated_large_header", "name,url,username,password," + strings.Repeat("A", 1<<20) + "\n" + strings.Repeat("n,u,a,p,\n", 33)},
		{"control_expansion", "name,url,username,password\nn,u,a," + strings.Repeat("\x01", 6<<20) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, []byte(tc.source), ChromeCSV)
			selected := make([]int, len(d.chromeRows))
			for i := range selected {
				selected[i] = i + 1
			}
			payload, err := exportChrome(d, selected)
			requireErrorCode(t, err, "output_limit")
			if payload != nil {
				t.Fatal("output limit returned partial bytes")
			}
		})
	}
}

func TestExportEnforcesStrictParserContainerBudget(t *testing.T) {
	// Source has only 250,000 cells; each generated login adds six containers.
	d := mustParse(t, []byte("name,url,username,password,custom\n"+strings.Repeat("n,u,a,p,v\n", MaxRecords)), ChromeCSV)
	selected := make([]int, MaxRecords)
	for i := range selected {
		selected[i] = i + 1
	}
	payload, err := exportChrome(d, selected)
	requireErrorCode(t, err, "output_validation")
	if payload != nil {
		t.Fatal("strict output validation returned partial bytes")
	}
}

func TestExportEnforcesStrictParserCustomFieldAmplificationBudget(t *testing.T) {
	headers := []string{"name", "url", "username", "password"}
	for i := 0; i < 96; i++ {
		headers = append(headers, fmt.Sprintf("c%d", i))
	}
	d := mustParse(t, []byte(strings.Join(headers, ",")+"\n"+strings.Repeat(strings.Repeat("v,", 99)+"v\n", 3500)), ChromeCSV)
	selected := make([]int, 3500)
	for i := range selected {
		selected[i] = i + 1
	}
	payload, err := exportChrome(d, selected)
	requireErrorCode(t, err, "output_validation")
	if payload != nil {
		t.Fatal("strict output validation returned partial bytes")
	}
}

func TestExportEmptyDocumentUsesArraysAndNoRecords(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,custom\n"), ChromeCSV)
	payload, err := exportChrome(d, nil)
	if err != nil {
		t.Fatalf("empty export failed: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(payload), []byte(`{"encrypted":false,"folders":[],"items":[]}`)) {
		t.Fatal("empty output acquired records or null containers")
	}
}
