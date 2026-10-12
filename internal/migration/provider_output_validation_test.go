package migration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func providerOutputExpected(t *testing.T, literal string) []mappedRecord {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(literal))
	d.UseNumber()
	var values []map[string]any
	if err := d.Decode(&values); err != nil {
		t.Fatal("invalid synthetic expected literal")
	}
	mapped := make([]mappedRecord, len(values))
	for i, value := range values {
		mapped[i].value = value
	}
	return mapped
}

func providerOutputParsed(t *testing.T, format Format, items string) *Document {
	t.Helper()
	var data []byte
	switch format {
	case BitwardenJSON:
		data = []byte(`{"encrypted":false,"items":` + items + `}`)
	case OnePassword1PUX:
		data = onePasswordZIP(t, onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":`+items+`}]}]}`, nil)
	case ProtonPassZIP:
		var output bytes.Buffer
		w := zip.NewWriter(&output)
		entry, err := w.Create("Proton Pass/data.json")
		if err != nil {
			t.Fatal("synthetic ZIP create")
		}
		if _, err := entry.Write([]byte(`{"version":"1.42.0","vaults":{"synthetic":{"name":"Imported","items":` + items + `}}}`)); err != nil {
			t.Fatal("synthetic ZIP write")
		}
		if err := w.Close(); err != nil {
			t.Fatal("synthetic ZIP close")
		}
		data = output.Bytes()
	}
	d, err := Parse(data, format)
	if err != nil {
		t.Fatal("synthetic output parse failed")
	}
	return d
}

func providerOutputRequireFailure(t *testing.T, mapped []mappedRecord, parsed *Document) {
	t.Helper()
	err := validateProviderOutput(mapped, parsed)
	if safe, ok := err.(*SafeError); !ok || safe.Code != "output_validation" || safe.Error() != "output_validation" {
		t.Fatal("modified output accepted or error unsafe")
	}
}

func TestProviderOutputValidationBitwardenExactValuesAndOrder(t *testing.T) {
	const expected = `[{"type":1,"name":"first","login":{"username":"  user  ","password":"  pass\r\nlast  "},"opaque":{"array":["x","x"],"empty":[],"object":{},"null":null,"n":900719925474099312345}},{"type":2,"name":"second","notes":"literal\\n\r\n"}]`
	mapped := providerOutputExpected(t, expected)
	if err := validateProviderOutput(mapped, providerOutputParsed(t, BitwardenJSON, expected)); err != nil {
		t.Fatal("exact literal output rejected")
	}
	for _, tc := range []struct{ name, items string }{
		{"whitespace", strings.Replace(expected, `  user  `, `user`, 1)},
		{"key", strings.Replace(expected, `"array"`, `"Array"`, 1)},
		{"count", `[{"type":1,"name":"first","login":{"username":"  user  ","password":"  pass\r\nlast  "},"opaque":{"array":["x","x"],"empty":[],"object":{},"null":null,"n":900719925474099312345}}]`},
		{"order", `[{"type":2,"name":"second","notes":"literal\\n\r\n"},{"type":1,"name":"first","login":{"username":"  user  ","password":"  pass\r\nlast  "},"opaque":{"array":["x","x"],"empty":[],"object":{},"null":null,"n":900719925474099312345}}]`},
		{"type", strings.Replace(expected, `"type":1`, `"type":2`, 1)},
		{"duplicate", strings.Replace(expected, `{"type":2,"name":"second","notes":"literal\\n\r\n"}`, `{"type":1,"name":"first","login":{"username":"  user  ","password":"  pass\r\nlast  "},"opaque":{"array":["x","x"],"empty":[],"object":{},"null":null,"n":900719925474099312345}}`, 1)},
		{"omission", strings.Replace(expected, `,"notes":"literal\\n\r\n"`, ``, 1)},
		{"array_multiplicity", strings.Replace(expected, `["x","x"]`, `["x"]`, 1)},
		{"empty_array_to_null", strings.Replace(expected, `"empty":[]`, `"empty":null`, 1)},
		{"empty_object_added_value", strings.Replace(expected, `"object":{}`, `"object":{"extra":false}`, 1)},
		{"empty_object_to_array", strings.Replace(expected, `"object":{}`, `"object":[]`, 1)},
		{"null_omission", strings.Replace(expected, `,"null":null`, ``, 1)},
		{"precision", strings.Replace(expected, `900719925474099312345`, `900719925474099312346`, 1)},
		{"extra", strings.Replace(expected, `"empty":[]`, `"empty":[],"extra":true`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			providerOutputRequireFailure(t, mapped, providerOutputParsed(t, BitwardenJSON, tc.items))
		})
	}
}

func TestProviderOutputValidationOnlyIntegerRepresentationBridged(t *testing.T) {
	mapped := providerOutputExpected(t, `[{"type":1,"name":"synthetic","opaque":{"integer":9007199254740993,"decimal":1.00,"negativeZero":-0}}]`)
	opaque := mapped[0].value["opaque"].(map[string]any)
	opaque["integer"] = int64(9007199254740993)
	const actual = `[{"type":1,"name":"synthetic","opaque":{"integer":9007199254740993,"decimal":1.00,"negativeZero":-0}}]`
	if err := validateProviderOutput(mapped, providerOutputParsed(t, BitwardenJSON, actual)); err != nil {
		t.Fatal("exact int64-to-wire integer rejected")
	}
	for _, modified := range []string{strings.Replace(actual, `1.00`, `1.0`, 1), strings.Replace(actual, `9007199254740993`, `9007199254740992`, 1), strings.Replace(actual, `"negativeZero":-0`, `"negativeZero":0`, 1)} {
		providerOutputRequireFailure(t, mapped, providerOutputParsed(t, BitwardenJSON, modified))
	}
}

func TestProviderOutputValidationOnePasswordDocumentedDefaults(t *testing.T) {
	mapped := providerOutputExpected(t, `[{"categoryUuid":"003","overview":{"title":"  note  "},"details":{}},{"categoryUuid":"003","overview":{"title":"  note  "},"details":{}}]`)
	const actual = `[{"categoryUuid":"003","overview":{"title":"  note  ","subtitle":"","url":""},"details":{},"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":0,"updatedAt":0,"favIndex":0,"state":"active"},{"categoryUuid":"003","overview":{"title":"  note  ","subtitle":"","url":""},"details":{},"uuid":"bbbbbbbbbbbbbbbbbbbbbbbbbb","createdAt":0,"updatedAt":0,"favIndex":0,"state":"active"}]`
	if err := validateProviderOutput(mapped, providerOutputParsed(t, OnePassword1PUX, actual)); err != nil {
		t.Fatal("documented defaults or duplicate items rejected")
	}
	for _, modified := range []string{strings.Replace(actual, `"url":""`, `"url":"ChangedSentinel"`, 1), strings.Replace(actual, `"state":"active"`, `"state":"archived"`, 1), strings.Replace(actual, `"createdAt":0`, `"createdAt":1`, 1), strings.Replace(actual, `bbbbbbbbbbbbbbbbbbbbbbbbbb`, `aaaaaaaaaaaaaaaaaaaaaaaaaa`, 1), strings.Replace(actual, `"details":{}`, `"details":{"notesPlain":""}`, 1)} {
		providerOutputRequireFailure(t, mapped, providerOutputParsed(t, OnePassword1PUX, modified))
	}
}

func TestProviderOutputValidationProtonWrapperExact(t *testing.T) {
	mapped := providerOutputExpected(t, `[{"data":{"type":"note","metadata":{"name":"synthetic","note":"  literal  ","itemUuid":""},"content":{},"extraFields":[]},"state":1,"createTime":1728000000,"modifyTime":1728000001}]`)
	mapped[0].value["createTime"] = int64(1728000000)
	const actual = `[{"data":{"type":"note","metadata":{"name":"synthetic","note":"  literal  ","itemUuid":""},"content":{},"extraFields":[]},"state":1,"createTime":1728000000,"modifyTime":1728000001,"itemId":"pwmigrate-item-1","shareId":"pwmigrate-vault-1"}]`
	if err := validateProviderOutput(mapped, providerOutputParsed(t, ProtonPassZIP, actual)); err != nil {
		t.Fatal("Proton documented wrapper output rejected")
	}
	for _, modified := range []string{strings.Replace(actual, `1728000000`, `1728000001`, 1), strings.Replace(actual, `pwmigrate-item-1`, `pwmigrate-item-2`, 1), strings.Replace(actual, `"extraFields":[]`, `"extraFields":[{"fieldName":"x","type":"text","data":{"content":"x"}}]`, 1)} {
		providerOutputRequireFailure(t, mapped, providerOutputParsed(t, ProtonPassZIP, modified))
	}
}

func TestProviderOutputValidationNeverOverridesMappedDefaultKeys(t *testing.T) {
	mapped := providerOutputExpected(t, `[{"categoryUuid":"003","overview":{"title":"synthetic","subtitle":"mapped"},"details":{},"favIndex":3}]`)
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, OnePassword1PUX, `[{"categoryUuid":"003","overview":{"title":"synthetic","subtitle":"","url":""},"details":{},"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":0,"updatedAt":0,"favIndex":0,"state":"active"}]`))
	mapped = providerOutputExpected(t, `[{"data":{"type":"note","metadata":{"name":"synthetic"},"content":{}},"itemId":"mapped-source-id"}]`)
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, ProtonPassZIP, `[{"data":{"type":"note","metadata":{"name":"synthetic"},"content":{}},"itemId":"pwmigrate-item-1","shareId":"pwmigrate-vault-1"}]`))
}

func TestProviderOutputValidationInvalidSnapshotsFailClosed(t *testing.T) {
	providerOutputRequireFailure(t, nil, nil)
	providerOutputRequireFailure(t, []mappedRecord{{value: nil}}, providerOutputParsed(t, BitwardenJSON, `[{"type":1,"name":"synthetic"}]`))
	providerOutputRequireFailure(t, nil, &Document{format: ChromeCSV})
}

func TestProviderOutputValidationDefaultsStayAtSchemaLocations(t *testing.T) {
	mapped := providerOutputExpected(t, `[{"categoryUuid":"003","overview":{"title":"synthetic"},"details":{"opaque":{"value":"exact"}}}]`)
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, OnePassword1PUX, `[{"categoryUuid":"003","overview":{"title":"synthetic","subtitle":"","url":""},"details":{"opaque":{"value":"exact","state":"active"}},"uuid":"aaaaaaaaaaaaaaaaaaaaaaaaaa","createdAt":0,"updatedAt":0,"favIndex":0,"state":"active"}]`))
	mapped = providerOutputExpected(t, `[{"type":1,"name":"synthetic","favorite":false,"opaque":{"value":"exact"}}]`)
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, BitwardenJSON, `[{"type":1,"name":"synthetic","favorite":false,"opaque":{"value":"exact"},"state":"active"}]`))
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, BitwardenJSON, `[{"type":1,"name":"synthetic","favorite":true,"opaque":{"value":"exact"}}]`))
}

func TestProviderOutputValidationEmptyExportsAndCanonicalInt(t *testing.T) {
	for _, format := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
		if err := validateProviderOutput(nil, providerOutputParsed(t, format, `[]`)); err != nil {
			t.Fatal("empty generated export rejected")
		}
	}
	mapped := providerOutputExpected(t, `[{"type":1,"name":"synthetic","opaque":{"integer":1}}]`)
	mapped[0].value["opaque"].(map[string]any)["integer"] = int(1)
	if err := validateProviderOutput(mapped, providerOutputParsed(t, BitwardenJSON, `[{"type":1,"name":"synthetic","opaque":{"integer":1}}]`)); err != nil {
		t.Fatal("canonical integer wire token rejected")
	}
	providerOutputRequireFailure(t, mapped, providerOutputParsed(t, BitwardenJSON, `[{"type":1,"name":"synthetic","opaque":{"integer":1.0}}]`))
}
