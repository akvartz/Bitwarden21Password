package migration

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func mustPlan(t *testing.T, d *Document, target Format, selection []int) Plan {
	t.Helper()
	plan, err := d.Plan(target, selection)
	if err != nil {
		t.Fatalf("Plan failed with safe code: %v", err)
	}
	return plan
}

func TestPlanAccountsForEveryCellAndEvidence(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,note,CustomNameSentinel\na,b,c,d,e,ValueSentinel\n"), ChromeCSV)
	got := mustPlan(t, d, BitwardenJSON, nil)
	want := []FieldDisposition{
		{Record: 1, Field: 1, Disposition: "native", TargetField: "name"},
		{Record: 1, Field: 2, Disposition: "native", TargetField: "login.uris[0].uri"},
		{Record: 1, Field: 3, Disposition: "native", TargetField: "login.username"},
		{Record: 1, Field: 4, Disposition: "native", TargetField: "login.password"},
		{Record: 1, Field: 5, Disposition: "native", TargetField: "notes"},
		{Record: 1, Field: 6, Disposition: "relocated", TargetField: "fields", Concealed: true},
	}
	if !reflect.DeepEqual(got.Fields, want) {
		t.Fatal("not every field received exactly its expected disposition")
	}
	if got.Source != ChromeCSV || got.Target != BitwardenJSON || got.State != "planned" || got.TotalRecords != 1 || got.SelectedRecords != 1 || got.ExcludedRecords != 0 || got.OutputEmitted || got.DestinationImportVerified {
		t.Fatal("plan counts or evidence levels are incorrect")
	}
}

func TestChromeDuplicatesKeepDifferentPasswords(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\nsame,url,user,first\nsame,url,user,second\nother,url,user,third\nsame,url,user,fourth\n"), ChromeCSV)
	inv := d.Inspect()
	if inv.Records != 4 || !reflect.DeepEqual(inv.DuplicateGroups, [][]int{{1, 2, 4}}) {
		t.Fatal("suspected duplicates were merged or grouped incorrectly")
	}
	plan := mustPlan(t, d, BitwardenJSON, []int{4, 2})
	if !reflect.DeepEqual(plan.DuplicateGroups, [][]int{{2, 4}}) || plan.SelectedRecords != 2 || plan.ExcludedRecords != 2 || len(plan.Fields) != 8 {
		t.Fatal("selection did not preserve duplicate multiplicity")
	}
	if len(mustPlan(t, d, BitwardenJSON, []int{1, 3}).DuplicateGroups) != 0 {
		t.Fatal("singleton duplicate groups remained after selection")
	}
}

func TestDuplicateGroupsDoNotConflateConcatenatedValues(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\na,bc,d,p\nab,c,d,p\na,bc,d,q\n"), ChromeCSV)
	if !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 3}}) {
		t.Fatal("duplicate key concatenation conflated distinct tuples")
	}
}

func TestPlanSelectionUsesSourceOrder(t *testing.T) {
	d := mustParse(t, []byte("password,username,url,name\np1,u1,l1,n1\np2,u2,l2,n2\np3,u3,l3,n3\n"), ChromeCSV)
	plan := mustPlan(t, d, BitwardenJSON, []int{3, 1})
	if plan.TotalRecords != 3 || plan.SelectedRecords != 2 || plan.ExcludedRecords != 1 || len(plan.Fields) != 8 {
		t.Fatal("selection counts changed")
	}
	for i, field := range plan.Fields {
		wantRecord := 1
		if i >= 4 {
			wantRecord = 3
		}
		if field.Record != wantRecord || field.Field != i%4+1 {
			t.Fatal("source record/column order changed")
		}
	}
	if plan.Fields[0].TargetField != "login.password" || plan.Fields[3].TargetField != "name" {
		t.Fatal("mapping used column position instead of normalized schema name")
	}
}

func TestPlanRejectsInvalidSelectionsAndRoutes(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\na,b,c,d\ne,f,g,h\n"), ChromeCSV)
	for _, selection := range [][]int{{}, {0}, {-1}, {3}, {1, 1}} {
		_, err := d.Plan(BitwardenJSON, selection)
		var safe *SafeError
		if !errors.As(err, &safe) || safe.Code != "invalid_selection" {
			t.Fatal("invalid selection did not return its safe code")
		}
	}
	for _, target := range []Format{ChromeCSV, "", Format("TargetSentinel")} {
		_, err := d.Plan(target, nil)
		var safe *SafeError
		if !errors.As(err, &safe) || safe.Code != "unsupported_route" {
			t.Fatal("unsupported target did not fail safely")
		}
	}
	bw := mustParse(t, []byte(`{"encrypted":false,"items":[]}`), BitwardenJSON)
	_, err := bw.Plan(BitwardenJSON, nil)
	var safe *SafeError
	if !errors.As(err, &safe) || safe.Code != "unsupported_route" {
		t.Fatal("unsupported source route did not fail safely")
	}
	empty := mustParse(t, []byte("name,url,username,password\n"), ChromeCSV)
	if plan := mustPlan(t, empty, BitwardenJSON, nil); plan.SelectedRecords != 0 || len(plan.Fields) != 0 {
		t.Fatal("empty export plan acquired fields")
	}
}

func TestInputAndReportMutationCannotChangeDocument(t *testing.T) {
	data := []byte("name,url,username,password\nsame,url,user,first\nsame,url,user,second\nother,url,user,third\n")
	d := mustParse(t, data, ChromeCSV)
	wantInventory := d.Inspect()
	wantPlan := mustPlan(t, d, BitwardenJSON, nil)
	for i := range data {
		data[i] = 'x'
	}
	if bytes.Equal(d.source, data) || d.chromeRows[0][3] != "first" {
		t.Fatal("caller input mutation changed private source data")
	}
	inventory := d.Inspect()
	inventory.Kinds["login"] = -1
	inventory.Kinds["SourceNameSentinel"] = 7
	inventory.DuplicateGroups[0][0] = 999
	inventory.DuplicateGroups = append(inventory.DuplicateGroups, []int{999, 998})
	inventory.Caveats[0] = "SourceValueSentinel"
	if !reflect.DeepEqual(d.Inspect(), wantInventory) {
		t.Fatal("inventory mutation changed document state")
	}
	plan := mustPlan(t, d, BitwardenJSON, nil)
	plan.Fields[0].TargetField = "SourceValueSentinel"
	plan.DuplicateGroups[0][0] = 999
	plan.Caveats[0] = "SourceValueSentinel"
	if !reflect.DeepEqual(mustPlan(t, d, BitwardenJSON, nil), wantPlan) {
		t.Fatal("plan mutation changed document state")
	}
	selection := []int{3, 1}
	selected := mustPlan(t, d, BitwardenJSON, selection)
	selection[0] = 2
	if selected.Fields[4].Record != 3 {
		t.Fatal("selection mutation changed returned plan")
	}
	bwData := []byte(`{"encrypted":false,"items":[{"type":1,"name":"safe","login":{"password":"original"}}]}`)
	bw := mustParse(t, bwData, BitwardenJSON)
	for i := range bwData {
		bwData[i] = 'x'
	}
	if bw.bitwardenRoot["items"].([]any)[0].(map[string]any)["login"].(map[string]any)["password"] != "original" {
		t.Fatal("caller input mutation changed retained JSON")
	}
}

func TestEveryPublicReportAndInputErrorIsRedacted(t *testing.T) {
	const sentinel = "DistinctiveSyntheticSentinel"
	chrome := mustParse(t, []byte("name,url,username,password,note,"+sentinel+"Custom\n"+strings.Repeat(sentinel+",", 5)+sentinel+"\n"), ChromeCSV)
	bw := mustParse(t, []byte(`{"encrypted":false,"items":[{"type":42,"name":"`+sentinel+`","opaque":{"`+sentinel+`Custom":"`+sentinel+`"}}],"`+sentinel+`Root":"`+sentinel+`"}`), BitwardenJSON)
	plan := mustPlan(t, chrome, BitwardenJSON, nil)
	for _, report := range []any{chrome.Inspect(), bw.Inspect(), plan, plan.Fields[5], chrome, bw} {
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal("public report failed to marshal")
		}
		if bytes.Contains(data, []byte(sentinel)) {
			t.Fatal("source value or arbitrary label leaked into public DTO")
		}
	}
	for _, input := range []struct {
		data   string
		format Format
	}{
		{"name,url,username,password," + sentinel + "," + sentinel + "\n", ChromeCSV},
		{"name,url,username,password\n" + sentinel + "\"\n", ChromeCSV},
		{`{"encrypted":false,"items":[{"type":"` + sentinel + `","name":"` + sentinel + `"}]}`, BitwardenJSON},
		{`{"encrypted":false,"items":[],"` + sentinel + `":0,"` + sentinel + `":1}`, BitwardenJSON},
		{"name,url,username,password\n", Format(sentinel)},
	} {
		_, err := Parse([]byte(input.data), input.format)
		if err == nil {
			t.Fatal("invalid input unexpectedly accepted")
		}
		encoded, marshalErr := json.Marshal(err)
		if marshalErr != nil || strings.Contains(err.Error(), sentinel) || bytes.Contains(encoded, []byte(sentinel)) {
			t.Fatal("error leaked source data")
		}
	}
	for _, code := range []string{"unknown_format", "unsupported_encrypted", "unsupported_route", "invalid_utf8", "invalid_json", "duplicate_json_key", "invalid_csv", "duplicate_header", "empty_header", "missing_header", "uneven_row", "invalid_item", "invalid_selection", "input_limit", "record_limit", "field_limit", "depth_limit", "column_limit", sentinel} {
		err := &SafeError{Code: code, Record: 2, Column: 3}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("arbitrary SafeError code appeared in Error output")
		}
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal("plan failed to marshal")
	}
	for _, expected := range []string{`"state":"planned"`, `"output_emitted":false`, `"destination_import_verified":false`, `"metadata_fields"`} {
		data := encoded
		if expected == `"metadata_fields"` {
			data, _ = json.Marshal(chrome.Inspect())
		}
		if !bytes.Contains(data, []byte(expected)) {
			t.Fatal("public report JSON contract is incomplete")
		}
	}
}
