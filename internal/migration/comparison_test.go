package migration

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func comparisonChrome(t *testing.T, rows string) *Document {
	t.Helper()
	return mustParse(t, []byte("name,url,username,password\n"+rows), ChromeCSV)
}

func comparisonBitwarden(t *testing.T, items string) *Document {
	t.Helper()
	return mustParse(t, []byte(`{"encrypted":false,"items":[`+items+`]}`), BitwardenJSON)
}

const comparisonItem = `{"type":1,"name":"synthetic-private-name","login":{"username":" synthetic-user ","password":" synthetic-password ","uris":[{"uri":"synthetic-private-url"}]},"fields":[]}`
const comparisonRow = "synthetic-private-name,synthetic-private-url, synthetic-user , synthetic-password \n"

func TestComparisonUsesIndependentDestinationAndRedactedDTO(t *testing.T) {
	source := comparisonChrome(t, comparisonRow)
	destination := comparisonBitwarden(t, `{"id":"synthetic-private-id","creationDate":"synthetic-private-date","revisionDate":"different-private-date","type":1,"name":"synthetic-private-name","login":{"username":" synthetic-user ","password":" synthetic-password ","uris":[{"uri":"synthetic-private-url"}]},"fields":[]}`)
	report, err := source.Compare(BitwardenJSON, nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	if report.State != "destination_compared" || report.MatchedRecords != 1 || report.MissingRecords != 0 || report.UnexpectedRecords != 0 || report.DestinationImportVerified {
		t.Fatal("comparison misrepresented supplied re-export evidence")
	}
	if len(report.Groups) != 1 || report.Groups[0].Code != "matched" || len(report.DestinationUnobservableFields) != 3 {
		t.Fatal("bookkeeping observation was not separately accounted")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"synthetic-private", "synthetic-user", "synthetic-password", "different-private", "hash", "fingerprint"} {
		if strings.Contains(string(encoded), text) {
			t.Fatal("comparison leaked private values or fingerprints")
		}
	}
}

func TestComparisonKeepsDuplicateMultiplicityAndAmbiguousMatches(t *testing.T) {
	source := comparisonChrome(t, comparisonRow+comparisonRow)
	for _, tc := range []struct {
		items                        string
		matched, missing, unexpected int
		dest                         []int
	}{
		{comparisonItem, 1, 1, 0, []int{1}},
		{comparisonItem + "," + comparisonItem, 2, 0, 0, []int{1, 2}},
		{comparisonItem + "," + comparisonItem + "," + comparisonItem, 2, 0, 1, []int{1, 2, 3}},
	} {
		report, err := source.Compare(BitwardenJSON, nil, comparisonBitwarden(t, tc.items))
		if err != nil {
			t.Fatal(err)
		}
		if report.MatchedRecords != tc.matched || report.MissingRecords != tc.missing || report.UnexpectedRecords != tc.unexpected || len(report.Groups) != 1 {
			t.Fatal("duplicate multiplicity changed")
		}
		g := report.Groups[0]
		if g.Code != "ambiguous_match" || !reflect.DeepEqual(g.SourceRecords, []int{1, 2}) || !reflect.DeepEqual(g.DestinationRecords, tc.dest) {
			t.Fatal("comparison assigned an arbitrary duplicate identity")
		}
	}
}

func TestComparisonPreservesAbsentNullEmptyAndExactCredentials(t *testing.T) {
	source := comparisonChrome(t, comparisonRow)
	for _, item := range []string{
		strings.Replace(comparisonItem, `"fields":[]`, `"fields":null`, 1),
		strings.Replace(comparisonItem, `,"fields":[]`, "", 1),
		strings.Replace(comparisonItem, `"password":" synthetic-password "`, `"password":"synthetic-password"`, 1),
		strings.Replace(comparisonItem, `"type":1`, `"type":1,"notes":""`, 1),
		strings.Replace(comparisonItem, `"type":1`, `"type":1,"notes":null`, 1),
	} {
		report, err := source.Compare(BitwardenJSON, nil, comparisonBitwarden(t, item))
		if err != nil {
			t.Fatal(err)
		}
		if report.MatchedRecords != 0 || report.MissingRecords != 1 || report.UnexpectedRecords != 1 {
			t.Fatal("comparison normalized a meaningful difference")
		}
	}
}

func TestComparisonUsesSelectedSourceOrderAndOwnsReports(t *testing.T) {
	source := comparisonChrome(t, comparisonRow+"other,other,other,other\n"+comparisonRow)
	report, err := source.Compare(BitwardenJSON, []int{3, 1}, comparisonBitwarden(t, comparisonItem))
	if err != nil {
		t.Fatal(err)
	}
	if report.ExpectedRecords != 2 || !reflect.DeepEqual(report.Groups[0].SourceRecords, []int{1, 3}) {
		t.Fatal("comparison changed selected source ordinals")
	}
	report.Groups[0].SourceRecords[0] = 99
	again, err := source.Compare(BitwardenJSON, []int{1}, comparisonBitwarden(t, comparisonItem))
	if err != nil || !reflect.DeepEqual(again.Groups[0].SourceRecords, []int{1}) {
		t.Fatal("report mutation changed source")
	}
}

func TestComparisonFailsSafelyForWrongDestinationsAndSelection(t *testing.T) {
	source := comparisonChrome(t, comparisonRow)
	for _, tc := range []struct {
		target      Format
		destination *Document
	}{
		{BitwardenJSON, nil}, {BitwardenJSON, source}, {Format("synthetic-private-unknown-format"), source},
	} {
		_, err := source.Compare(tc.target, nil, tc.destination)
		requireErrorCode(t, err, "unsupported_route")
	}
	for _, selected := range [][]int{{}, {0}, {2}, {1, 1}} {
		_, err := source.Compare(BitwardenJSON, selected, comparisonBitwarden(t, comparisonItem))
		requireErrorCode(t, err, "invalid_selection")
	}
}

func TestComparisonEmptyWholeExportAndUnsupportedItem(t *testing.T) {
	empty := comparisonChrome(t, "")
	report, err := empty.Compare(BitwardenJSON, nil, comparisonBitwarden(t, ""))
	if err != nil || report.ExpectedRecords != 0 || report.DestinationRecords != 0 || len(report.Groups) != 0 {
		t.Fatal("empty whole export comparison failed")
	}
	unsupported := comparisonBitwarden(t, `{"type":5,"name":"synthetic","sshKey":{"privateKey":"synthetic-private-key"}}`)
	_, err = unsupported.Compare(OnePassword1PUX, nil, &Document{format: OnePassword1PUX, provider: &providerData{}})
	requireErrorCode(t, err, "unsupported_route")
}

func TestComparisonAccountsForUnsupportedSourceFieldOrdinals(t *testing.T) {
	d := &Document{format: BitwardenJSON, provider: &providerData{records: []providerRecord{{fields: []sourceField{
		{path: "/name"}, {path: "/private-unknown"}, {path: "/id"}, {path: "/omitted"}, {path: "/missing"},
	}}}}}
	item := mappedRecord{mappings: map[string]fieldMapping{
		"/name":            {disposition: "native", target: "name"},
		"/private-unknown": {disposition: "unsupported"},
		"/id":              {disposition: "native", target: "id"},
		"/omitted":         {disposition: "omitted"},
	}}
	got := d.comparisonUnobservable(BitwardenJSON, 1, item)
	want := []ComparisonField{
		{1, 2, "source_field_unobservable"}, {1, 3, "provider_metadata_unobservable"},
		{1, 4, "source_field_unobservable"}, {1, 5, "source_field_unobservable"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("unsupported or bookkeeping source data implied observed")
	}
}

func TestComparisonProjectionKeepsMeaningfulProviderAndCustomFields(t *testing.T) {
	for _, tc := range []struct {
		format      Format
		left, right string
		equal       bool
	}{
		{OnePassword1PUX, `{"uuid":"old","createdAt":1,"updatedAt":2,"overview":{"title":"exact","ainfo":"old display"},"details":{}}`, `{"uuid":"new","createdAt":3,"updatedAt":4,"overview":{"title":"exact","ainfo":"new display"},"details":{}}`, true},
		{OnePassword1PUX, `{"overview":{"title":"exact"},"state":"active"}`, `{"overview":{"title":"exact"},"state":"archived"}`, false},
		{ProtonPassZIP, `{"itemId":"old","shareId":"old","createTime":1,"data":{"metadata":{"itemUuid":"old","name":"exact"},"content":{}}}`, `{"itemId":"new","shareId":"new","createTime":2,"data":{"metadata":{"itemUuid":"new","name":"exact"},"content":{}}}`, true},
		{ProtonPassZIP, `{"data":{"metadata":{"name":"exact"}},"state":1,"pinned":false}`, `{"data":{"metadata":{"name":"exact"}},"state":0,"pinned":false}`, false},
		{ProtonPassZIP, `{"data":{"metadata":{"name":"exact"}},"state":1,"pinned":false}`, `{"data":{"metadata":{"name":"exact"}},"state":1,"pinned":true}`, false},
		{BitwardenJSON, `{"name":"exact","fields":[{"name":"id","value":"old"}]}`, `{"name":"exact","fields":[{"name":"id","value":"new"}]}`, false},
		{BitwardenJSON, `{"name":"exact","deletedDate":null}`, `{"name":"exact","deletedDate":"synthetic date"}`, false},
		{ProtonPassZIP, `{"data":{"metadata":{"name":"exact"}},"future":[]}`, `{"data":{"metadata":{"name":"exact"}},"future":{}}`, false},
		{ProtonPassZIP, `{"data":{"metadata":{"name":"exact"}},"future":1}`, `{"data":{"metadata":{"name":"exact"}},"future":1.0}`, false},
	} {
		left, err := parseStrictJSON([]byte(tc.left))
		if err != nil {
			t.Fatal(err)
		}
		right, err := parseStrictJSON([]byte(tc.right))
		if err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(left)
		if err != nil {
			t.Fatal(err)
		}
		a, err := comparisonKey(tc.format, left.(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		b, err := comparisonKey(tc.format, right.(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		if (a == b) != tc.equal {
			t.Fatal("projection normalized a meaningful value or retained provider bookkeeping")
		}
		after, err := json.Marshal(left)
		if err != nil || string(before) != string(after) {
			t.Fatal("projection mutated source tree")
		}
	}
}

func TestComparisonLargeDuplicateGroup(t *testing.T) {
	const records = 20000
	source := comparisonChrome(t, strings.Repeat("a,b,c,d\n", records))
	item := `{"type":1,"name":"a","login":{"username":"c","password":"d","uris":[{"uri":"b"}]},"fields":[]}`
	destination := comparisonBitwarden(t, strings.Repeat(item+",", records-1)+item)
	report, err := source.Compare(BitwardenJSON, nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	if report.MatchedRecords != records || len(report.Groups) != 1 || report.Groups[0].Code != "ambiguous_match" || len(report.Groups[0].SourceRecords) != records || len(report.Groups[0].DestinationRecords) != records {
		t.Fatal("large multiset did not retain all duplicate observations")
	}
}

func comparisonProtonSSHItem(private, public string) map[string]any {
	return map[string]any{"data": map[string]any{"type": "sshKey", "metadata": map[string]any{"name": "SYNTHETIC_SSH_TITLE"}, "content": map[string]any{"privateKey": private, "publicKey": public, "sections": []any{}}, "extraFields": []any{}}, "state": json.Number("1"), "pinned": false}
}

func TestComparisonProtonSSHCanonicalizesOnlyDeclaredPrivateField(t *testing.T) {
	// Encoding fixtures come from the public RFC8032 seed through stdlib/x/crypto
	// encoders, independently of provider mapping and comparison implementation.
	pkcs8, openSSH, public, _ := onePasswordSSHTestValues(t, onePasswordSSHTestKey(t))
	left := comparisonProtonSSHItem(pkcs8, public)
	right := comparisonProtonSSHItem(openSSH, public)
	before, err := json.Marshal(left)
	if err != nil {
		t.Fatal(err)
	}
	a, err := comparisonKey(ProtonPassZIP, left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := comparisonKey(ProtonPassZIP, right)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("declared Proton SSH private representations were not compared semantically")
	}
	after, err := json.Marshal(left)
	if err != nil || string(before) != string(after) {
		t.Fatal("semantic SSH comparison mutated owned input")
	}
	for _, kind := range []string{"login", "note", "future", "sshkey", "ssh_key"} {
		left := comparisonProtonSSHItem(pkcs8, public)
		right := comparisonProtonSSHItem(openSSH, public)
		left["data"].(map[string]any)["type"] = kind
		right["data"].(map[string]any)["type"] = kind
		a, err := comparisonKey(ProtonPassZIP, left)
		if err != nil {
			t.Fatal(err)
		}
		b, err := comparisonKey(ProtonPassZIP, right)
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatal("non-SSH source payload was reinterpreted as an SSH key")
		}
	}
}

func TestComparisonProtonSSHRetainsOtherMeaningfulValuesAndInvalidRepresentations(t *testing.T) {
	pkcs8, openSSH, public, _ := onePasswordSSHTestValues(t, onePasswordSSHTestKey(t))
	for _, mutate := range []func(map[string]any){
		func(item map[string]any) {
			item["data"].(map[string]any)["content"].(map[string]any)["publicKey"] = public + "exact extra comment"
		},
		func(item map[string]any) {
			item["data"].(map[string]any)["content"].(map[string]any)["unknown"] = map[string]any{"privateKey": pkcs8}
		},
		func(item map[string]any) { item["data"].(map[string]any)["content"].(map[string]any)["sections"] = nil },
		func(item map[string]any) { item["state"] = json.Number("0") },
		func(item map[string]any) { item["pinned"] = true },
	} {
		left := comparisonProtonSSHItem(pkcs8, public)
		right := comparisonProtonSSHItem(openSSH, public)
		mutate(right)
		a, err := comparisonKey(ProtonPassZIP, left)
		if err != nil {
			t.Fatal(err)
		}
		b, err := comparisonKey(ProtonPassZIP, right)
		if err != nil {
			t.Fatal(err)
		}
		if a == b {
			t.Fatal("SSH semantics erased another meaningful provider value")
		}
	}
	left := comparisonProtonSSHItem("invalid synthetic private\r\n", public)
	right := comparisonProtonSSHItem("invalid synthetic private", public)
	a, err := comparisonKey(ProtonPassZIP, left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := comparisonKey(ProtonPassZIP, right)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("unsupported private representation was silently normalized")
	}
	left = comparisonProtonSSHItem(pkcs8, public)
	right = comparisonProtonSSHItem(openSSH, public)
	left["data"].(map[string]any)["content"].(map[string]any)["unknown"] = map[string]any{"privateKey": pkcs8}
	right["data"].(map[string]any)["content"].(map[string]any)["unknown"] = map[string]any{"privateKey": openSSH}
	a, err = comparisonKey(ProtonPassZIP, left)
	if err != nil {
		t.Fatal(err)
	}
	b, err = comparisonKey(ProtonPassZIP, right)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("unknown nested private-key lookalike was semantically canonicalized")
	}
}

func TestComparisonProtonPrivateMappingMarksOriginalRepresentationUnobservable(t *testing.T) {
	d := &Document{format: BitwardenJSON, provider: &providerData{records: []providerRecord{{kind: "ssh_key", fields: []sourceField{{path: "/sshKey/privateKey"}, {path: "/sshKey/publicKey"}}}}}}
	item := mappedRecord{mappings: map[string]fieldMapping{
		"/sshKey/privateKey": {disposition: "native", target: "/data/content/privateKey"},
		"/sshKey/publicKey":  {disposition: "native", target: "/data/content/publicKey"},
	}}
	if got := d.comparisonUnobservable(ProtonPassZIP, 1, item); !reflect.DeepEqual(got, []ComparisonField{{1, 1, "ssh_original_representation_unobservable"}}) {
		t.Fatal("semantic SSH comparison implied original-byte preservation")
	}
}

func TestComparisonSSHPrivateObservationUsesDeclaredSourcePathsAcrossRoutes(t *testing.T) {
	for _, tc := range []struct {
		format Format
		path   string
		want   bool
	}{
		{BitwardenJSON, "/sshKey/privateKey", true},
		{BitwardenJSON, "/sshKey/publicKey", false},
		{BitwardenJSON, "/fields/0/privateKey", false},
		{ProtonPassZIP, "/data/content/privateKey", true},
		{ProtonPassZIP, "/data/content/publicKey", false},
		{ProtonPassZIP, "/data/content/sections/0/sectionFields/0/data/privateKey", false},
		{OnePassword1PUX, "/details/sections/0/fields/1/value/sshKey/privateKey", true},
		{OnePassword1PUX, "/details/sections/10/fields/0/value/sshKey/metadata/privateKey", true},
		{OnePassword1PUX, "/details/sections/0/fields/1/value/sshKey/metadata/keyType", false},
		{OnePassword1PUX, "/details/sections/0/fields/1/value/concealed/privateKey", false},
		{OnePassword1PUX, "/details/sections/-1/fields/1/value/sshKey/privateKey", false},
		{OnePassword1PUX, "/details/sections/00/fields/1/value/sshKey/privateKey", false},
		{OnePassword1PUX, "/details/sections/0/fields/x/value/sshKey/privateKey", false},
	} {
		for _, kind := range []string{"ssh_key", "unknown"} {
			d := &Document{format: tc.format, provider: &providerData{records: []providerRecord{{kind: kind, fields: []sourceField{{path: tc.path}}}}}}
			item := mappedRecord{mappings: map[string]fieldMapping{tc.path: {disposition: "transformed", target: "provider_item"}}}
			got := d.comparisonUnobservable(ProtonPassZIP, 1, item)
			want := []ComparisonField{}
			if tc.want && kind == "ssh_key" {
				want = append(want, ComparisonField{1, 1, "ssh_original_representation_unobservable"})
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("private representation observation did not follow declared schema and source kind")
			}
		}
	}
}

func comparisonProton(t *testing.T, items ...map[string]any) *Document {
	t.Helper()
	values := make([]any, len(items))
	for i := range items {
		values[i] = items[i]
	}
	root := map[string]any{"version": "1.42.0", "vaults": map[string]any{"synthetic-vault": map[string]any{"name": "SYNTHETIC_VAULT", "items": values}}}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	return mustParse(t, protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": data}), ProtonPassZIP)
}

func TestComparisonProtonSSHIndependentDestinationRetainsMultiplicityAndRedaction(t *testing.T) {
	pkcs8, openSSH, public, fingerprint := onePasswordSSHTestValues(t, onePasswordSSHTestKey(t))
	// The destination fixture follows the independently documented Proton SSH
	// schema; it is not produced by the mapper or generated output parser.
	sourceItem := map[string]any{"type": json.Number("5"), "name": "SYNTHETIC_SSH_TITLE", "sshKey": map[string]any{"privateKey": openSSH, "publicKey": public, "keyFingerprint": fingerprint}, "fields": []any{}}
	sourceBytes, err := json.Marshal(map[string]any{"encrypted": false, "items": []any{sourceItem, sourceItem}})
	if err != nil {
		t.Fatal(err)
	}
	source := mustParse(t, sourceBytes, BitwardenJSON)
	destinationItem := comparisonProtonSSHItem(pkcs8, public)
	data := destinationItem["data"].(map[string]any)
	data["metadata"].(map[string]any)["note"] = ""
	data["metadata"].(map[string]any)["itemUuid"] = "SYNTHETIC_DESTINATION_ID"
	data["content"].(map[string]any)["sections"] = []any{map[string]any{"sectionName": "Extra fields", "sectionFields": []any{map[string]any{"fieldName": "Key fingerprint", "type": "hidden", "data": map[string]any{"content": fingerprint}}}}}
	destinationItem["files"] = []any{}
	for _, count := range []int{1, 3} {
		items := make([]map[string]any, count)
		for i := range items {
			items[i] = destinationItem
		}
		report, err := source.Compare(ProtonPassZIP, nil, comparisonProton(t, items...))
		if err != nil {
			t.Fatal(err)
		}
		matched := min(count, 2)
		if report.MatchedRecords != matched || report.MissingRecords != 2-matched || report.UnexpectedRecords != count-matched || len(report.Groups) != 1 || report.Groups[0].Code != "ambiguous_match" || !reflect.DeepEqual(report.Groups[0].SourceRecords, []int{1, 2}) {
			t.Fatal("semantic SSH comparison changed multiplicity or implied duplicate pairing")
		}
		privateFields := 0
		for _, field := range report.SourceUnobservableFields {
			if field.Code == "ssh_original_representation_unobservable" {
				privateFields++
			}
		}
		if privateFields != 2 || report.DestinationImportVerified || !slices.Contains(report.Caveats, "ssh_private_key_representation_compared_semantically") {
			t.Fatal("SSH comparison implied original encoding or destination acceptance")
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, privateText := range []string{"SYNTHETIC_SSH_TITLE", "SYNTHETIC_DESTINATION_ID", "BEGIN PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY", "ssh-ed25519", fingerprint} {
			if strings.Contains(string(encoded), privateText) {
				t.Fatal("SSH comparison report exposed private provider data")
			}
		}
	}
}

func TestComparisonProtonSourceSSHPrivateRepresentationUnobservable(t *testing.T) {
	pkcs8, openSSH, public, fingerprint := onePasswordSSHTestValues(t, onePasswordSSHTestKey(t))
	item := comparisonProtonSSHItem(openSSH, public)
	item["data"].(map[string]any)["metadata"].(map[string]any)["note"] = ""
	source := comparisonProton(t, item)
	destinationBytes, err := json.Marshal(map[string]any{"encrypted": false, "items": []any{map[string]any{"type": json.Number("5"), "name": "SYNTHETIC_SSH_TITLE", "notes": "", "favorite": false, "deletedDate": nil, "fields": []any{}, "sshKey": map[string]any{"privateKey": pkcs8, "publicKey": public, "keyFingerprint": fingerprint}}}})
	if err != nil {
		t.Fatal(err)
	}
	report, err := source.Compare(BitwardenJSON, nil, mustParse(t, destinationBytes, BitwardenJSON))
	if err != nil {
		t.Fatal(err)
	}
	if report.MatchedRecords != 1 || report.MissingRecords != 0 || report.UnexpectedRecords != 0 {
		t.Fatal("independent Proton SSH private encoding did not compare semantically")
	}
	privateFields := 0
	for _, field := range report.SourceUnobservableFields {
		if field.Code == "ssh_original_representation_unobservable" {
			privateFields++
		}
	}
	if privateFields != 1 || !slices.Contains(report.Caveats, "ssh_private_key_representation_compared_semantically") {
		t.Fatal("native Proton private key comparison claimed original representation")
	}
}
