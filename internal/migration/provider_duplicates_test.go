package migration

import (
	"bytes"
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
)

// Literal source fixtures are independent of the provider writers and duplicate
// detector. Unfamiliar content participates even when a destination cannot map it.
var providerDuplicateFixtures = []struct {
	format      Format
	item        string
	id, created string
	modified    string
}{
	{BitwardenJSON, `{"type":1,"name":"DUPLICATE_PRIVATE_TITLE","login":{"username":" user Ω ","password":"DUPLICATE_PRIVATE_PASSWORD\r\n","uris":[{"uri":"https://synthetic.invalid/1"},{"uri":"https://synthetic.invalid/2"}]},"fields":[{"name":"private custom","value":"DUPLICATE_PRIVATE_VALUE","type":0}],"opaque":{"large":900719925474099312345,"empty":[],"null":null}}`, "id", "creationDate", "revisionDate"},
	{OnePassword1PUX, `{"categoryUuid":"001","overview":{"title":"DUPLICATE_PRIVATE_TITLE","urls":[{"url":"https://synthetic.invalid/1"},{"url":"https://synthetic.invalid/2"}]},"details":{"loginFields":[{"designation":"username","value":" user Ω "},{"designation":"password","value":"DUPLICATE_PRIVATE_PASSWORD\r\n"}],"opaque":{"large":900719925474099312345,"empty":[],"null":null,"custom":"DUPLICATE_PRIVATE_VALUE"}}}`, "uuid", "createdAt", "updatedAt"},
	{ProtonPassZIP, `{"data":{"type":"login","metadata":{"name":"DUPLICATE_PRIVATE_TITLE"},"content":{"itemUsername":" user Ω ","password":"DUPLICATE_PRIVATE_PASSWORD\r\n","urls":["https://synthetic.invalid/1","https://synthetic.invalid/2"]},"extraFields":[{"fieldName":"private custom","type":"hidden","data":{"content":"DUPLICATE_PRIVATE_VALUE"}}]},"state":1,"pinned":false,"opaque":{"large":900719925474099312345,"empty":[],"null":null}}`, "itemId", "createTime", "modifyTime"},
}

func providerDuplicatesParse(t *testing.T, format Format, items ...string) *Document {
	t.Helper()
	joined := strings.Join(items, ",")
	switch format {
	case BitwardenJSON:
		return mustParse(t, []byte(`{"encrypted":false,"items":[`+joined+`]}`), format)
	case OnePassword1PUX:
		return mustParse(t, onePasswordZIP(t, onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[`+joined+`]}]}]}`, nil), format)
	case ProtonPassZIP:
		return mustParse(t, protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.42.0","vaults":{"synthetic":{"name":"synthetic","items":[` + joined + `]}}}`)}), format)
	}
	t.Fatal("unknown synthetic fixture format")
	return nil
}

func providerDuplicatesRawItem(t *testing.T, item string) map[string]any {
	t.Helper()
	parsed, err := parseStrictJSON([]byte(item))
	if err != nil {
		t.Fatal("invalid synthetic fixture")
	}
	return parsed.(map[string]any)
}

func providerDuplicatesJSON(t *testing.T, item map[string]any) string {
	t.Helper()
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatal("invalid synthetic fixture")
	}
	return string(data)
}

func TestProviderDuplicatesFlagExactRawContentInSourceOrderAndSelectedPlans(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			variant := strings.Replace(fixture.item, "DUPLICATE_PRIVATE_PASSWORD", "DUPLICATE_DIFFERENT_PASSWORD", 1)
			d := providerDuplicatesParse(t, fixture.format, fixture.item, variant, fixture.item, variant, fixture.item)
			inv := d.Inspect()
			if inv.Records != 5 || inv.DuplicateDetection != "exact_provider_content_v1" || !reflect.DeepEqual(inv.DuplicateGroups, [][]int{{1, 3, 5}, {2, 4}}) {
				t.Fatal("provider duplicate candidates missing, merged, or out of source order")
			}
			if !slices.Contains(inv.Caveats, "provider_duplicate_candidates_exact_content_only") {
				t.Fatal("conservative duplicate detection scope was undisclosed")
			}
			for _, target := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
				if target == fixture.format {
					continue
				}
				for _, tc := range []struct {
					selected []int
					want     [][]int
				}{
					{nil, [][]int{{1, 3, 5}, {2, 4}}},
					{[]int{5, 1, 4}, [][]int{{1, 5}}},
					{[]int{4, 2, 3}, [][]int{{2, 4}}},
					{[]int{3, 4}, [][]int{}},
				} {
					plan, err := d.Plan(target, tc.selected)
					if err != nil || !reflect.DeepEqual(plan.DuplicateGroups, tc.want) {
						t.Fatal("selected provider plan lost original ordinals or retained a singleton group")
					}
				}
			}
		})
	}
}

func TestProviderDuplicatesIgnoreOnlyWellTypedNativeIdentityAndTimestamps(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			left := providerDuplicatesRawItem(t, fixture.item)
			right := providerDuplicatesRawItem(t, fixture.item)
			left[fixture.id], right[fixture.id] = "synthetic-first-id", "synthetic-second-id"
			if fixture.format == BitwardenJSON {
				left[fixture.created], right[fixture.created] = "2026-10-11T00:00:00Z", "2026-10-12T12:34:56.000000001-04:00"
				left[fixture.modified], right[fixture.modified] = "2026-10-11T01:00:00Z", "2026-10-12T13:34:56Z"
			} else {
				left[fixture.created], right[fixture.created] = json.Number("0"), json.Number("1791763200")
				left[fixture.modified], right[fixture.modified] = json.Number("1"), json.Number("1791763201")
			}
			if fixture.format == ProtonPassZIP {
				left["data"].(map[string]any)["metadata"].(map[string]any)["itemUuid"] = "synthetic-first-uuid"
				right["data"].(map[string]any)["metadata"].(map[string]any)["itemUuid"] = "synthetic-second-uuid"
			}
			for _, item := range []string{providerDuplicatesJSON(t, left), providerDuplicatesJSON(t, right)} {
				d := providerDuplicatesParse(t, fixture.format, fixture.item, item)
				if !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 2}}) {
					t.Fatal("valid native identity or timestamps prevented exact content candidate flagging")
				}
			}
			d := providerDuplicatesParse(t, fixture.format, providerDuplicatesJSON(t, left), providerDuplicatesJSON(t, right))
			if !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 2}}) {
				t.Fatal("different native bookkeeping prevented candidate flagging")
			}
		})
	}
}

func TestProviderDuplicatesRetainMalformedAndAbsentNullBookkeeping(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			for _, value := range []any{nil, "", " leading ", "unicode-Ω", json.Number("9"), []any{}, map[string]any{"unknown": "DUPLICATE_PRIVATE_VALUE"}} {
				item := providerDuplicatesRawItem(t, fixture.item)
				item[fixture.id] = value
				d := providerDuplicatesParse(t, fixture.format, fixture.item, providerDuplicatesJSON(t, item))
				if len(d.Inspect().DuplicateGroups) != 0 {
					t.Fatal("malformed native identity or absent/null distinction was ignored")
				}
			}
			for _, field := range []string{fixture.created, fixture.modified} {
				values := []any{json.Number("-1"), json.Number("253402300800"), json.Number("900719925474099312345")}
				if fixture.format != ProtonPassZIP {
					values = append(values, nil, "", "2026-99-99T00:00:00Z", "not a date", json.Number("1.0"))
					if fixture.format == BitwardenJSON {
						values = append(values, "2026-10-12T1:00:00Z", "2026-10-12T01:00:00,1Z", "2026-10-12T01:00:00.1234567890Z", "2026-10-12T01:00:00+24:00", "2026-10-12T01:00:00+00:60")
					}
				}
				for _, value := range values {
					item := providerDuplicatesRawItem(t, fixture.item)
					item[field] = value
					d := providerDuplicatesParse(t, fixture.format, fixture.item, providerDuplicatesJSON(t, item))
					if len(d.Inspect().DuplicateGroups) != 0 {
						t.Fatal("malformed timestamp or absent/null distinction was ignored")
					}
				}
			}
		})
	}
}

func TestProviderDuplicatesRetainEveryMeaningfulUnknownValueAndArrayOrder(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			mutations := []func(map[string]any){
				func(item map[string]any) { item["unknown"] = nil },
				func(item map[string]any) { item["unknown"] = []any{} },
				func(item map[string]any) { item["unknown"] = map[string]any{} },
				func(item map[string]any) { item["unknown"] = json.Number("1.0") },
				func(item map[string]any) { item["folderId"] = "synthetic-folder" },
				func(item map[string]any) { item["organizationId"] = "synthetic-organization" },
				func(item map[string]any) { item["collectionIds"] = []any{"synthetic-collection"} },
				func(item map[string]any) { item["shareId"] = "synthetic-share" },
				func(item map[string]any) { item["deletedDate"] = nil },
				func(item map[string]any) {
					item["custom"] = map[string]any{fixture.id: "synthetic-id", fixture.created: json.Number("1")}
				},
			}
			for _, mutate := range mutations {
				item := providerDuplicatesRawItem(t, fixture.item)
				mutate(item)
				d := providerDuplicatesParse(t, fixture.format, fixture.item, providerDuplicatesJSON(t, item))
				if len(d.Inspect().DuplicateGroups) != 0 {
					t.Fatal("provider duplicate rule ignored meaningful relationships, states, or unknown content")
				}
			}
			for _, variant := range []string{
				strings.Replace(fixture.item, "DUPLICATE_PRIVATE_PASSWORD", "DUPLICATE_DIFFERENT_PASSWORD", 1),
				strings.Replace(fixture.item, "DUPLICATE_PRIVATE_VALUE", "DUPLICATE_DIFFERENT_VALUE", 1),
				strings.Replace(fixture.item, " user Ω ", "user Ω", 1),
				strings.Replace(fixture.item, `"empty":[]`, `"empty":null`, 1),
				strings.Replace(fixture.item, `"large":900719925474099312345`, `"large":900719925474099312346`, 1),
			} {
				d := providerDuplicatesParse(t, fixture.format, fixture.item, variant)
				if len(d.Inspect().DuplicateGroups) != 0 {
					t.Fatal("exact provider duplicate rule normalized a meaningful private value")
				}
			}
			item := providerDuplicatesRawItem(t, fixture.item)
			var ordered []any
			switch fixture.format {
			case BitwardenJSON:
				item["type"] = json.Number("2")
				ordered = item["login"].(map[string]any)["uris"].([]any)
			case OnePassword1PUX:
				item["categoryUuid"] = "003"
				ordered = item["overview"].(map[string]any)["urls"].([]any)
			case ProtonPassZIP:
				item["data"].(map[string]any)["type"] = "note"
				ordered = item["data"].(map[string]any)["content"].(map[string]any)["urls"].([]any)
			}
			d := providerDuplicatesParse(t, fixture.format, fixture.item, providerDuplicatesJSON(t, item))
			if len(d.Inspect().DuplicateGroups) != 0 {
				t.Fatal("duplicate detection conflated provider item kinds")
			}
			// Compare the same changed kind while reversing its meaningful array.
			before := providerDuplicatesJSON(t, item)
			ordered[0], ordered[1] = ordered[1], ordered[0]
			d = providerDuplicatesParse(t, fixture.format, before, providerDuplicatesJSON(t, item))
			if len(d.Inspect().DuplicateGroups) != 0 {
				t.Fatal("duplicate detection reordered a meaningful array")
			}
			// Object key order has no JSON value semantics.
			d = providerDuplicatesParse(t, fixture.format, fixture.item, providerDuplicatesJSON(t, providerDuplicatesRawItem(t, fixture.item)))
			if !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 2}}) {
				t.Fatal("object key serialization order prevented an exact candidate")
			}
		})
	}
}

func TestProviderDuplicatesOwnReportsAndReviewApprovalSnapshot(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			d := providerDuplicatesParse(t, fixture.format, fixture.item, fixture.item, fixture.item)
			target := BitwardenJSON
			if fixture.format == BitwardenJSON {
				target = OnePassword1PUX
			}
			before := bytes.Clone(d.source)
			rawBefore, err := json.Marshal(d.provider.root)
			if err != nil {
				t.Fatal("invalid owned source")
			}
			inv := d.Inspect()
			if len(inv.DuplicateGroups) != 1 {
				t.Fatal("provider duplicates missing")
			}
			inv.DuplicateGroups[0][0] = 999
			plan, err := d.Plan(target, []int{3, 1})
			if err != nil || !reflect.DeepEqual(plan.DuplicateGroups, [][]int{{1, 3}}) {
				t.Fatal("selected duplicate snapshot unavailable")
			}
			plan.DuplicateGroups[0][0] = 998
			again, err := d.Plan(target, nil)
			if err != nil || !reflect.DeepEqual(again.DuplicateGroups, [][]int{{1, 2, 3}}) || !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 2, 3}}) {
				t.Fatal("public duplicate group mutation changed document")
			}
			for _, report := range []any{d.Inspect(), again} {
				encoded, err := json.Marshal(report)
				if err != nil || strings.Contains(string(encoded), "DUPLICATE_PRIVATE") || strings.Contains(string(encoded), "synthetic.invalid") || strings.Contains(string(encoded), "900719925474099312345") {
					t.Fatal("duplicate detection exposed private source content")
				}
			}
			rawAfter, err := json.Marshal(d.provider.root)
			if err != nil || !bytes.Equal(rawBefore, rawAfter) || !bytes.Equal(before, d.source) {
				t.Fatal("duplicate inspection or planning mutated original source")
			}
			if !protectedoutput.Supported() {
				return
			}
			selection := []int{3, 1}
			job, err := d.NewJob(target, selection, t.TempDir())
			if err != nil {
				t.Fatal("provider review snapshot unavailable")
			}
			selection[0] = 2
			review := job.Review()
			if !reflect.DeepEqual(review.Plan.DuplicateGroups, [][]int{{1, 3}}) {
				t.Fatal("job changed selected duplicate snapshot")
			}
			ids := make([]string, len(review.Issues))
			for i, issue := range review.Issues {
				ids[i] = issue.ID
			}
			review.Plan.DuplicateGroups[0][0] = 997
			if !reflect.DeepEqual(job.Review().Plan.DuplicateGroups, [][]int{{1, 3}}) || job.Approve(review.ReviewID, ids) != nil || job.State() != "approved" {
				t.Fatal("duplicate report mutation changed one-shot approval snapshot")
			}
		})
	}
}

func TestProviderDuplicatesBoundedLargeGroupWithoutPairwiseComparison(t *testing.T) {
	const records = 20000
	for _, fixture := range providerDuplicateFixtures {
		t.Run(string(fixture.format), func(t *testing.T) {
			items := make([]string, records)
			for i := range items {
				items[i] = fixture.item
			}
			d := providerDuplicatesParse(t, fixture.format, items...)
			inv := d.Inspect()
			if inv.Records != records || len(inv.DuplicateGroups) != 1 || len(inv.DuplicateGroups[0]) != records || inv.DuplicateGroups[0][0] != 1 || inv.DuplicateGroups[0][records-1] != records {
				t.Fatal("large provider source did not retain all candidate ordinals")
			}
		})
	}
}

func TestProviderDuplicatesKeepNativeVaultAndFolderRelationships(t *testing.T) {
	for _, fixture := range providerDuplicateFixtures {
		if fixture.format == BitwardenJSON {
			continue
		}
		t.Run(string(fixture.format), func(t *testing.T) {
			items := fixture.item + "," + fixture.item
			var source []byte
			if fixture.format == OnePassword1PUX {
				source = onePasswordZIP(t, onePasswordAttrs, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[`+items+`]}]},{"attrs":{},"vaults":[{"attrs":{},"items":[`+items+`]}]}]}`, nil)
			} else {
				source = protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.42.0","vaults":{"z":{"name":"synthetic","items":[` + items + `]},"a":{"name":"synthetic","items":[` + items + `]}}}`)})
			}
			d := mustParse(t, source, fixture.format)
			if !reflect.DeepEqual(d.Inspect().DuplicateGroups, [][]int{{1, 2}, {3, 4}}) {
				t.Fatal("native vault or account relationships were removed from duplicate predicate")
			}
		})
	}
	item := providerDuplicatesRawItem(t, providerDuplicateFixtures[0].item)
	groups, err := providerDuplicateGroups(BitwardenJSON, []providerRecord{
		{value: item, vault: 1, folder: 1}, {value: item, vault: 1, folder: 2},
		{value: item, vault: 1, folder: 1}, {value: item, vault: 1, folder: 2},
	})
	if err != nil || !reflect.DeepEqual(groups, [][]int{{1, 3}, {2, 4}}) {
		t.Fatal("native folder relationship was removed from duplicate predicate")
	}
}

func TestProviderDuplicatesNeverUseSemanticSSHComparisonKeys(t *testing.T) {
	pkcs8, openSSH, public, fingerprint := onePasswordSSHTestValues(t, onePasswordSSHTestKey(t))
	for _, format := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
		t.Run(string(format), func(t *testing.T) {
			items := make([]string, 2)
			for i, private := range []string{pkcs8, openSSH} {
				var item map[string]any
				switch format {
				case BitwardenJSON:
					item = map[string]any{"type": json.Number("5"), "name": "synthetic", "sshKey": map[string]any{"privateKey": private, "publicKey": public, "keyFingerprint": fingerprint}}
				case OnePassword1PUX:
					item = map[string]any{"categoryUuid": "114", "overview": map[string]any{"title": "synthetic"}, "details": map[string]any{"sections": []any{map[string]any{"fields": []any{map[string]any{"value": map[string]any{"sshKey": map[string]any{"privateKey": private}}}}}}}}
				case ProtonPassZIP:
					item = map[string]any{"data": map[string]any{"type": "sshKey", "metadata": map[string]any{"name": "synthetic"}, "content": map[string]any{"privateKey": private, "publicKey": public, "sections": []any{}}}}
				}
				items[i] = providerDuplicatesJSON(t, item)
			}
			d := providerDuplicatesParse(t, format, items...)
			if len(d.Inspect().DuplicateGroups) != 0 {
				t.Fatal("exact content duplicate rule normalized SSH private representations")
			}
		})
	}
}
