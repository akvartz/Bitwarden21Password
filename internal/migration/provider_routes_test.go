package migration

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/testsupport"
)

func TestProviderPlanAccountsForEverySelectedField(t *testing.T) {
	d := mustParse(t, []byte(`{"encrypted":false,"items":[{"type":1,"name":"SYNTHETIC_TITLE","login":{"username":" u ","password":" p \r\n"},"SYNTHETIC_UNKNOWN":"SYNTHETIC_VALUE"},{"type":99,"name":"SYNTHETIC_UNKNOWN_ITEM"}]}`), BitwardenJSON)
	p, err := d.Plan(OnePassword1PUX, []int{1})
	if err != nil {
		t.Fatal("rich route unavailable:", err)
	}
	if p.SelectedRecords != 1 || p.ExcludedRecords != 1 || len(p.Fields) != 5 {
		t.Fatal("selected field accounting incomplete")
	}
	for i, f := range p.Fields {
		if f.Record != 1 || f.Field != i+1 || f.Disposition == "" {
			t.Fatal("field disposition missing")
		}
	}
	if p.Fields[0].Disposition != "unsupported" {
		t.Fatal("unfamiliar field not reported")
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "SYNTHETIC_") {
		t.Fatal("private field exposed")
	}
}

func TestPublicProviderJobsPublishExactCredentialsOnQualifiedPlatforms(t *testing.T) {
	if !protectedoutput.Supported() {
		t.Skip("public protected output is not qualified on this platform")
	}
	sources := []struct {
		format Format
		data   []byte
	}{
		{BitwardenJSON, []byte(`{"encrypted":false,"items":[{"type":1,"name":"synthetic","login":{"username":" user ","password":" secret\r\n "}}]}`)},
		{OnePassword1PUX, onePasswordZIP(t, `{"version":3,"description":"1Password Unencrypted Export"}`, `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[{"categoryUuid":"001","overview":{"title":"synthetic"},"details":{"loginFields":[{"designation":"username","value":" user "},{"designation":"password","value":" secret\r\n "}]}}]}]}]}`, nil)},
		{ProtonPassZIP, protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1.42.0","vaults":{"synthetic":{"name":"synthetic","items":[{"data":{"type":"login","metadata":{"name":"synthetic"},"content":{"itemUsername":" user ","password":" secret\r\n "},"extraFields":[]},"state":1,"pinned":false}]}}}`)})},
	}
	for _, source := range sources {
		for _, target := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
			if source.format == target {
				continue
			}
			t.Run(string(source.format)+"_to_"+string(target), func(t *testing.T) {
				parent := testsupport.PrivateParent(t)
				document := mustParse(t, source.data, source.format)
				job, err := document.NewJob(target, nil, parent)
				if err != nil {
					t.Fatal("public provider job rejected")
				}
				approveJob(t, job)
				receipt, err := job.Commit(context.Background())
				if err != nil {
					t.Fatal("public provider job failed")
				}
				if receipt.Plan.State != "output_validated" || !receipt.Plan.OutputEmitted || receipt.Plan.DestinationImportVerified {
					t.Fatal("public job misrepresented platform or provider evidence")
				}
				path := filepath.Join(parent, receipt.JobDirectory, receipt.FileName)
				testsupport.AssertPrivate(t, filepath.Dir(path), true)
				testsupport.AssertPrivate(t, path, false)
				if publishedPassword(t, path, target) != " secret\r\n " {
					t.Fatal("public provider job changed exact credential bytes")
				}
				if _, err := job.Commit(context.Background()); err == nil {
					t.Fatal("public provider job replay accepted")
				}
			})
		}
	}
}

func publishedPassword(t *testing.T, path string, format Format) any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("published provider artifact unavailable")
	}
	if format != BitwardenJSON {
		archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
		if err != nil {
			t.Fatal("published provider archive invalid")
		}
		name := "export.data"
		if format == ProtonPassZIP {
			name = "Proton Pass/data.json"
		}
		present := false
		for _, file := range archive.File {
			if file.Name == name {
				reader, err := file.Open()
				if err != nil {
					t.Fatal("published native entry unavailable")
				}
				payload, err = io.ReadAll(reader)
				closeErr := reader.Close()
				if err != nil || closeErr != nil {
					t.Fatal("published native entry unreadable")
				}
				present = true
			}
		}
		if !present {
			t.Fatal("published native entry omitted")
		}
	}
	var root map[string]any
	if json.Unmarshal(payload, &root) != nil {
		t.Fatal("published native JSON invalid")
	}
	var items []any
	switch format {
	case BitwardenJSON:
		items, _ = root["items"].([]any)
	case OnePassword1PUX:
		accounts, _ := root["accounts"].([]any)
		if len(accounts) != 1 {
			t.Fatal("published account count changed")
		}
		account, _ := accounts[0].(map[string]any)
		vaults, _ := account["vaults"].([]any)
		if len(vaults) != 1 {
			t.Fatal("published vault count changed")
		}
		vault, _ := vaults[0].(map[string]any)
		items, _ = vault["items"].([]any)
	case ProtonPassZIP:
		vaults, _ := root["vaults"].(map[string]any)
		if len(vaults) != 1 {
			t.Fatal("published vault count changed")
		}
		for _, raw := range vaults {
			vault, _ := raw.(map[string]any)
			items, _ = vault["items"].([]any)
		}
	}
	if len(items) != 1 {
		t.Fatal("published record multiplicity changed")
	}
	item, _ := items[0].(map[string]any)
	switch format {
	case BitwardenJSON:
		login, _ := item["login"].(map[string]any)
		return login["password"]
	case ProtonPassZIP:
		data, _ := item["data"].(map[string]any)
		content, _ := data["content"].(map[string]any)
		return content["password"]
	case OnePassword1PUX:
		details, _ := item["details"].(map[string]any)
		fields, _ := details["loginFields"].([]any)
		for _, raw := range fields {
			field, _ := raw.(map[string]any)
			if field["designation"] == "password" {
				return field["value"]
			}
		}
	}
	return nil
}

func TestMixedBrowserSchemasRequireExplicitFormat(t *testing.T) {
	for _, header := range []string{"name,title,url,username,password,notes,otpauth\n", "name,url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n"} {
		_, err := Parse([]byte(header), "")
		var safe *SafeError
		if !errors.As(err, &safe) || safe.Code != "unknown_format" {
			t.Fatal("ambiguous browser schema accepted")
		}
		if _, err := Parse([]byte(header), ChromeCSV); err != nil {
			t.Fatal("explicit source should resolve schema")
		}
	}
}

func TestNativeBrowserProfilesKeepExactPasswordsAcrossProviderRoutes(t *testing.T) {
	fixtures := []struct {
		format Format
		data   string
	}{
		{FirefoxCSV, "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nhttps://synthetic.invalid, user ,\" secret\r\n \" ,realm,form,guid,1,2,3\n"},
		{SafariCSV, "Title,URL,Username,Password,Notes,OTPAuth\nSYNTHETIC_TITLE,https://synthetic.invalid, user ,\" secret\r\n \",note,otpauth://totp?secret=ASDFA\n"},
	}
	fixtures[0].data = strings.ReplaceAll(fixtures[0].data, "\" ,realm", "\",realm")
	for _, fixture := range fixtures {
		d := mustParse(t, []byte(fixture.data), fixture.format)
		for _, target := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
			plan, err := d.Plan(target, nil)
			if err != nil || len(plan.Fields) != len(d.chromeHeaders) {
				t.Fatal("browser field accounting missing")
			}
			payload, err := d.exportProvider(target, []int{1})
			if err != nil {
				t.Fatal("native browser export failed:", err)
			}
			parsed, err := Parse(payload, target)
			if err != nil || len(parsed.provider.records) != 1 {
				t.Fatal("provider schema invalid")
			}
			item := parsed.provider.records[0].value
			var password any
			switch target {
			case BitwardenJSON:
				password = item["login"].(map[string]any)["password"]
			case ProtonPassZIP:
				password = item["data"].(map[string]any)["content"].(map[string]any)["password"]
			case OnePassword1PUX:
				for _, raw := range item["details"].(map[string]any)["loginFields"].([]any) {
					field := raw.(map[string]any)
					if field["designation"] == "password" {
						password = field["value"]
					}
				}
			}
			if password != " secret\r\n " {
				t.Fatal("native browser credential changed")
			}
		}
	}
}

func TestChromeSourcePlansAndExportsToAllProviderProfiles(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,note,Extra\nSYNTHETIC_TITLE,https://synthetic.invalid, u , p , exact ,hidden\n"), ChromeCSV)
	for _, target := range []Format{BitwardenJSON, OnePassword1PUX, ProtonPassZIP} {
		plan, err := d.Plan(target, nil)
		if err != nil || len(plan.Fields) != 6 || plan.SelectedRecords != 1 {
			t.Fatal("browser profile unavailable")
		}
		payload, err := d.exportProvider(target, []int{1})
		if err != nil {
			t.Fatal("browser export failed:", err)
		}
		parsed, err := Parse(payload, target)
		if err != nil || parsed.inventory.Records != 1 {
			t.Fatal("browser provider schema invalid")
		}
	}
}
