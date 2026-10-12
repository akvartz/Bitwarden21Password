package migration

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
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
