package migration

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const firefoxNativeHeader = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged"
const safariNativeHeader = "Title,URL,Username,Password,Notes,OTPAuth"

func browserDocument(t *testing.T, data string, format Format) *Document {
	t.Helper()
	d := &Document{source: []byte(data), format: format}
	if err := d.parseBrowserCSV(); err != nil {
		t.Fatalf("browser parse failed: %v", err)
	}
	return d
}

func browserSafeCode(t *testing.T, data string, format Format, code string) {
	t.Helper()
	d := &Document{source: []byte(data), format: format}
	err := d.parseBrowserCSV()
	var safe *SafeError
	if !errors.As(err, &safe) || safe.Code != code {
		t.Fatalf("expected safe browser code %s, got %v", code, err)
	}
}

func TestFirefoxPreservesNativeColumnsWithoutInventedTitle(t *testing.T) {
	header := "\xef\xbb\xbf URL , USERNAME ,Password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged,[Custom]"
	data := header + "\r\n" + " https://example.invalid/Ω ,  user  ,\"  pass\r\nline\nlast  \",\"realm,quoted\",,synthetic-guid,001,0,-1,\" value\r\nline \"\r\n"
	d := browserDocument(t, data, Format("firefox-csv"))
	want := [][]string{{" https://example.invalid/Ω ", "  user  ", "  pass\r\nline\nlast  ", "realm,quoted", "", "synthetic-guid", "001", "0", "-1", " value\r\nline "}}
	if !reflect.DeepEqual(d.chromeRows, want) {
		t.Fatal("Firefox cell bytes changed")
	}
	if len(d.chromeHeaders) != 10 || len(d.chromeOriginalHeaders) != 10 || d.chromeHeaders[0] != "url" || d.chromeOriginalHeaders[0] != " URL " {
		t.Fatal("Firefox source column structure changed")
	}
	for _, h := range d.chromeHeaders {
		if h == "name" {
			t.Fatal("Firefox invented a source title column")
		}
	}
	if !bytes.Equal(d.source, []byte(data)) {
		t.Fatal("browser parsing mutated source bytes")
	}
	i := d.Inspect()
	if i.Format != Format("firefox-csv") || i.Records != 1 || i.Fields != 10 || i.MetadataFields != 0 || i.Kinds["login"] != 1 {
		t.Fatal("Firefox inventory counted generated fields as source fields")
	}
}

func TestSafariAliasesOnlySchemaHeadersAndPreservesCells(t *testing.T) {
	header := "\xef\xbb\xbf Title ,URL, Username ,Password, Notes , OTPAuth ,CustomTrailing"
	data := header + "\r\n" + "  title Ω  , url ,  user  ,\"  pass\r\nline  \",\" note\r\nline\nlast \",\" opaque OTP value \",\r\n"
	d := browserDocument(t, data, Format("safari-csv"))
	if !reflect.DeepEqual(d.chromeRows, [][]string{{"  title Ω  ", " url ", "  user  ", "  pass\r\nline  ", " note\r\nline\nlast ", " opaque OTP value ", ""}}) {
		t.Fatal("Safari cell bytes changed")
	}
	if !reflect.DeepEqual(d.chromeHeaders, []string{"name", "url", "username", "password", "note", "totp", "customtrailing"}) {
		t.Fatal("Safari documented header aliases were not projected")
	}
	if !reflect.DeepEqual(d.chromeOriginalHeaders, []string{" Title ", "URL", " Username ", "Password", " Notes ", " OTPAuth ", "CustomTrailing"}) {
		t.Fatal("Safari original header labels changed")
	}
	i := d.Inspect()
	if i.Format != Format("safari-csv") || i.Records != 1 || i.Fields != 7 || i.MetadataFields != 0 || i.Kinds["login"] != 1 {
		t.Fatal("Safari source accounting changed")
	}
}

func TestFirefoxExtrasNeverAcquireNativeFieldSemantics(t *testing.T) {
	d := browserDocument(t, firefoxNativeHeader+",name,note,totp,Title,Notes,OTPAuth\n"+
		"url,user,password,realm,origin,guid,001,002,003,title,note,otp,other-title,other-note,other-otp", Format("firefox-csv"))
	for column, header := range d.chromeHeaders {
		if column < 3 {
			continue
		}
		if header != fmt.Sprintf("browser-extra-%d", column+1) {
			t.Fatal("Firefox extra header acquired native destination semantics")
		}
	}
	if !d.browserNameFromURL || len(d.chromeRows[0]) != 15 || d.Inspect().Fields != 15 {
		t.Fatal("Firefox generated title changed native source columns")
	}
}

func TestBrowserDuplicateKeysExcludePasswordsAndKeepMultiplicity(t *testing.T) {
	for _, tc := range []struct {
		format       Format
		header, rows string
	}{
		{Format("firefox-csv"), firefoxNativeHeader, "same,user,first,,,,,,\nsame,user,second,,,,,,\n same,user,third,,,,,,\nsame, user,fourth,,,,,,\nsame,user,fifth,,,,,,\n"},
		{Format("safari-csv"), safariNativeHeader, "same,url,user,first,,\nsame,url,user,second,,\n same,url,user,third,,\nsame,url, user,fourth,,\nsame,url,user,fifth,,\n"},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			d := browserDocument(t, tc.header+"\n"+tc.rows, tc.format)
			i := d.Inspect()
			if i.Records != 5 || !reflect.DeepEqual(i.DuplicateGroups, [][]int{{1, 2, 5}}) {
				t.Fatal("browser duplicate detection merged, normalized, or compared passwords")
			}
			if tc.format == Format("firefox-csv") && i.DuplicateDetection != "exact_url_username" {
				t.Fatal("Firefox duplicate disclosure invented source names")
			}
		})
	}
}

func TestBrowserStrictRejections(t *testing.T) {
	for _, tc := range []struct {
		format  Format
		header  string
		columns int
	}{
		{Format("firefox-csv"), firefoxNativeHeader, 9},
		{Format("safari-csv"), safariNativeHeader, 6},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			row := strings.Repeat(",", tc.columns-1)
			for _, failure := range []struct{ name, data, code string }{
				{"empty", "", "missing_header"},
				{"duplicate_normalized", tc.header + ", USERNAME \n", "duplicate_header"},
				{"empty_header", tc.header + ", \t\n", "empty_header"},
				{"missing_native_columns", "url,username,password\n", "missing_header"},
				{"short", tc.header + "\n" + strings.Repeat(",", tc.columns-2), "uneven_row"},
				{"long", tc.header + "\n" + strings.Repeat(",", tc.columns), "uneven_row"},
				{"blank", tc.header + "\n\n" + row, "invalid_csv"},
				{"blank_CRLF", tc.header + "\r\n\r\n", "invalid_csv"},
				{"unclosed_quote", tc.header + "\n\"a" + row, "invalid_csv"},
				{"bare_quote", tc.header + "\na\"b" + row, "invalid_csv"},
				{"after_quote", tc.header + "\n\"a\"b" + row, "invalid_csv"},
				{"duplicate_unicode_distinct", tc.header + ",É,é\n" + row + ",a,b", ""},
			} {
				t.Run(failure.name, func(t *testing.T) {
					if failure.code == "" {
						browserDocument(t, failure.data, tc.format)
					} else {
						browserSafeCode(t, failure.data, tc.format, failure.code)
					}
				})
			}
		})
	}
	for _, alias := range []string{"name", "note", "totp"} {
		browserSafeCode(t, safariNativeHeader+","+alias+"\n", Format("safari-csv"), "duplicate_header")
	}
}

func TestBrowserHeaderOnlyAndEmptyRecords(t *testing.T) {
	for _, tc := range []struct {
		format  Format
		header  string
		columns int
	}{
		{Format("firefox-csv"), firefoxNativeHeader, 9},
		{Format("safari-csv"), safariNativeHeader, 6},
	} {
		for _, ending := range []string{"", "\n", "\r\n"} {
			d := browserDocument(t, tc.header+ending, tc.format)
			if d.Inspect().Records != 0 || d.Inspect().Fields != 0 {
				t.Fatal("header-only browser export created data")
			}
			d = browserDocument(t, tc.header+"\n"+strings.Repeat(",", tc.columns-1)+ending, tc.format)
			if d.Inspect().Records != 1 || d.Inspect().Fields != tc.columns {
				t.Fatal("browser parser lost explicit empty record")
			}
		}
	}
}

func TestBrowserDetectionRequiresUniqueCompleteSchema(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   Format
	}{
		{firefoxNativeHeader, Format("firefox-csv")},
		{safariNativeHeader, Format("safari-csv")},
		{"name,url,username,password", ChromeCSV},
		{"{opaque}," + firefoxNativeHeader, Format("firefox-csv")},
		{"[opaque]," + safariNativeHeader, Format("safari-csv")},
		{"Custom," + firefoxNativeHeader, Format("firefox-csv")},
		{"url,username,password", ""},
		{"Title,URL,Username,Password", ""},
		{"name," + firefoxNativeHeader, ""},
		{"name," + safariNativeHeader, ""},
		{safariNativeHeader + ",httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged", ""},
		{firefoxNativeHeader + ", USERNAME ", ""},
		{safariNativeHeader + ",name", ""},
		{safariNativeHeader + ",note", ""},
		{safariNativeHeader + ",totp", ""},
		{firefoxNativeHeader + ", ", ""},
		{"\"unclosed," + firefoxNativeHeader, ""},
		{"", ""},
	} {
		if got := detectBrowserCSV([]byte("\xef\xbb\xbf" + tc.header + "\r\n")); got != tc.want {
			t.Fatalf("browser detection: expected %q, got %q", tc.want, got)
		}
	}
}

func TestBrowserPublicParseRoutesAndLimits(t *testing.T) {
	for _, tc := range []struct {
		format  Format
		header  string
		columns int
	}{
		{FirefoxCSV, firefoxNativeHeader, 9},
		{SafariCSV, safariNativeHeader, 6},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			for _, explicit := range []Format{"", tc.format} {
				for _, custom := range []string{"", "{opaque},", "[opaque],"} {
					columns := tc.columns
					if custom != "" {
						columns++
					}
					data := []byte(custom + tc.header + "\r\n" + strings.Repeat(",", columns-1) + "\r\n")
					d := mustParse(t, data, explicit)
					if d.Inspect().Format != tc.format || d.Inspect().Fields != columns {
						t.Fatal("public Parse lost browser format or exact source count")
					}
					if d.browserNameFromURL != (tc.format == FirefoxCSV) {
						t.Fatal("browser destination title policy changed")
					}
				}
			}
			requireSafeCode(t, []byte(tc.header+"\n\xff"+strings.Repeat(",", tc.columns-1)), tc.format, "invalid_utf8")
			requireSafeCode(t, bytes.Repeat([]byte{'x'}, MaxInputBytes+1), tc.format, "input_limit")
			requireSafeCode(t, []byte(tc.header+"\n\"unclosed"), "", "invalid_csv")
		})
	}
}

func TestBrowserParserUsesCSVLimits(t *testing.T) {
	for _, tc := range []struct {
		format  Format
		header  string
		columns int
	}{
		{Format("firefox-csv"), firefoxNativeHeader, 9},
		{Format("safari-csv"), safariNativeHeader, 6},
	} {
		t.Run(string(tc.format), func(t *testing.T) {
			row := strings.Repeat(",", tc.columns-1) + "\n"
			d := browserDocument(t, tc.header+"\n"+strings.Repeat(row, MaxRecords), tc.format)
			if d.Inspect().Records != MaxRecords {
				t.Fatal("browser record boundary changed")
			}
			browserSafeCode(t, tc.header+"\n"+strings.Repeat(row, MaxRecords+1), tc.format, "record_limit")
			h := tc.header
			for c := tc.columns; c < MaxCSVColumns; c++ {
				h += fmt.Sprintf(",Custom%d", c)
			}
			d = browserDocument(t, h+"\n"+strings.Repeat(",", MaxCSVColumns-1), tc.format)
			if d.Inspect().Fields != MaxCSVColumns {
				t.Fatal("browser column boundary changed")
			}
			browserSafeCode(t, h+",extra", tc.format, "column_limit")
			browserSafeCode(t, tc.header+"\n"+strings.Repeat(",", MaxCSVColumns), tc.format, "column_limit")
			h = tc.header
			for c := tc.columns; c < 1000; c++ {
				h += fmt.Sprintf(",Custom%d", c)
			}
			body := h + "\n" + strings.Repeat(strings.Repeat(",", 999)+"\n", 1000)
			d = browserDocument(t, body, tc.format)
			if d.Inspect().Fields != MaxFields {
				t.Fatal("browser field boundary changed")
			}
			browserSafeCode(t, body+strings.Repeat(",", 999)+"\n", tc.format, "field_limit")
		})
	}
}
