package migration

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, data []byte, source Format) *Document {
	t.Helper()
	d, err := Parse(data, source)
	if err != nil {
		t.Fatalf("Parse failed with safe code: %v", err)
	}
	if d == nil {
		t.Fatal("Parse returned nil without an error")
	}
	return d
}

func requireSafeCode(t *testing.T, data []byte, source Format, code string) {
	t.Helper()
	d, err := Parse(data, source)
	if err == nil {
		t.Fatalf("expected %s; input unexpectedly accepted", code)
	}
	if d != nil {
		t.Fatal("failure returned a partial document")
	}
	var safe *SafeError
	if !errors.As(err, &safe) {
		t.Fatal("input failure was not a SafeError")
	}
	if safe.Code != code {
		t.Fatalf("expected safe code %s, got %s", code, safe.Code)
	}
}

func TestChromeExactCellPreservation(t *testing.T) {
	// These independent expectations catch trimming, newline normalization,
	// legacy note interpretation, unknown-field loss, and trailing-cell loss.
	data := []byte("\xef\xbb\xbf Name ,URL, USERNAME ,Password,Note,CustomSentinelA,Trailing\r\n" +
		"  title Ω  ,https://example.invalid/é,  user  ,\"  pass\r\nline\nlast  \",\"---- pwmigrate extras ----\\nopaque\r\nnotes\",literal\\n,\r\n" +
		"other,,user,   ,,custom,\r\n" +
		"empty,,,,,,\r\n")
	d := mustParse(t, data, ChromeCSV)
	want := [][]string{
		{"  title Ω  ", "https://example.invalid/é", "  user  ", "  pass\r\nline\nlast  ", "---- pwmigrate extras ----\\nopaque\r\nnotes", "literal\\n", ""},
		{"other", "", "user", "   ", "", "custom", ""},
		{"empty", "", "", "", "", "", ""},
	}
	if !reflect.DeepEqual(d.chromeRows, want) {
		t.Fatal("CSV cells were not retained exactly")
	}
	if !bytes.Equal(d.source, data) {
		t.Fatal("source snapshot differs from supplied bytes")
	}
	got := d.Inspect()
	if got.Records != 3 || got.Fields != 21 || got.MetadataFields != 0 || got.Kinds["login"] != 3 {
		t.Fatalf("unexpected safe counts: records=%d fields=%d metadata=%d login=%d", got.Records, got.Fields, got.MetadataFields, got.Kinds["login"])
	}
}

func TestChromeQuotedDelimitersAndBareCR(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\n\"quoted,\"\"title\"\"\",url,user,bare\rvalue\n"), ChromeCSV)
	if !reflect.DeepEqual(d.chromeRows, [][]string{{"quoted,\"title\"", "url", "user", "bare\rvalue"}}) {
		t.Fatal("quoted delimiter, escaped quote, or bare CR changed")
	}
}

func TestChromeEmptyExportsAndRecordTerminators(t *testing.T) {
	for _, data := range []string{"name,url,username,password", "name,url,username,password\n", "name,url,username,password\r\n"} {
		d := mustParse(t, []byte(data), ChromeCSV)
		if d.Inspect().Records != 0 || d.Inspect().Fields != 0 {
			t.Fatal("header-only export acquired a record")
		}
	}
	for _, data := range []string{"name,url,username,password\n,,,", "name,url,username,password\n,,,\n", "name,url,username,password\r\n,,,\r\n"} {
		d := mustParse(t, []byte(data), ChromeCSV)
		if d.Inspect().Records != 1 || d.Inspect().Fields != 4 {
			t.Fatal("final terminator created a record or explicit empty cells disappeared")
		}
	}
}

func TestChromeStrictRejections(t *testing.T) {
	const header = "name,url,username,password\n"
	tests := []struct{ name, data, code string }{
		{"duplicate_normalized_header", "name,url,username,password, NAME \n", "duplicate_header"},
		{"empty_normalized_header", "name,url,username,password, \t\n", "empty_header"},
		{"missing_name", "url,username,password\n", "missing_header"},
		{"missing_url", "name,username,password\n", "missing_header"},
		{"missing_username", "name,url,password\n", "missing_header"},
		{"missing_password", "name,url,username\n", "missing_header"},
		{"short_row", header + "a,b,c\n", "uneven_row"},
		{"long_row", header + "a,b,c,d,e\n", "uneven_row"},
		{"bare_quote", header + "a,b,c,d\"e\n", "invalid_csv"},
		{"unclosed_quote", header + "a,b,c,\"d\n", "invalid_csv"},
		{"characters_after_quote", header + "a,b,c,\"d\"e\n", "invalid_csv"},
		{"blank_logical_row", header + "\na,b,c,d\n", "invalid_csv"},
		{"blank_final_row", header + "a,b,c,d\n\n", "invalid_csv"},
		{"blank_CRLF_row", header + "\r\n", "invalid_csv"},
		{"invalid_utf8", header + "a,b,c,\xff\n", "invalid_utf8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { requireSafeCode(t, []byte(tc.data), ChromeCSV, tc.code) })
	}
}

func TestChromeHeaderMatchingOnlyUsesASCIICase(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,É,é\na,b,c,d,e,f"), ChromeCSV)
	if d.Inspect().Fields != 6 {
		t.Fatal("distinct Unicode custom headers were conflated")
	}
}

func TestChromeLimits(t *testing.T) {
	t.Run("input_bytes", func(t *testing.T) {
		requireSafeCode(t, bytes.Repeat([]byte{'x'}, MaxInputBytes+1), ChromeCSV, "input_limit")
	})
	t.Run("record_boundary", func(t *testing.T) {
		data := []byte("name,url,username,password\n" + strings.Repeat(",,,\n", MaxRecords))
		d := mustParse(t, data, ChromeCSV)
		if d.Inspect().Records != MaxRecords {
			t.Fatal("record boundary count changed")
		}
		data = append(data, []byte(",,,\n")...)
		requireSafeCode(t, data, ChromeCSV, "record_limit")
	})
	t.Run("column_boundary", func(t *testing.T) {
		h := []string{"name", "url", "username", "password"}
		for i := 4; i < MaxCSVColumns; i++ {
			h = append(h, fmt.Sprintf("custom%d", i))
		}
		d := mustParse(t, []byte(strings.Join(h, ",")+"\n"+strings.Repeat(",", MaxCSVColumns-1)), ChromeCSV)
		if d.Inspect().Fields != MaxCSVColumns {
			t.Fatal("column boundary count changed")
		}
		requireSafeCode(t, []byte(strings.Join(h, ",")+",extra\n"), ChromeCSV, "column_limit")
	})
	t.Run("body_column_limit", func(t *testing.T) {
		requireSafeCode(t, []byte("name,url,username,password\n"+strings.Repeat(",", MaxCSVColumns)), ChromeCSV, "column_limit")
	})
	t.Run("field_boundary", func(t *testing.T) {
		h := []string{"name", "url", "username", "password"}
		for i := 4; i < 1000; i++ {
			h = append(h, fmt.Sprintf("custom%d", i))
		}
		data := []byte(strings.Join(h, ",") + "\n" + strings.Repeat(strings.Repeat(",", 999)+"\n", 1000))
		d := mustParse(t, data, ChromeCSV)
		if d.Inspect().Fields != MaxFields {
			t.Fatal("field boundary count changed")
		}
		data = append(data, []byte(strings.Repeat(",", 999)+"\n")...)
		requireSafeCode(t, data, ChromeCSV, "field_limit")
	})
}

func TestParseDetectionAndSafeFormatErrors(t *testing.T) {
	for _, tc := range []struct {
		data   string
		format Format
	}{
		{"name,url,username,password\na,b,c,d", ChromeCSV},
		{"\xef\xbb\xbf Name ,URL,USERNAME,PASSWORD\r\n", ChromeCSV},
		{" \n{\"encrypted\":false,\"items\":[]}", BitwardenJSON},
	} {
		if d := mustParse(t, []byte(tc.data), ""); d.Inspect().Format != tc.format {
			t.Fatal("incorrect detected format")
		}
	}
	requireSafeCode(t, []byte("unfamiliar input"), "", "unknown_format")
	requireSafeCode(t, []byte(`{"unrelated":true}`), "", "unknown_format")
	requireSafeCode(t, []byte(`{"encrypted":true}`), "", "unsupported_encrypted")
	requireSafeCode(t, []byte(""), "", "unknown_format")
	requireSafeCode(t, []byte("name,url,username,password\n"), Format("SentinelUnknownFormat"), "unknown_format")
}

func TestDetectChromeWithJSONLookingCustomHeader(t *testing.T) {
	for _, tc := range []struct{ name, header string }{
		{"brace", "{opaque}"},
		{"bracket", "[opaque]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header + ",name,url,username,password\n"
			d := mustParse(t, []byte(header+"value,title,url,user,password\n"), "")
			if d.Inspect().Format != ChromeCSV || d.Inspect().Fields != 5 {
				t.Fatal("recognized Chrome schema was misclassified")
			}
			requireSafeCode(t, []byte(header+"value,title,url,user,password\"invalid\n"), "", "invalid_csv")
		})
	}
}
