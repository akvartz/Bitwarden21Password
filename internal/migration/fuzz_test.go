package migration

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzChromeParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("name,url,username,password\n"),
		[]byte("\xef\xbb\xbf Name ,URL,USERNAME,PASSWORD,Note,Opaque\r\na,b,c,\"  p\r\nq  \",\"---- pwmigrate extras ----\\n\",\r\n"),
		[]byte("name,url,username,password\n,,,\n\n"),
		[]byte("name,url,username,password,NAME\n"),
		[]byte("name,url,username,password\na,b,c,\"unterminated"),
		[]byte{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) { assertFuzzParse(t, data, ChromeCSV) })
}

func FuzzBitwardenParser(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"encrypted":false,"items":[]}`),
		[]byte(`{"encrypted":false,"items":[{"type":1,"name":"Ω","login":{"username":null,"password":"\uD83D\uDD10","totp":"\\n"},"opaque":[{},null,900719925474099312345]}]}`),
		[]byte(`{"encrypted":false,"items":[],"key":1,"\u006bey":2}`),
		[]byte(`{"encrypted":false,"items":[{"type":1,"name":"x","login":{"password":"\uD800"}}]}`),
		[]byte(`{"encrypted":true,"items":[]}`),
		[]byte(`{"encrypted":false,"items":[]} {}`),
		[]byte{0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) { assertFuzzParse(t, data, BitwardenJSON) })
}

func assertFuzzParse(t *testing.T, data []byte, source Format) {
	t.Helper()
	d, err := Parse(data, source)
	if err != nil {
		var safe *SafeError
		if d != nil || !errors.As(err, &safe) {
			t.Fatal("input failure returned partial data or an unsafe error")
		}
		return
	}
	if d == nil || !bytes.Equal(d.source, data) {
		t.Fatal("successful parse lost the exact source snapshot")
	}
	inv := d.Inspect()
	if inv.Records < 0 || inv.Records > MaxRecords || inv.Fields < 0 || inv.MetadataFields < 0 || inv.Fields+inv.MetadataFields > MaxFields {
		t.Fatal("successful parse exceeded inventory bounds")
	}
}
