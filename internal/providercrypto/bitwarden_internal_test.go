package providercrypto

import (
	"bytes"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

// These are synthetic literal vectors published by the provider SDK, not
// outputs produced by this package. The pinned sources are in README.md.
func TestBitwardenSDKKDFAndStretchLiterals(t *testing.T) {
	for _, v := range []struct {
		envelope BitwardenEnvelope
		want     string
	}{
		{BitwardenEnvelope{Salt: "test_key", KDFType: 0, KDFIterations: 10000},
			"6f1fb22dee9825728fd77c5387adc3178e8678f93d84a3b671c5bdccbc15ed60dd7fceea651bca265634221c4e1cb910303d7fa6d1f7c257e81a3055c1f9b39b"},
		{BitwardenEnvelope{Salt: "test_key", KDFType: 1, KDFIterations: 4, KDFMemory: 32, KDFParallelism: 2},
			"ecfda679cf7c62952a8d61e2cf47ad3c0a00b8fffc573e20bca6addf929fdedbd6904cade16a8483ad3886f1dfe3a5a192256fce9b18e09786bdca001b958315"},
	} {
		want, err := hex.DecodeString(v.want)
		if err != nil {
			t.Fatal("bad synthetic literal")
		}
		key, err := deriveBitwardenKey(v.envelope, []byte("67t9b5g67$%Dh89n"))
		if err != nil || !bytes.Equal(key, want) {
			t.Fatal("provider SDK KDF/stretch literal did not match")
		}
		clear(key)
	}
}

func TestBitwardenSDKCipherLiteral(t *testing.T) {
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	r := bitwardenRecord{
		iv:         []byte{216, 218, 36, 0, 196, 186, 150, 85, 49, 147, 110, 168, 185, 227, 42, 172},
		mac:        []byte{60, 78, 44, 111, 72, 233, 3, 6, 86, 250, 217, 242, 62, 229, 184, 221, 231, 150, 189, 44, 99, 189, 220, 55, 196, 194, 101, 60, 102, 195, 149, 130},
		ciphertext: []byte{234, 77, 16, 15, 189, 82, 36, 188, 182, 88, 64, 67, 145, 94, 30, 178, 36, 235, 130, 67, 255, 207, 183, 168, 73, 231, 82, 122, 193, 139, 25, 129},
	}
	if !r.authenticated(key[32:]) {
		t.Fatal("provider SDK literal authentication failed")
	}
	plain, err := r.decrypt(key[:32])
	if err != nil || !bytes.Equal(plain, []byte("Bitwarden SDK test vector")) {
		t.Fatal("provider SDK cipher literal did not match")
	}
	clear(plain)
	clear(key)
}

func TestBitwardenDelimiterFloodAllocationBound(t *testing.T) {
	// Splitting all delimiters can allocate hundreds of MiB for a bounded input.
	// Parsing must instead use a bounded number of components.
	s := "2." + strings.Repeat("|", 1<<20)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := parseBitwardenRecord(s); err == nil {
		t.Fatal("delimiter flood accepted")
	}
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 65536 {
		t.Fatal("record parsing has unbounded allocations")
	}
}

func FuzzBitwardenRecord(f *testing.F) {
	f.Add("2.AAECAwQFBgcICQoLDA0ODw==|AQID|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	f.Add("0.AAECAwQFBgcICQoLDA0ODw==|AQID")
	f.Add("2.||")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			t.Skip()
		}
		r, err := parseBitwardenRecord(s)
		if err == nil {
			if len(r.iv) != 16 || len(r.mac) != 32 || len(r.ciphertext) == 0 || len(r.ciphertext)%16 != 0 {
				t.Fatal("invalid lengths accepted")
			}
		} else if _, ok := err.(*Error); !ok {
			t.Fatal("unsafe error type")
		}
	})
}
