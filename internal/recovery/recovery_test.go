package recovery

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// This publicly documented key and ciphertext are upstream synthetic examples,
// not user secrets. The known plaintext is documented in age's ExampleDecrypt.
const upstreamIdentity = "AGE-SECRET-KEY-184JMZMVQH3E6U0PSL869004Y3U2NYV7R30EU99CSEDNPH02YUVFSZW44VU"
const normalManifest = `{"schema":"pwmigrate-recovery","version":1,"source_format":"chrome-csv","retention":"whole_source","source_bytes":4}`

func independentEnvelope(manifest string, source []byte) []byte {
	out := []byte("pwmigrate-recovery\n")
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(manifest)))
	out = append(out, size[:]...)
	out = append(out, manifest...)
	return append(out, source...)
}

// Encrypting independent literal framing through the maintained age API avoids
// letting recovery.Encrypt determine the reader's expected envelope.
func independentAge(t testing.TB, plaintext []byte) []byte {
	t.Helper()
	identity, err := age.ParseX25519Identity(upstreamIdentity)
	if err != nil {
		t.Fatal("synthetic identity invalid")
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, identity.Recipient())
	if err != nil {
		t.Fatal("independent age encryption failed")
	}
	if _, err = w.Write(plaintext); err != nil {
		t.Fatal("independent age write failed")
	}
	if err = w.Close(); err != nil {
		t.Fatal("independent age close failed")
	}
	return out.Bytes()
}

func requireFailure(t *testing.T, ciphertext, identity []byte, code string) {
	t.Helper()
	payload, err := Decrypt(ciphertext, identity)
	if err == nil {
		t.Fatal("invalid recovery returned success")
	}
	if payload.Format != "" || payload.Source != nil {
		t.Fatal("failed recovery exposed plaintext")
	}
	if err.Error() != code {
		t.Fatalf("error code = %q, want %q", err.Error(), code)
	}
}

func TestReaderAcceptsIndependentLiteralEnvelope(t *testing.T) {
	source := []byte("test")
	ciphertext := independentAge(t, independentEnvelope(normalManifest, source))
	payload, err := Decrypt(ciphertext, []byte(upstreamIdentity))
	if err != nil {
		t.Fatalf("independent recovery failed: %v", err)
	}
	if payload.Format != "chrome-csv" || !bytes.Equal(payload.Source, source) {
		t.Fatal("reader changed independent source")
	}
}

func TestReaderRejectsMalformedAuthenticatedEnvelopes(t *testing.T) {
	cases := []struct {
		name, manifest string
		source         []byte
	}{
		{"duplicate_version", strings.Replace(normalManifest, `"version":1`, `"version":1,"version":1`, 1), []byte("test")},
		{"duplicate_escaped_version", strings.Replace(normalManifest, `"version":1`, `"version":1,"\u0076ersion":1`, 1), []byte("test")},
		{"unknown_field", strings.Replace(normalManifest, `"version":1`, `"version":1,"secret":"SYNTHETIC_SECRET"`, 1), []byte("test")},
		{"missing_schema", strings.Replace(normalManifest, `"schema":"pwmigrate-recovery",`, ``, 1), []byte("test")},
		{"wrong_schema", strings.Replace(normalManifest, `pwmigrate-recovery`, `unknown`, 1), []byte("test")},
		{"wrong_version", strings.Replace(normalManifest, `"version":1`, `"version":2`, 1), []byte("test")},
		{"fractional_version", strings.Replace(normalManifest, `"version":1`, `"version":1.0`, 1), []byte("test")},
		{"null_version", strings.Replace(normalManifest, `"version":1`, `"version":null`, 1), []byte("test")},
		{"wrong_format", strings.Replace(normalManifest, `chrome-csv`, `SYNTHETIC_SECRET`, 1), []byte("test")},
		{"wrong_retention", strings.Replace(normalManifest, `whole_source`, `selected_only`, 1), []byte("test")},
		{"negative_size", strings.Replace(normalManifest, `"source_bytes":4`, `"source_bytes":-1`, 1), []byte("test")},
		{"oversized_size", strings.Replace(normalManifest, `"source_bytes":4`, fmt.Sprintf(`"source_bytes":%d`, MaxSourceBytes+1), 1), []byte("test")},
		{"fractional_size", strings.Replace(normalManifest, `"source_bytes":4`, `"source_bytes":4.0`, 1), []byte("test")},
		{"null_size", strings.Replace(normalManifest, `"source_bytes":4`, `"source_bytes":null`, 1), []byte("test")},
		{"size_string", strings.Replace(normalManifest, `"source_bytes":4`, `"source_bytes":"4"`, 1), []byte("test")},
		{"truncated_source", normalManifest, []byte("tes")},
		{"extra_payload", normalManifest, []byte("testEXTRA")},
		{"extra_document", normalManifest + `{}`, []byte("test")},
		{"invalid_utf8", strings.Replace(normalManifest, `pwmigrate-recovery`, "\xff", 1), []byte("test")},
		{"nested_manifest", `{"schema":{"nested":[]}}`, []byte("test")},
		{"array_manifest", `[]`, []byte("test")},
		{"empty_manifest", ``, []byte("test")},
		{"huge_manifest", strings.Repeat(" ", MaxManifestBytes+1), []byte("test")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requireFailure(t, independentAge(t, independentEnvelope(tc.manifest, tc.source)), []byte(upstreamIdentity), "recovery_manifest")
		})
	}
	valid := independentEnvelope(normalManifest, []byte("test"))
	badMagic := bytes.Clone(valid)
	badMagic[0] ^= 1
	badLength := bytes.Clone(valid)
	binary.BigEndian.PutUint32(badLength[19:23], ^uint32(0))
	for name, plain := range map[string][]byte{"bad_magic": badMagic, "oversized_length": badLength, "incomplete_frame": valid[:22]} {
		t.Run(name, func(t *testing.T) {
			requireFailure(t, independentAge(t, plain), []byte(upstreamIdentity), "recovery_manifest")
		})
	}
}

func TestAuthenticatesEntireStreamBeforeReturningSource(t *testing.T) {
	source := bytes.Repeat([]byte("SYNTHETIC_SECRET"), 12000)
	manifest := strings.Replace(normalManifest, `"source_bytes":4`, fmt.Sprintf(`"source_bytes":%d`, len(source)), 1)
	valid := independentAge(t, independentEnvelope(manifest, source))
	for _, at := range []int{0, 30, 120, len(valid) / 2, len(valid) - 1} {
		t.Run(fmt.Sprintf("tamper_%d", at), func(t *testing.T) {
			bad := bytes.Clone(valid)
			bad[at] ^= 1
			requireFailure(t, bad, []byte(upstreamIdentity), "recovery_authentication")
		})
	}
	for _, cut := range []int{0, 20, 168, 65536, len(valid) - 1, len(valid) - 16} {
		t.Run(fmt.Sprintf("truncate_%d", cut), func(t *testing.T) {
			requireFailure(t, valid[:cut], []byte(upstreamIdentity), "recovery_authentication")
		})
	}
	t.Run("trailing_ciphertext", func(t *testing.T) {
		requireFailure(t, append(bytes.Clone(valid), 0), []byte(upstreamIdentity), "recovery_authentication")
	})
	t.Run("concatenated_ciphertext", func(t *testing.T) {
		requireFailure(t, append(bytes.Clone(valid), valid...), []byte(upstreamIdentity), "recovery_authentication")
	})
	wrong, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal("synthetic identity generation failed")
	}
	t.Run("wrong_identity", func(t *testing.T) { requireFailure(t, valid, []byte(wrong.String()), "recovery_authentication") })
}

func TestWriterAgeInteroperabilityAndExactRetention(t *testing.T) {
	source := []byte{' ', '\r', '\n', 0, 0xff, '\t', ' '}
	for _, format := range []string{"chrome-csv", "bitwarden-json", "onepassword-1pux", "proton-pass-zip"} {
		t.Run(format, func(t *testing.T) {
			ciphertext, err := Encrypt(format, source, []byte(upstreamIdentity))
			if err != nil {
				t.Fatal("writer failed")
			}
			if bytes.Contains(ciphertext, []byte(upstreamIdentity)) || bytes.Contains(ciphertext, []byte(`"retention"`)) {
				t.Fatal("writer exposed key or manifest")
			}
			identity, err := age.ParseX25519Identity(upstreamIdentity)
			if err != nil {
				t.Fatal("synthetic identity invalid")
			}
			r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
			if err != nil {
				t.Fatal("maintained age reader rejected output")
			}
			plaintext, err := io.ReadAll(r)
			if err != nil {
				t.Fatal("maintained age reader failed authentication")
			}
			manifest := fmt.Sprintf(`{"schema":"pwmigrate-recovery","version":1,"source_format":%q,"retention":"whole_source","source_bytes":%d}`, format, len(source))
			if !bytes.Equal(plaintext, independentEnvelope(manifest, source)) {
				t.Fatal("writer framing or exact source differed")
			}
		})
	}
}

func TestIdentityGenerationAndConventionalKeyFiles(t *testing.T) {
	first, err := GenerateIdentity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	second, err := GenerateIdentity()
	if err != nil {
		t.Fatal("identity generation failed")
	}
	if bytes.Equal(first, second) {
		t.Fatal("identity generation reused a key")
	}
	if _, err := age.ParseX25519Identity(string(first)); err != nil {
		t.Fatal("generated identity is not X25519")
	}
	keyFile := []byte("# synthetic fixture\r\n\r\n" + upstreamIdentity + "\r\n")
	ciphertext := independentAge(t, independentEnvelope(normalManifest, []byte("test")))
	if _, err := Decrypt(ciphertext, keyFile); err != nil {
		t.Fatal("conventional age key file rejected")
	}
	for _, key := range [][]byte{nil, []byte("SYNTHETIC_SECRET"), bytes.Repeat([]byte{'#'}, MaxIdentityBytes+1), []byte(upstreamIdentity + "\n" + upstreamIdentity), []byte("age-plugin-SYNTHETIC_SECRET")} {
		requireFailure(t, ciphertext, key, "recovery_identity")
		out, err := Encrypt("chrome-csv", []byte("test"), key)
		if err == nil || err.Error() != "recovery_identity" || out != nil {
			t.Fatal("writer accepted invalid identity")
		}
	}
}

func TestResourceLimitsAndEmptySource(t *testing.T) {
	requireFailure(t, make([]byte, MaxCiphertextBytes+1), []byte(upstreamIdentity), "recovery_ciphertext_limit")
	requireFailure(t, independentAge(t, make([]byte, MaxEnvelopeBytes+1)), []byte(upstreamIdentity), "recovery_payload_limit")
	if out, err := Encrypt("chrome-csv", make([]byte, MaxSourceBytes+1), []byte(upstreamIdentity)); err == nil || err.Error() != "recovery_source_limit" || out != nil {
		t.Fatal("writer accepted over-limit source")
	}
	if out, err := Encrypt("SYNTHETIC_SECRET", []byte("test"), []byte(upstreamIdentity)); err == nil || err.Error() != "recovery_format" || out != nil {
		t.Fatal("writer accepted unknown format")
	}
	manifest := strings.Replace(normalManifest, `"source_bytes":4`, `"source_bytes":0`, 1)
	payload, err := Decrypt(independentAge(t, independentEnvelope(manifest, nil)), []byte(upstreamIdentity))
	if err != nil || payload.Format != "chrome-csv" || len(payload.Source) != 0 {
		t.Fatal("empty source not retained")
	}
	for _, length := range []int{65536 - 23 - len(normalManifest), 65536, MaxSourceBytes} {
		source := bytes.Repeat([]byte{'x'}, length)
		ciphertext, err := Encrypt("chrome-csv", source, []byte(upstreamIdentity))
		if err != nil {
			t.Fatal("allowed source boundary rejected")
		}
		payload, err := Decrypt(ciphertext, []byte(upstreamIdentity))
		if err != nil || !bytes.Equal(payload.Source, source) {
			t.Fatal("allowed source boundary recovery failed")
		}
	}
}

func TestUpstreamFixtureRejectsRecoveryManifest(t *testing.T) {
	ciphertext, err := os.ReadFile("testdata/upstream-example.age")
	if err != nil {
		t.Fatal("upstream fixture missing")
	}
	// A recovery-manifest error distinguishes successful full authentication of
	// this maintained static vector from our own generated round trips.
	requireFailure(t, ciphertext, []byte(upstreamIdentity), "recovery_manifest")
}

func TestFullLengthFinalChunkAuthenticatesEOF(t *testing.T) {
	// The source length changes the manifest's decimal size field. Settle its
	// length before ensuring this independently encoded envelope is exactly one
	// full 64 KiB age plaintext chunk, whose EOF needs a separate trailing read.
	length := 65536
	var manifest string
	for {
		manifest = strings.Replace(normalManifest, `"source_bytes":4`, fmt.Sprintf(`"source_bytes":%d`, length), 1)
		next := 65536 - 23 - len(manifest)
		if next == length {
			break
		}
		length = next
	}
	source := bytes.Repeat([]byte{'x'}, length)
	plaintext := independentEnvelope(manifest, source)
	if len(plaintext) != 65536 {
		t.Fatal("synthetic full chunk fixture invalid")
	}
	ciphertext := independentAge(t, plaintext)
	payload, err := Decrypt(ciphertext, []byte(upstreamIdentity))
	if err != nil || !bytes.Equal(payload.Source, source) {
		t.Fatal("valid full final chunk rejected")
	}
	requireFailure(t, append(bytes.Clone(ciphertext), 0), []byte(upstreamIdentity), "recovery_authentication")
	requireFailure(t, ciphertext[:len(ciphertext)-1], []byte(upstreamIdentity), "recovery_authentication")
}

func TestOnlyOneX25519RecipientAndIdentitySupported(t *testing.T) {
	identity, err := age.ParseX25519Identity(upstreamIdentity)
	if err != nil {
		t.Fatal("synthetic identity invalid")
	}
	var duplicateRecipient bytes.Buffer
	w, err := age.Encrypt(&duplicateRecipient, identity.Recipient(), identity.Recipient())
	if err != nil {
		t.Fatal("synthetic multi recipient encryption failed")
	}
	if _, err := w.Write(independentEnvelope(normalManifest, []byte("test"))); err != nil {
		t.Fatal("synthetic write failed")
	}
	if err := w.Close(); err != nil {
		t.Fatal("synthetic close failed")
	}
	requireFailure(t, duplicateRecipient.Bytes(), []byte(upstreamIdentity), "recovery_authentication")
	hybrid, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal("synthetic hybrid identity generation failed")
	}
	requireFailure(t, independentAge(t, independentEnvelope(normalManifest, []byte("test"))), []byte(hybrid.String()), "recovery_identity")
	passwordRecipient, err := age.NewScryptRecipient("SYNTHETIC_SECRET")
	if err != nil {
		t.Fatal("synthetic scrypt recipient failed")
	}
	passwordRecipient.SetWorkFactor(1)
	var unsupported bytes.Buffer
	w, err = age.Encrypt(&unsupported, passwordRecipient)
	if err != nil {
		t.Fatal("synthetic scrypt encryption failed")
	}
	if _, err := w.Write(independentEnvelope(normalManifest, []byte("test"))); err != nil {
		t.Fatal("synthetic write failed")
	}
	if err := w.Close(); err != nil {
		t.Fatal("synthetic close failed")
	}
	requireFailure(t, unsupported.Bytes(), []byte(upstreamIdentity), "recovery_authentication")
}

func TestErrorsNeverEchoSourceOrIdentity(t *testing.T) {
	for _, e := range []*Error{nil, {Code: "SYNTHETIC_SECRET"}, {Code: "recovery_authentication"}} {
		if strings.Contains(e.Error(), "SYNTHETIC_SECRET") {
			t.Fatal("error exposed caller-controlled material")
		}
	}
	ciphertext := []byte("SYNTHETIC_SECRET\n")
	for _, key := range [][]byte{[]byte(upstreamIdentity), []byte("SYNTHETIC_SECRET")} {
		payload, err := Decrypt(ciphertext, key)
		if err == nil || payload.Source != nil || strings.Contains(err.Error(), "SYNTHETIC_SECRET") || strings.Contains(err.Error(), upstreamIdentity) {
			t.Fatal("error exposed invalid ciphertext or key")
		}
	}
}

func FuzzDecrypt(f *testing.F) {
	valid := independentAge(f, independentEnvelope(normalManifest, []byte("test")))
	f.Add(valid)
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Add([]byte("SYNTHETIC_SECRET"))
	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		if len(ciphertext) > 1<<16 {
			t.Skip()
		}
		payload, err := Decrypt(ciphertext, []byte(upstreamIdentity))
		if err != nil {
			if payload.Source != nil || payload.Format != "" {
				t.Fatal("failure returned plaintext")
			}
			if _, ok := err.(*Error); !ok {
				t.Fatal("failure returned library error")
			}
			return
		}
		if !supportedFormat(payload.Format) || len(payload.Source) > MaxSourceBytes {
			t.Fatal("success violated payload contract")
		}
	})
}
