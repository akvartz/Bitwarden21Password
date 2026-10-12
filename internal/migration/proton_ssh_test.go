package migration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func protonSSHRecord(private, public string) providerRecord {
	item := map[string]any{"data": map[string]any{"type": "sshKey", "metadata": map[string]any{"name": " synthetic SSH ", "note": " literal\\n\r\n ", "itemUuid": "synthetic-id"}, "content": map[string]any{"privateKey": private, "publicKey": public, "sections": []any{}}, "extraFields": []any{}}, "state": json.Number("1"), "pinned": true}
	return providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")}
}

func protonSSHBitwardenRecord(private, public, fingerprint string) providerRecord {
	item := map[string]any{"type": json.Number("5"), "name": " synthetic SSH ", "notes": " literal\\n\r\n ", "favorite": true, "sshKey": map[string]any{"privateKey": private, "publicKey": public, "keyFingerprint": fingerprint}, "fields": []any{}}
	return providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")}
}

func protonSSHVerifyRFCKey(t *testing.T, private string) {
	t.Helper()
	expected, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(ed25519.PublicKey(expected))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(private))
	if err != nil {
		t.Fatal("private key representation invalid")
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatal("private-key semantic public bytes differ from independent RFC vector")
	}
	sig, err := signer.Sign(rand.Reader, []byte("synthetic SSH verification"))
	if err != nil || pub.Verify([]byte("synthetic SSH verification"), sig) != nil {
		t.Fatal("SSH signature verification failed")
	}
}

func TestProtonSSHNativeParserRecognizesDeclaredShape(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, _ := onePasswordSSHTestValues(t, key)
	r := protonSSHRecord(pkcs8, public)
	root := map[string]any{"version": "1.42.0", "vaults": map[string]any{"v": map[string]any{"name": "synthetic", "items": []any{r.value}}}}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": data}), ProtonPassZIP)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.provider.records) != 1 || d.provider.records[0].kind != "ssh_key" || d.inventory.Kinds["ssh_key"] != 1 {
		t.Fatal("declared native SSH type remained unknown")
	}
}

func TestProtonSSHToBitwardenPKCS8Ed25519SemanticAndLiteralMapping(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := protonSSHRecord(pkcs8, public)
	m, err := mapProtonToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("verified native SSH item blocked")
	}
	protonRequireAccounting(t, r, m)
	s := m.value["sshKey"].(map[string]any)
	if m.value["type"] != json.Number("5") || s["publicKey"] != public || s["keyFingerprint"] != fingerprint || m.value["name"] != " synthetic SSH " || m.value["notes"] != " literal\\n\r\n " {
		t.Fatal("native SSH metadata/public values changed")
	}
	private := s["privateKey"].(string)
	if !strings.HasPrefix(private, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatal("Bitwarden private key lacks evidenced OpenSSH representation")
	}
	protonSSHVerifyRFCKey(t, private)
	if m.mappings["/data/content/privateKey"].disposition != "transformed" || m.mappings["/data/content/publicKey"].disposition != "native" {
		t.Fatal("SSH representation transformation not accounted")
	}
	if r.value["data"].(map[string]any)["content"].(map[string]any)["privateKey"] != pkcs8 {
		t.Fatal("immutable original SSH bytes mutated")
	}
}

func TestProtonSSHOpenSSHPreservesExactNativePrivateAndPublic(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, openSSH, public, fingerprint := onePasswordSSHTestValues(t, key)
	private := " \n" + openSSH + "\t\r\n"
	public = "\t" + strings.TrimSuffix(public, "\n") + " synthetic public comment \r\n"
	r := protonSSHRecord(private, public)
	m, err := mapProtonToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("exact OpenSSH pair rejected")
	}
	s := m.value["sshKey"].(map[string]any)
	if s["privateKey"] != private || s["publicKey"] != public || s["keyFingerprint"] != fingerprint || m.mappings["/data/content/privateKey"].disposition != "native" {
		t.Fatal("representable exact OpenSSH bytes normalized")
	}
	protonSSHVerifyRFCKey(t, s["privateKey"].(string))
}

func TestBitwardenSSHToProtonNativeLiteralSchemaAndExactValues(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, private, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := protonSSHBitwardenRecord(private, public, fingerprint)
	m, err := mapBitwardenToProton(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("verified Bitwarden SSH item blocked")
	}
	protonRequireAccounting(t, r, m)
	d := m.value["data"].(map[string]any)
	s := d["content"].(map[string]any)
	if d["type"] != "sshKey" || s["privateKey"] != private || s["publicKey"] != public || d["metadata"].(map[string]any)["note"] != " literal\\n\r\n " {
		t.Fatal("native Proton SSH schema or exact values changed")
	}
	sections := s["sections"].([]any)
	if len(sections) != 1 {
		t.Fatal("fingerprint missing from documented native custom section")
	}
	section := sections[0].(map[string]any)
	fields := section["sectionFields"].([]any)
	field := fields[0].(map[string]any)
	if section["sectionName"] != "Extra fields" || field["fieldName"] != "Key fingerprint" || field["type"] != "hidden" || field["data"].(map[string]any)["content"] != fingerprint {
		t.Fatal("independently documented fingerprint section literal changed")
	}
	if m.mappings["/sshKey/keyFingerprint"].disposition != "relocated" || m.mappings["/sshKey/privateKey"].disposition != "native" {
		t.Fatal("fingerprint relocation or exact key accounting missing")
	}
	if _, err := exportProton([]map[string]any{m.value}); err != nil {
		t.Fatal("validated native SSH writer rejected output")
	}
}

func TestProtonSSHRejectsMalformedMissingContradictoryAndEncryptedPairs(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	_, _, otherPublic, _ := onePasswordSSHTestValues(t, other)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing_private", func(s map[string]any) { delete(s, "privateKey") }},
		{"missing_public", func(s map[string]any) { delete(s, "publicKey") }},
		{"malformed_private", func(s map[string]any) { s["privateKey"] = "SSHSecretSentinel" }},
		{"contradictory_public", func(s map[string]any) { s["publicKey"] = otherPublic }},
		{"multiple_public", func(s map[string]any) { s["publicKey"] = public + otherPublic }},
		{"public_options", func(s map[string]any) { s["publicKey"] = "command=\"sentinel\" " + public }},
		{"encrypted_private", func(s map[string]any) {
			s["privateKey"] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"
		}},
		{"private_cap", func(s map[string]any) { s["privateKey"] = strings.Repeat("x", (256<<10)+1) }},
		{"public_cap", func(s map[string]any) { s["publicKey"] = strings.Repeat("x", (256<<10)+1) }},
		{"private_suffix", func(s map[string]any) { s["privateKey"] = pkcs8 + "SSHSecretSentinel" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := protonSSHRecord(pkcs8, public)
			s := r.value["data"].(map[string]any)["content"].(map[string]any)
			tc.change(s)
			r.fields = flattenFields(r.value, "")
			m, err := mapProtonToBitwarden(r)
			if err != nil && strings.Contains(err.Error(), "Sentinel") {
				t.Fatal("unsafe SSH parse error")
			}
			if m.value != nil || len(m.issues) == 0 {
				t.Fatal("unsafe native SSH pair emitted")
			}
			protonRequireAccounting(t, r, m)
			for _, mapping := range m.mappings {
				if mapping.disposition != "unsupported" {
					t.Fatal("failed SSH record falsely mapped")
				}
			}
		})
	}
	r := protonSSHBitwardenRecord(pkcs8, public, fingerprint)
	r.value["sshKey"].(map[string]any)["keyFingerprint"] = "SHA256:MismatchSentinel"
	r.fields = flattenFields(r.value, "")
	m, err := mapBitwardenToProton(r)
	if err != nil || m.value != nil {
		t.Fatal("contradictory Bitwarden fingerprint accepted")
	}
}

func TestProtonSSHSectionsDoNotGuessFingerprintOwnership(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, private, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := protonSSHRecord(private, public)
	s := r.value["data"].(map[string]any)["content"].(map[string]any)
	s["sections"] = []any{map[string]any{"sectionName": " synthetic section ", "sectionFields": []any{
		map[string]any{"fieldName": "Key fingerprint", "type": "hidden", "data": map[string]any{"content": "user text differs from derived fingerprint"}},
		map[string]any{"fieldName": " custom ", "type": "text", "data": map[string]any{"content": " value\r\n "}},
		map[string]any{"fieldName": " otp ", "type": "totp", "data": map[string]any{"totpUri": " otp secret "}},
		map[string]any{"fieldName": " unknown ", "type": "future", "data": map[string]any{"payload": " untouched "}},
	}}}
	r.fields = flattenFields(r.value, "")
	m, err := mapProtonToBitwarden(r)
	if err != nil || m.value == nil {
		t.Fatal("native SSH pair incorrectly rejected because user custom fingerprint label differs")
	}
	protonRequireAccounting(t, r, m)
	if m.value["sshKey"].(map[string]any)["keyFingerprint"] != fingerprint {
		t.Fatal("arbitrary user section was reinterpreted as required SSH fingerprint")
	}
	fields := m.value["fields"].([]any)
	if len(fields) != 2 || fields[0].(map[string]any)["value"] != "user text differs from derived fingerprint" || fields[1].(map[string]any)["value"] != " value\r\n " {
		t.Fatal("supported section fields or exact values lost")
	}
	for _, path := range []string{"/data/content/sections/0/sectionName", "/data/content/sections/0/sectionFields/2/data/totpUri", "/data/content/sections/0/sectionFields/3/data/payload"} {
		if m.mappings[path].disposition != "unsupported" {
			t.Fatal("unsupported section semantics silently coerced")
		}
	}
}

func TestProtonSSHSupportedRSAProfilesAndUnsupportedECDSA(t *testing.T) {
	for _, bits := range []int{2048, 3072, 4096} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal("synthetic RSA generation failed")
			}
			pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
			for _, private := range []string{pkcs8, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))} {
				m, err := mapProtonToBitwarden(protonSSHRecord(private, public))
				if err != nil || m.value == nil {
					t.Fatal("documented RSA profile rejected")
				}
				out := m.value["sshKey"].(map[string]any)
				if out["publicKey"] != public || out["keyFingerprint"] != fingerprint {
					t.Fatal("RSA public values changed")
				}
				signer, err := ssh.ParsePrivateKey([]byte(out["privateKey"].(string)))
				if err != nil {
					t.Fatal("RSA OpenSSH encoding invalid")
				}
				sig, err := signer.Sign(rand.Reader, []byte("synthetic"))
				pub, perr := ssh.NewPublicKey(key.Public())
				if err != nil || perr != nil || pub.Verify([]byte("synthetic"), sig) != nil {
					t.Fatal("RSA semantics changed")
				}
			}
			m, err := mapBitwardenToProton(protonSSHBitwardenRecord(pkcs8, public, fingerprint))
			if err != nil || m.value == nil {
				t.Fatal("native Proton RSA writer pair rejected")
			}
			if bits == 2048 {
				op := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "rsa")
				composed, err := mapProviderRecord(OnePassword1PUX, ProtonPassZIP, op)
				if err != nil || composed.value == nil {
					t.Fatal("supported RSA source to Proton composition blocked")
				}
				if _, err := exportProton([]map[string]any{composed.value}); err != nil {
					t.Fatal("composed RSA native output invalid")
				}
				blocked, err := mapProviderRecord(ProtonPassZIP, OnePassword1PUX, protonSSHRecord(pkcs8, public))
				if err != nil || blocked.value != nil {
					t.Fatal("unverified RSA 1PUX writer profile enabled")
				}
			}
		})
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	m, err := mapProtonToBitwarden(protonSSHRecord(pkcs8, public))
	if err != nil || m.value != nil {
		t.Fatal("unsupported ECDSA pair coerced")
	}
	m, err = mapBitwardenToProton(protonSSHBitwardenRecord(pkcs8, public, fingerprint))
	if err != nil || m.value != nil {
		t.Fatal("unsupported ECDSA writer pair coerced")
	}
}

func TestProtonSSHASN1ExtraPropertyIsRejected(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, _ := onePasswordSSHTestValues(t, key)
	block, _ := pem.Decode([]byte(pkcs8))
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(block.Bytes, &seq); err != nil {
		t.Fatal(err)
	}
	extra, err := asn1.Marshal(0)
	if err != nil {
		t.Fatal(err)
	}
	seq.Bytes = append(seq.Bytes, extra...)
	seq.FullBytes = nil
	der, err := asn1.Marshal(seq)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	m, err := mapProtonToBitwarden(protonSSHRecord(private, public))
	if err != nil || m.value != nil {
		t.Fatal("extra ASN.1 property was silently canonicalized")
	}
}

func TestProtonSSHIntermediaryEd25519RoutesAndOutputGuard(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	pp := protonSSHRecord(pkcs8, public)
	m, err := mapProviderRecord(ProtonPassZIP, OnePassword1PUX, pp)
	if err != nil || m.value == nil || m.value["categoryUuid"] != "114" {
		t.Fatal("supported Proton to 1PUX composition blocked")
	}
	if m.mappings["/data/content/privateKey"].disposition != "transformed" {
		t.Fatal("intermediary SSH conversion not accounted")
	}
	op := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "ed25519")
	m, err = mapProviderRecord(OnePassword1PUX, ProtonPassZIP, op)
	if err != nil || m.value == nil {
		t.Fatal("supported 1PUX to Proton composition blocked")
	}
	if _, err := exportProton([]map[string]any{m.value}); err != nil {
		t.Fatal("composed native SSH output invalid")
	}
}

func TestProtonSSHGeneratedOutputGuardRejectsMalformedPair(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, _, public, _ := onePasswordSSHTestValues(t, key)
	bad := protonSSHRecord("MalformedSSHSecretSentinel", public)
	output, err := exportProton([]map[string]any{bad.value})
	if output != nil || err == nil || strings.Contains(err.Error(), "Sentinel") {
		t.Fatal("invalid native SSH generated output escaped guard")
	}
}

func TestProtonSSHRejectsAESAndOpenSSHEncryptedKeysBeforeMapping(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	plain, _ := pem.Decode([]byte(pkcs8))
	// Encryption here creates independent synthetic negative fixtures only.
	aes, err := x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", plain.Bytes, []byte("synthetic fixture password"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal("synthetic AES fixture generation failed")
	}
	openSSH, err := ssh.MarshalPrivateKeyWithPassphrase(key, "synthetic", []byte("synthetic fixture password"))
	if err != nil {
		t.Fatal("synthetic encrypted OpenSSH fixture generation failed")
	}
	for _, block := range []*pem.Block{aes, openSSH} {
		private := string(pem.EncodeToMemory(block))
		for _, r := range []providerRecord{protonSSHRecord(private, public), protonSSHBitwardenRecord(private, public, fingerprint)} {
			var m mappedRecord
			if r.value["sshKey"] != nil {
				m, err = mapBitwardenToProton(r)
			} else {
				m, err = mapProtonToBitwarden(r)
			}
			if err != nil || m.value != nil {
				t.Fatal("encrypted key payload emitted")
			}
			found := false
			for _, code := range m.issues {
				if code == "unsupported_encrypted_ssh_key" {
					found = true
				}
			}
			if !found {
				t.Fatal("encrypted SSH key rejection lacks fixed disclosure")
			}
		}
	}
}

func TestProtonSSHRejectsOutOfProfileRSAIntegers(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	for _, bits := range []int{1024, 8192} {
		value := struct {
			Version               int
			N                     *big.Int
			E                     int
			D, P, Q, DP, DQ, QInv *big.Int
		}{0, new(big.Int).Lsh(big.NewInt(1), uint(bits-1)), 65537, big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1), big.NewInt(1)}
		der, err := asn1.Marshal(value)
		if err != nil {
			t.Fatal("synthetic ASN.1 fixture generation failed")
		}
		private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
		for _, r := range []providerRecord{protonSSHRecord(private, public), protonSSHBitwardenRecord(private, public, fingerprint)} {
			var m mappedRecord
			if r.value["sshKey"] != nil {
				m, err = mapBitwardenToProton(r)
			} else {
				m, err = mapProtonToBitwarden(r)
			}
			if err != nil || m.value != nil {
				t.Fatal("out-of-profile RSA integer admitted")
			}
		}
	}
}

func TestProtonSSHReportsContainOnlyFixedCodesAndOrdinals(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	private, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := protonSSHRecord(private, public)
	r.value["data"].(map[string]any)["metadata"].(map[string]any)["name"] = "SSHLabelSentinel"
	r.value["data"].(map[string]any)["content"].(map[string]any)["arbitrarySecretLabelSentinel"] = "SSHSecretSentinel"
	root := map[string]any{"version": "1.42.0", "vaults": map[string]any{"SSHVaultSentinel": map[string]any{"name": "SSHVaultSentinel", "items": []any{r.value}}}}
	native, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(protonTestZIP(t, map[string][]byte{"Proton Pass/data.json": native}), ProtonPassZIP)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := d.Plan(BitwardenJSON, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range []any{d.Inspect(), plan} {
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, sentinel := range []string{private, public, fingerprint, "SSHLabelSentinel", "SSHVaultSentinel", "SSHSecretSentinel", "arbitrarySecretLabelSentinel"} {
			if bytes.Contains(encoded, []byte(sentinel)) {
				t.Fatal("public SSH report disclosed source data")
			}
		}
	}
	if d.provider.records[0].value["data"].(map[string]any)["content"].(map[string]any)["arbitrarySecretLabelSentinel"] != "SSHSecretSentinel" {
		t.Fatal("unknown SSH payload disappeared from owned inventory")
	}
}
