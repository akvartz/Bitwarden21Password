package migration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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

// RFC 8032 test vector 1 is a public, nonproduction key. Expected public
// bytes are independent literals, and signatures verify key semantics.
func onePasswordSSHTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func onePasswordSSHTestValues(t *testing.T, key any) (string, string, string, string) {
	t.Helper()
	dER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER}))
	openBlock, err := ssh.MarshalPrivateKey(key, "synthetic comment")
	if err != nil {
		t.Fatal(err)
	}
	openSSH := string(pem.EncodeToMemory(openBlock))
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return pkcs8, openSSH, public, ssh.FingerprintSHA256(signer.PublicKey())
}

func onePasswordSSHTestRecord(t *testing.T, pkcs8, public, fingerprint, kind string) providerRecord {
	t.Helper()
	item := map[string]any{"categoryUuid": "114", "overview": map[string]any{"title": "synthetic"}, "details": map[string]any{"sections": []any{map[string]any{"name": "", "title": "", "fields": []any{map[string]any{"id": "synthetic-field", "title": "Private key", "value": map[string]any{"sshKey": map[string]any{"privateKey": pkcs8, "metadata": map[string]any{"privateKey": pkcs8, "publicKey": public, "fingerprint": fingerprint, "keyType": kind}}}}}}}}}
	return providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")}
}

func onePasswordSSHVerifySemantics(t *testing.T, private string, expected ed25519.PrivateKey) {
	t.Helper()
	signer, err := ssh.ParsePrivateKey([]byte(private))
	if err != nil {
		t.Fatal("generated private key cannot be parsed")
	}
	publicLiteral, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := ssh.NewPublicKey(ed25519.PublicKey(publicLiteral))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), publicKey.Marshal()) {
		t.Fatal("generated SSH public key differs from RFC vector")
	}
	signature, err := signer.Sign(rand.Reader, []byte("synthetic verification"))
	if err != nil {
		t.Fatal("generated key cannot sign")
	}
	if err := publicKey.Verify([]byte("synthetic verification"), signature); err != nil {
		t.Fatal("generated SSH key semantics changed")
	}
}

func TestOnePasswordSSHToBitwardenEd25519SemanticConversion(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "ed25519")
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("verified SSH key was blocked")
	}
	item := m.value["sshKey"].(map[string]any)
	if item["publicKey"] != public || item["keyFingerprint"] != fingerprint {
		t.Fatal("public SSH fields normalized")
	}
	onePasswordSSHVerifySemantics(t, item["privateKey"].(string), key)
	if !strings.HasPrefix(item["privateKey"].(string), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatal("destination private key does not use evidenced OpenSSH format")
	}
	path := "/details/sections/0/fields/0/value/sshKey/metadata/privateKey"
	if m.mappings[path].disposition != "transformed" {
		t.Fatal("private-key reencoding was falsely native")
	}
	if len(m.mappings) != len(r.fields) {
		t.Fatal("SSH source leaf disposition missing")
	}
}

func TestBitwardenSSHToOnePasswordEd25519SemanticConversion(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, openSSH, public, fingerprint := onePasswordSSHTestValues(t, key)
	item := map[string]any{"type": json.Number("5"), "name": "synthetic", "notes": "literal\\n\r\n", "sshKey": map[string]any{"privateKey": openSSH, "publicKey": public, "keyFingerprint": fingerprint}}
	r := providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")}
	m, err := mapBitwardenToOnePassword(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("verified SSH key was blocked")
	}
	if m.value["categoryUuid"] != "114" {
		t.Fatal("SSH category schema incorrect")
	}
	field := m.value["details"].(map[string]any)["sections"].([]any)[0].(map[string]any)["fields"].([]any)[0].(map[string]any)
	value := field["value"].(map[string]any)["sshKey"].(map[string]any)
	metadata := value["metadata"].(map[string]any)
	if value["privateKey"] != metadata["privateKey"] || metadata["publicKey"] != public || metadata["fingerprint"] != fingerprint || metadata["keyType"] != "ed25519" {
		t.Fatal("literal provider SSH schema incorrect")
	}
	pkcs8 := metadata["privateKey"].(string)
	if !strings.HasPrefix(pkcs8, "-----BEGIN PRIVATE KEY-----") {
		t.Fatal("1PUX metadata private key is not evidenced PKCS8 PEM")
	}
	onePasswordSSHVerifySemantics(t, pkcs8, key)
	if m.mappings["/sshKey/privateKey"].disposition != "transformed" {
		t.Fatal("private representation change was falsely native")
	}
	if item["sshKey"].(map[string]any)["privateKey"] != openSSH {
		t.Fatal("source exact key representation mutated")
	}
}

func TestOnePasswordSSHMalformedAndConflictingInputsFailClosed(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	otherSeed := bytes.Repeat([]byte{7}, 32)
	other := ed25519.NewKeyFromSeed(otherSeed)
	otherPKCS8, _, otherPublic, _ := onePasswordSSHTestValues(t, other)
	for _, tc := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"private_malformed", func(v map[string]any) { v["metadata"].(map[string]any)["privateKey"] = "KeySentinel" }},
		{"private_encrypted", func(v map[string]any) {
			v["metadata"].(map[string]any)["privateKey"] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n-----END ENCRYPTED PRIVATE KEY-----\n"
		}},
		{"missing_metadata", func(v map[string]any) { delete(v, "metadata") }},
		{"public_mismatch", func(v map[string]any) { v["metadata"].(map[string]any)["publicKey"] = otherPublic }},
		{"fingerprint_mismatch", func(v map[string]any) { v["metadata"].(map[string]any)["fingerprint"] = "SHA256:MismatchSentinel" }},
		{"duplicate_representation_mismatch", func(v map[string]any) { v["privateKey"] = otherPKCS8 }},
		{"multiple_public_keys", func(v map[string]any) { v["metadata"].(map[string]any)["publicKey"] = public + otherPublic }},
		{"key_type_mismatch", func(v map[string]any) { v["metadata"].(map[string]any)["keyType"] = "rsa" }},
		{"private_resource_limit", func(v map[string]any) {
			v["metadata"].(map[string]any)["privateKey"] = strings.Repeat("x", (256<<10)+1)
		}},
		{"trailing_private_data", func(v map[string]any) { v["metadata"].(map[string]any)["privateKey"] = pkcs8 + "TrailingSentinel" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "ed25519")
			value := onePasswordSectionFields(r.value["details"].(map[string]any))[0].value["sshKey"].(map[string]any)
			tc.change(value)
			r.fields = flattenFields(r.value, "")
			m, err := mapOnePasswordToBitwarden(r)
			if err != nil {
				if strings.Contains(err.Error(), "Sentinel") {
					t.Fatal("unsafe key parse error")
				}
			}
			if m.value != nil {
				t.Fatal("unsafe SSH payload emitted")
			}
			if len(m.issues) == 0 {
				t.Fatal("SSH rejection has no fixed issue")
			}
			for _, mapping := range m.mappings {
				if mapping.disposition != "unsupported" {
					t.Fatal("failed SSH record falsely mapped")
				}
			}
		})
	}
}

func TestOnePasswordSSHDuplicateKeyFieldsFailClosed(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "ed25519")
	section := r.value["details"].(map[string]any)["sections"].([]any)[0].(map[string]any)
	fields := section["fields"].([]any)
	section["fields"] = append(fields, fields[0])
	r.fields = flattenFields(r.value, "")
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("duplicate SSH credentials collapsed")
	}
}

func TestOnePasswordSSHRSA2048SourceSemanticConversion(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "rsa"))
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("documented RSA2048 key source was blocked")
	}
	signer, err := ssh.ParsePrivateKey([]byte(m.value["sshKey"].(map[string]any)["privateKey"].(string)))
	if err != nil {
		t.Fatal("converted RSA key invalid")
	}
	pub, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
		t.Fatal("RSA key semantics changed")
	}
}

func TestOnePasswordSSHRSAAdditionalDocumentedSizes(t *testing.T) {
	for _, bits := range []int{3072, 4096} {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			key, err := rsa.GenerateKey(rand.Reader, bits)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
			m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "rsa"))
			if err != nil {
				t.Fatal(err)
			}
			if m.value == nil {
				t.Fatal("documented RSA source size blocked")
			}
			signer, err := ssh.ParsePrivateKey([]byte(m.value["sshKey"].(map[string]any)["privateKey"].(string)))
			if err != nil {
				t.Fatal("converted RSA key invalid")
			}
			pub, err := ssh.NewPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(signer.PublicKey().Marshal(), pub.Marshal()) {
				t.Fatal("RSA key semantics changed")
			}
		})
	}
}

func TestOnePasswordSSHRSAUnsupportedIntegerSizeRejectedBeforeValidation(t *testing.T) {
	var key struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, QInv *big.Int
	}
	key.N = new(big.Int).Lsh(big.NewInt(1), 200000)
	key.E = 65537
	key.D = big.NewInt(1)
	key.P = big.NewInt(3)
	key.Q = big.NewInt(5)
	key.DP = big.NewInt(1)
	key.DQ = big.NewInt(1)
	key.QInv = big.NewInt(2)
	dER, err := asn1.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: dER}))
	_, _, code := onePasswordSSHParse(private)
	if code != "unsupported_ssh_key_type" {
		t.Fatal("oversized RSA reached cryptographic validation")
	}
}

func FuzzOnePasswordSSHBoundedCanonical(f *testing.F) {
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"))
	f.Add([]byte("KeySentinel"))
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	dER, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > onePasswordSSHMaxKeyBytes+1 {
			return
		}
		canonical, err := onePasswordSSHCanonical(string(data))
		if err != nil {
			if safe, ok := err.(*SafeError); !ok || safe.Code != "invalid_item" {
				t.Fatal("unsafe SSH error")
			}
			return
		}
		if len(canonical) > onePasswordSSHMaxKeyBytes {
			t.Fatal("canonical key limit exceeded")
		}
		if _, _, code := onePasswordSSHParse(canonical); code != "" {
			t.Fatal("accepted canonical key invalid")
		}
	})
}

func TestBitwardenSSHInconsistentEd25519SeedAndPublicFailClosed(t *testing.T) {
	key := append(ed25519.PrivateKey(nil), onePasswordSSHTestKey(t)...)
	key[63] ^= 1
	_, private, public, fingerprint := onePasswordSSHTestValues(t, key)
	item := map[string]any{"type": json.Number("5"), "name": "synthetic", "sshKey": map[string]any{"privateKey": private, "publicKey": public, "keyFingerprint": fingerprint}}
	r := providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")}
	m, err := mapBitwardenToOnePassword(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("inconsistent Ed25519 private seed and public tail reinterpreted")
	}
}

func TestOnePasswordSSHMalformedLeadingPEMIsNotSkipped(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	private := "-----BEGIN PRIVATE KEY-----\nNotBase64Sentinel!\n-----END PRIVATE KEY-----\n" + pkcs8
	m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, private, public, fingerprint, "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("PEM parser skipped first source representation")
	}
}

func TestOnePasswordSSHUnsupportedECDSAFailsClosed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "ecdsa"))
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("1Password-unsupported SSH algorithm emitted")
	}
}

func TestBitwardenSSHOpenSSHEmbeddedPublicMismatchFailsClosed(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, private, public, fingerprint := onePasswordSSHTestValues(t, key)
	block, _ := pem.Decode([]byte(private))
	var wire struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}
	if err := ssh.Unmarshal(block.Bytes[len("openssh-key-v1\x00"):], &wire); err != nil {
		t.Fatal(err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	otherPub, err := ssh.NewPublicKey(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	wire.PubKey = otherPub.Marshal()
	block.Bytes = append([]byte("openssh-key-v1\x00"), ssh.Marshal(&wire)...)
	private = string(pem.EncodeToMemory(block))
	item := map[string]any{"type": json.Number("5"), "name": "synthetic", "sshKey": map[string]any{"privateKey": private, "publicKey": public, "keyFingerprint": fingerprint}}
	m, err := mapBitwardenToOnePassword(providerRecord{value: item, kind: "ssh_key", fields: flattenFields(item, "")})
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("OpenSSH wrapper public key conflicts with private representation")
	}
}

func TestOnePasswordSSHDescriptiveKeyTypeIsUnsupportedMetadata(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	r := onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "Descriptive type sentinel")
	m, err := mapOnePasswordToBitwarden(r)
	if err != nil {
		t.Fatal(err)
	}
	if m.value == nil {
		t.Fatal("unknown display metadata prevented independently verified key semantics")
	}
	if m.mappings["/details/sections/0/fields/0/value/sshKey/metadata/keyType"].disposition != "unsupported" {
		t.Fatal("unknown metadata enum falsely interpreted")
	}
	onePasswordSSHVerifySemantics(t, m.value["sshKey"].(map[string]any)["privateKey"].(string), key)
}

func TestOnePasswordSSHPublicParserDoesNotSkipLeadingLines(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	for _, prefix := range []string{"IgnoredSentinel\n", "ssh-ed25519 BadSentinel\n"} {
		m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, pkcs8, prefix+public, fingerprint, "ed25519"))
		if err != nil {
			t.Fatal(err)
		}
		if m.value != nil {
			t.Fatal("public parser skipped arbitrary source lines")
		}
	}
}

func TestOnePasswordSSHVersionOnePKCS8PublicConsistency(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	seedDER, err := asn1.Marshal(key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []bool{false, true} {
		publicBytes := append([]byte(nil), key.Public().(ed25519.PublicKey)...)
		if wrong {
			publicBytes[0] ^= 1
		}
		outer := struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
			PublicKey  asn1.BitString `asn1:"optional,tag:1"`
		}{Version: 1, Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}, PrivateKey: seedDER, PublicKey: asn1.BitString{Bytes: publicBytes, BitLength: 256}}
		dER, err := asn1.Marshal(outer)
		if err != nil {
			t.Fatal(err)
		}
		private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER}))
		m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, private, public, fingerprint, "ed25519"))
		if err != nil {
			t.Fatal(err)
		}
		if wrong && m.value != nil {
			t.Fatal("PKCS8 optional public key conflicts with private seed")
		}
		if !wrong && m.value == nil {
			t.Fatal("independently verified 1PUX PKCS8 version1 schema blocked")
		}
	}
}

func TestOnePasswordSSHRejectsDuplicateOrUnknownPKCS8OuterFields(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	seedDER, err := asn1.Marshal(key.Seed())
	if err != nil {
		t.Fatal("synthetic seed framing")
	}
	for _, tag := range []int{1, 2} {
		wrong := append([]byte{0}, key.Public().(ed25519.PublicKey)...)
		wrong[1] ^= 1
		outer := struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
			PublicKey  asn1.BitString `asn1:"optional,tag:1"`
			Extra      asn1.RawValue
		}{Version: 1, Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}, PrivateKey: seedDER, PublicKey: asn1.BitString{Bytes: key.Public().(ed25519.PublicKey), BitLength: 256}, Extra: asn1.RawValue{Class: 2, Tag: tag, Bytes: wrong}}
		dER, err := asn1.Marshal(outer)
		if err != nil {
			t.Fatal("synthetic outer framing")
		}
		private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER}))
		mapped, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, private, public, fingerprint, "ed25519"))
		if err != nil {
			t.Fatal("mapping error")
		}
		if mapped.value != nil {
			t.Fatal("duplicate or unknown PKCS8 trailing fields silently accepted")
		}
	}
}

func TestOnePasswordSSHRejectsPresentEmptyPKCS8Public(t *testing.T) {
	key := onePasswordSSHTestKey(t)
	_, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	seedDER, err := asn1.Marshal(key.Seed())
	if err != nil {
		t.Fatal(err)
	}
	outer := struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
		PublicKey  asn1.RawValue
	}{Version: 1, Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}, PrivateKey: seedDER, PublicKey: asn1.RawValue{Class: 2, Tag: 1, Bytes: []byte{0}}}
	dER, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	private := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER}))
	m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, private, public, fingerprint, "ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	if m.value != nil {
		t.Fatal("present empty embedded public treated as absent")
	}
}

func TestOnePasswordSSHRSARejectsTrailingInnerMembers(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _, public, fingerprint := onePasswordSSHTestValues(t, key)
	block, _ := pem.Decode([]byte(pkcs8))
	for _, where := range []string{"algorithm", "private"} {
		t.Run(where, func(t *testing.T) {
			var outer struct {
				Version    int
				Algorithm  pkix.AlgorithmIdentifier
				PrivateKey []byte
			}
			if rest, err := asn1.Unmarshal(block.Bytes, &outer); err != nil || len(rest) != 0 {
				t.Fatal("synthetic PKCS8 framing")
			}
			if where == "private" {
				extra, err := asn1.Marshal(9)
				if err != nil {
					t.Fatal(err)
				}
				outer.PrivateKey = onePasswordSSHTestAppendASNMember(t, outer.PrivateKey, extra)
				data, err := asn1.Marshal(outer)
				if err != nil {
					t.Fatal(err)
				}
				pkcs8 = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}))
			} else {
				algorithm, err := asn1.Marshal(outer.Algorithm)
				if err != nil {
					t.Fatal(err)
				}
				algorithm = onePasswordSSHTestAppendASNMember(t, algorithm, []byte{0x84, 0x01, 0x01})
				version, _ := asn1.Marshal(outer.Version)
				private, _ := asn1.Marshal(outer.PrivateKey)
				body := append(append(version, algorithm...), private...)
				data, err := asn1.Marshal(asn1.RawValue{Class: 0, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
				if err != nil {
					t.Fatal(err)
				}
				pkcs8 = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}))
			}
			m, err := mapOnePasswordToBitwarden(onePasswordSSHTestRecord(t, pkcs8, public, fingerprint, "rsa"))
			if err != nil {
				t.Fatal(err)
			}
			if m.value != nil {
				t.Fatal("trailing inner ASN member was silently ignored")
			}
		})
	}
}

func onePasswordSSHTestAppendASNMember(t *testing.T, data, member []byte) []byte {
	t.Helper()
	var sequence asn1.RawValue
	if rest, err := asn1.Unmarshal(data, &sequence); err != nil || len(rest) != 0 {
		t.Fatal("synthetic sequence framing")
	}
	sequence.FullBytes = nil
	sequence.Bytes = append(append([]byte(nil), sequence.Bytes...), member...)
	encoded, err := asn1.Marshal(sequence)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
