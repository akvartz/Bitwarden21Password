package migration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"

	"golang.org/x/crypto/ssh"
)

const onePasswordSSHMaxKeyBytes = 256 << 10

// This profile is grounded in the pinned provider type declarations and its
// independent Ed25519 1PUX fixture: metadata.privateKey is PKCS#8 PEM; publicKey
// is OpenSSH authorized-key text; fingerprint is SHA256; keyType is ed25519.
// RSA source keys use the documented provider sizes/exponent. RSA writer
// metadata.keyType has no independently verified 1PUX literal yet.
func onePasswordMapSSHToBitwarden(record providerRecord) (mappedRecord, error) {
	m := onePasswordMappingStart(record)
	fail := func(code string) (mappedRecord, error) { onePasswordIssue(&m, code); return m, nil }
	details, ok := record.value["details"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_key")
	}
	candidates := []onePasswordField{}
	for _, field := range onePasswordSectionFields(details) {
		if _, present := field.value["sshKey"]; present {
			candidates = append(candidates, field)
		}
	}
	if len(candidates) != 1 {
		if len(candidates) > 1 {
			return fail("unsupported_duplicate_credentials")
		}
		return fail("unsupported_ssh_key")
	}
	field := candidates[0]
	if len(field.value) != 1 {
		return fail("unsupported_ssh_representation")
	}
	value, ok := field.value["sshKey"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_representation")
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	private, privateOK := metadata["privateKey"].(string)
	public, publicOK := metadata["publicKey"].(string)
	fingerprint, fingerprintOK := metadata["fingerprint"].(string)
	keyType, keyTypeOK := metadata["keyType"].(string)
	if !privateOK || !publicOK || !fingerprintOK || !keyTypeOK {
		return fail("unsupported_ssh_metadata")
	}
	// The authoritative metadata format is PKCS#8. Do not guess unfamiliar
	// provider encodings just because a general SSH parser accepts them.
	block, code := onePasswordSSHPEM(private)
	if code != "" {
		return fail(code)
	}
	if block.Type != "PRIVATE KEY" {
		return fail("unsupported_ssh_representation")
	}
	key, kind, code := onePasswordSSHParse(private)
	if code != "" {
		return fail(code)
	}
	if (keyType == "ed25519" || keyType == "rsa") && keyType != kind {
		return fail("unsupported_ssh_key_type")
	}
	keyTypeMapped := keyType == kind
	if !keyTypeMapped {
		onePasswordIssue(&m, "unsupported_ssh_key_type_metadata")
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return fail("unsupported_ssh_key")
	}
	if code := onePasswordSSHCheckPublic(signer.PublicKey(), public, fingerprint); code != "" {
		return fail(code)
	}
	// The provider says the other privateKey representation is inconsistent.
	// If it is present, either verify it with the maintained parser or leave it
	// explicitly unsupported; a parseable conflicting key fails closed.
	topPrivate, topPresent := value["privateKey"]
	topMapped := false
	if topPresent {
		text, ok := topPrivate.(string)
		if !ok {
			return fail("unsupported_ssh_representation")
		}
		if len(text) > onePasswordSSHMaxKeyBytes {
			return fail("unsupported_ssh_key_limit")
		}
		other, _, code := onePasswordSSHParse(text)
		if code == "" {
			otherSigner, err := ssh.NewSignerFromKey(other)
			if err != nil || !bytes.Equal(otherSigner.PublicKey().Marshal(), signer.PublicKey().Marshal()) {
				return fail("unsupported_ssh_key_mismatch")
			}
			topMapped = true
		} else {
			onePasswordIssue(&m, "unsupported_ssh_representation")
		}
	}
	openBlock, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return fail("unsupported_ssh_key")
	}
	openSSH := string(pem.EncodeToMemory(openBlock))
	overview, ok := record.value["overview"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	name, ok := overview["title"].(string)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	m.value = map[string]any{"type": json.Number("5"), "name": name, "sshKey": map[string]any{"privateKey": openSSH, "publicKey": public, "keyFingerprint": fingerprint}}
	onePasswordMark(&m, "/categoryUuid", "transformed", "type", false)
	onePasswordMark(&m, "/overview/title", "native", "name", false)
	prefix := field.path + "/value/sshKey"
	onePasswordMark(&m, prefix+"/metadata/privateKey", "transformed", "sshKey.privateKey", true)
	onePasswordMark(&m, prefix+"/metadata/publicKey", "native", "sshKey.publicKey", false)
	onePasswordMark(&m, prefix+"/metadata/fingerprint", "native", "sshKey.keyFingerprint", false)
	if keyTypeMapped {
		onePasswordMark(&m, prefix+"/metadata/keyType", "transformed", "sshKey.privateKey", false)
	}
	if topMapped {
		onePasswordMark(&m, prefix+"/privateKey", "transformed", "sshKey.privateKey", true)
	}
	onePasswordSSHMapCommonToBitwarden(&m, record.value, details)
	for _, custom := range onePasswordSectionFields(details) {
		onePasswordMapCustom(&m, custom, "ssh_key")
	}
	return m, nil
}

func onePasswordMapBitwardenToSSH(record providerRecord) (mappedRecord, error) {
	m := onePasswordMappingStart(record)
	fail := func(code string) (mappedRecord, error) { onePasswordIssue(&m, code); return m, nil }
	value, ok := record.value["sshKey"].(map[string]any)
	if !ok {
		return fail("unsupported_ssh_key")
	}
	private, privateOK := value["privateKey"].(string)
	public, publicOK := value["publicKey"].(string)
	fingerprint, fingerprintOK := value["keyFingerprint"].(string)
	if !privateOK || !publicOK || !fingerprintOK {
		return fail("unsupported_ssh_metadata")
	}
	key, kind, code := onePasswordSSHParse(private)
	if code != "" {
		return fail(code)
	}
	if kind != "ed25519" {
		return fail("unsupported_ssh_writer_profile")
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return fail("unsupported_ssh_key")
	}
	if code := onePasswordSSHCheckPublic(signer.PublicKey(), public, fingerprint); code != "" {
		return fail(code)
	}
	canonical, err := onePasswordSSHCanonical(private)
	if err != nil {
		return fail("unsupported_ssh_key")
	}
	name, ok := record.value["name"].(string)
	if !ok {
		return fail("unsupported_ssh_metadata")
	}
	details := map[string]any{}
	m.value = map[string]any{"categoryUuid": "114", "overview": map[string]any{"title": name, "subtitle": "", "url": ""}, "details": details, "state": "active", "favIndex": json.Number("0"), "createdAt": json.Number("0"), "updatedAt": json.Number("0")}
	onePasswordAppendField(details, "pwmigrate.ssh.privateKey", "Private key", map[string]any{"sshKey": map[string]any{"privateKey": canonical, "metadata": map[string]any{"privateKey": canonical, "publicKey": public, "fingerprint": fingerprint, "keyType": "ed25519"}}})
	onePasswordMark(&m, "/type", "transformed", "categoryUuid", false)
	onePasswordMark(&m, "/name", "native", "overview.title", false)
	onePasswordMark(&m, "/sshKey/privateKey", "transformed", "details.sections.fields.value.sshKey.metadata.privateKey", true)
	onePasswordMark(&m, "/sshKey/publicKey", "native", "details.sections.fields.value.sshKey.metadata.publicKey", false)
	onePasswordMark(&m, "/sshKey/keyFingerprint", "native", "details.sections.fields.value.sshKey.metadata.fingerprint", false)
	if notes, ok := record.value["notes"].(string); ok {
		details["notesPlain"] = notes
		onePasswordMark(&m, "/notes", "native", "details.notesPlain", false)
	}
	if favorite, ok := record.value["favorite"].(bool); ok {
		if favorite {
			m.value["favIndex"] = json.Number("1")
		}
		onePasswordMark(&m, "/favorite", "transformed", "favIndex", false)
	}
	onePasswordMapBitwardenCustom(&m, record.value, details)
	if value, present := record.value["attachments"]; present && onePasswordNonempty(value) {
		onePasswordIssue(&m, "unsupported_attachments")
	}
	return m, nil
}

func onePasswordSSHMapCommonToBitwarden(m *mappedRecord, source, details map[string]any) {
	if notes, present := details["notesPlain"]; present {
		if _, ok := notes.(string); ok || notes == nil {
			m.value["notes"] = notes
			onePasswordMark(m, "/details/notesPlain", "native", "notes", false)
		}
	}
	if index, ok := source["favIndex"].(json.Number); ok {
		if number, err := strconv.ParseInt(index.String(), 10, 64); err == nil && number >= 0 {
			m.value["favorite"] = number > 0
			onePasswordMark(m, "/favIndex", "transformed", "favorite", false)
		}
	}
}

// onePasswordSSHCanonical is a private semantic representation for transformed
// SSH comparison. Never publish it, its key material, or a source key hash.
func onePasswordSSHCanonical(private string) (string, error) {
	key, _, code := onePasswordSSHParse(private)
	if code != "" {
		return "", &SafeError{Code: "invalid_item"}
	}
	dER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", &SafeError{Code: "invalid_item"}
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: dER})), nil
}

func onePasswordSSHPEM(private string) (*pem.Block, string) {
	if len(private) == 0 {
		return nil, "unsupported_ssh_key"
	}
	if len(private) > onePasswordSSHMaxKeyBytes {
		return nil, "unsupported_ssh_key_limit"
	}
	data := bytes.Trim([]byte(private), " \t\r\n")
	if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
		return nil, "unsupported_ssh_representation"
	}
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.Trim(rest, " \t\r\n")) != 0 {
		return nil, "unsupported_ssh_representation"
	}
	if bytes.Count(data, []byte("-----BEGIN ")) != 1 || bytes.Count(data, []byte("-----END ")) != 1 || !bytes.HasPrefix(data, []byte("-----BEGIN "+block.Type+"-----")) || !bytes.HasSuffix(data, []byte("-----END "+block.Type+"-----")) {
		return nil, "unsupported_ssh_representation"
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" || len(block.Headers) > 0 {
		return nil, "unsupported_encrypted_ssh_key"
	}
	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "OPENSSH PRIVATE KEY":
	default:
		return nil, "unsupported_ssh_representation"
	}
	return block, ""
}

func onePasswordSSHParse(private string) (any, string, string) {
	block, code := onePasswordSSHPEM(private)
	if code != "" {
		return nil, "", code
	}
	if code := onePasswordSSHASNBounds(block); code != "" {
		return nil, "", code
	}
	if code := onePasswordSSHOpenSSHBounds(block); code != "" {
		return nil, "", code
	}
	key, err := ssh.ParseRawPrivateKey([]byte(private))
	if err != nil {
		var encrypted *ssh.PassphraseMissingError
		if errors.As(err, &encrypted) {
			return nil, "", "unsupported_encrypted_ssh_key"
		}
		return nil, "", "unsupported_ssh_key"
	}
	switch key := key.(type) {
	case ed25519.PrivateKey:
		if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
			return nil, "", "unsupported_ssh_key"
		}
		return key, "ed25519", ""
	case *ed25519.PrivateKey:
		if key == nil || len(*key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed((*key).Seed()), *key) {
			return nil, "", "unsupported_ssh_key"
		}
		return *key, "ed25519", ""
	case *rsa.PrivateKey:
		if key == nil || key.N == nil {
			return nil, "", "unsupported_ssh_key"
		}
		bits := key.N.BitLen()
		if (bits != 2048 && bits != 3072 && bits != 4096) || key.E < 65537 {
			return nil, "", "unsupported_ssh_key_type"
		}
		if err := key.Validate(); err != nil {
			return nil, "", "unsupported_ssh_key"
		}
		return key, "rsa", ""
	default:
		return nil, "", "unsupported_ssh_key_type"
	}
}

// Bound RSA integers before the maintained parser validates or precomputes
// them. This reads the public ASN.1 container; cryptographic validation remains
// entirely in crypto/x509, crypto/rsa and x/crypto/ssh.
func onePasswordSSHASNBounds(block *pem.Block) string {
	data := block.Bytes
	var public asn1.BitString
	publicPresent := false
	if block.Type == "PRIVATE KEY" {
		members, ok := onePasswordSSHASNSequence(data, 4)
		if !ok || len(members) < 3 || !onePasswordSSHASNTag(members[0], 0, asn1.TagInteger, false) || !onePasswordSSHASNTag(members[1], 0, asn1.TagSequence, true) || !onePasswordSSHASNTag(members[2], 0, asn1.TagOctetString, false) {
			return "unsupported_ssh_representation"
		}
		if len(members) == 4 && !onePasswordSSHASNTag(members[3], 2, 1, false) {
			return "unsupported_ssh_representation"
		}
		publicPresent = len(members) == 4
		algorithm, ok := onePasswordSSHASNSequence(members[1].FullBytes, 2)
		if !ok || len(algorithm) < 1 || !onePasswordSSHASNTag(algorithm[0], 0, asn1.TagOID, false) {
			return "unsupported_ssh_representation"
		}
		if len(algorithm) == 2 && (!onePasswordSSHASNTag(algorithm[1], 0, asn1.TagNull, false) || len(algorithm[1].Bytes) != 0) {
			return "unsupported_ssh_representation"
		}
		var outer struct {
			Version    int
			Algorithm  pkix.AlgorithmIdentifier
			PrivateKey []byte
			Attributes asn1.RawValue  `asn1:"optional,tag:0"`
			PublicKey  asn1.BitString `asn1:"optional,tag:1"`
		}
		rest, err := asn1.Unmarshal(data, &outer)
		if err != nil || len(rest) != 0 {
			return "unsupported_ssh_key"
		}
		if outer.Version != 0 && outer.Version != 1 {
			return "unsupported_ssh_representation"
		}
		if (outer.Version == 0 && len(members) != 3) || (outer.Version == 1 && len(members) != 4) {
			return "unsupported_ssh_representation"
		}
		if len(outer.Attributes.FullBytes) > 0 {
			return "unsupported_ssh_representation"
		}
		public = outer.PublicKey
		if outer.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) {
			if len(algorithm) != 1 {
				return "unsupported_ssh_representation"
			}
			var seed []byte
			rest, err := asn1.Unmarshal(outer.PrivateKey, &seed)
			if err != nil || len(rest) != 0 || len(seed) != ed25519.SeedSize {
				return "unsupported_ssh_key"
			}
			if publicPresent {
				derived := ed25519.NewKeyFromSeed(seed)
				if public.BitLength != 256 || !bytes.Equal(public.Bytes, derived[ed25519.SeedSize:]) {
					return "unsupported_ssh_key_mismatch"
				}
			}
			return ""
		}
		if !outer.Algorithm.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}) {
			return ""
		}
		data = outer.PrivateKey
	} else if block.Type != "RSA PRIVATE KEY" {
		return ""
	}
	members, ok := onePasswordSSHASNSequence(data, 9)
	if !ok || len(members) != 9 {
		return "unsupported_ssh_representation"
	}
	for _, member := range members {
		if !onePasswordSSHASNTag(member, 0, asn1.TagInteger, false) {
			return "unsupported_ssh_representation"
		}
	}
	var key struct {
		Version               int
		N                     *big.Int
		E                     int
		D, P, Q, DP, DQ, QInv *big.Int
		Other                 []asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(data, &key)
	if err != nil || len(rest) != 0 {
		return "unsupported_ssh_key"
	}
	if key.Version != 0 || len(key.Other) != 0 || key.N == nil {
		return "unsupported_ssh_key_type"
	}
	bits := key.N.BitLen()
	if (bits != 2048 && bits != 3072 && bits != 4096) || key.E < 65537 || key.E > (1<<24)-1 || key.E&1 == 0 {
		return "unsupported_ssh_key_type"
	}
	for _, integer := range []*big.Int{key.D, key.P, key.Q, key.DP, key.DQ, key.QInv} {
		if integer == nil || integer.BitLen() > 4096 {
			return "unsupported_ssh_key_limit"
		}
	}
	if publicPresent {
		if public.BitLength != len(public.Bytes)*8 {
			return "unsupported_ssh_public_key"
		}
		var pub struct {
			N *big.Int
			E int
		}
		members, ok := onePasswordSSHASNSequence(public.Bytes, 2)
		if !ok || len(members) != 2 || !onePasswordSSHASNTag(members[0], 0, asn1.TagInteger, false) || !onePasswordSSHASNTag(members[1], 0, asn1.TagInteger, false) {
			return "unsupported_ssh_public_key"
		}
		rest, err := asn1.Unmarshal(public.Bytes, &pub)
		if err != nil || len(rest) != 0 || pub.N == nil {
			return "unsupported_ssh_public_key"
		}
		if pub.N.Cmp(key.N) != 0 || pub.E != key.E {
			return "unsupported_ssh_key_mismatch"
		}
	}
	return ""
}

// Unmarshal into RawValue and consume each member explicitly: Go's struct
// decoder intentionally ignores fields trailing inside a SEQUENCE. A key
// profile must reject those fields rather than silently canonicalizing them.
func onePasswordSSHASNSequence(data []byte, maximum int) ([]asn1.RawValue, bool) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(data, &sequence)
	if err != nil || len(rest) != 0 || !onePasswordSSHASNTag(sequence, 0, asn1.TagSequence, true) {
		return nil, false
	}
	members := make([]asn1.RawValue, 0, maximum)
	data = sequence.Bytes
	for len(data) > 0 {
		if len(members) >= maximum {
			return nil, false
		}
		var member asn1.RawValue
		rest, err := asn1.Unmarshal(data, &member)
		if err != nil || len(rest) >= len(data) {
			return nil, false
		}
		members = append(members, member)
		data = rest
	}
	return members, true
}

func onePasswordSSHASNTag(value asn1.RawValue, class, tag int, compound bool) bool {
	return value.Class == class && value.Tag == tag && value.IsCompound == compound
}

// Read only the documented OpenSSH framing through ssh.Unmarshal, before the
// maintained key parser performs RSA validation. This profile accepts one
// unencrypted key and bounds every integer to the evidenced provider sizes.
func onePasswordSSHOpenSSHBounds(block *pem.Block) string {
	if block.Type != "OPENSSH PRIVATE KEY" {
		return ""
	}
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(block.Bytes, []byte(magic)) {
		return "unsupported_ssh_key"
	}
	var wire struct {
		CipherName, KdfName, KdfOpts string
		NumKeys                      uint32
		PubKey, PrivKeyBlock         []byte
	}
	if err := ssh.Unmarshal(block.Bytes[len(magic):], &wire); err != nil {
		return "unsupported_ssh_key"
	}
	if wire.CipherName != "none" || wire.KdfName != "none" {
		return "unsupported_encrypted_ssh_key"
	}
	if wire.KdfOpts != "" || wire.NumKeys != 1 {
		return "unsupported_ssh_representation"
	}
	var common struct {
		Check1, Check2 uint32
		KeyType        string
		Rest           []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(wire.PrivKeyBlock, &common); err != nil || common.Check1 != common.Check2 {
		return "unsupported_ssh_key"
	}
	switch common.KeyType {
	case ssh.KeyAlgoED25519:
		var key struct {
			Pub, Priv []byte
			Comment   string
			Pad       []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(common.Rest, &key); err != nil {
			return "unsupported_ssh_key"
		}
		if len(key.Pub) != ed25519.PublicKeySize || len(key.Priv) != ed25519.PrivateKeySize {
			return "unsupported_ssh_key"
		}
		derived := ed25519.NewKeyFromSeed(key.Priv[:ed25519.SeedSize])
		if !bytes.Equal(derived, key.Priv) || !bytes.Equal(key.Pub, derived[ed25519.SeedSize:]) {
			return "unsupported_ssh_key_mismatch"
		}
		var public struct {
			KeyType string
			Pub     []byte
		}
		if err := ssh.Unmarshal(wire.PubKey, &public); err != nil {
			return "unsupported_ssh_public_key"
		}
		if public.KeyType != ssh.KeyAlgoED25519 || !bytes.Equal(public.Pub, key.Pub) {
			return "unsupported_ssh_key_mismatch"
		}
	case ssh.KeyAlgoRSA:
		var key struct {
			N, E, D, QInv, P, Q *big.Int
			Comment             string
			Pad                 []byte `ssh:"rest"`
		}
		if err := ssh.Unmarshal(common.Rest, &key); err != nil {
			return "unsupported_ssh_key"
		}
		if key.N == nil || key.E == nil {
			return "unsupported_ssh_key"
		}
		bits := key.N.BitLen()
		if (bits != 2048 && bits != 3072 && bits != 4096) || key.E.BitLen() > 24 || key.E.Int64() < 65537 || key.E.Int64()&1 == 0 {
			return "unsupported_ssh_key_type"
		}
		for _, integer := range []*big.Int{key.N, key.E, key.D, key.QInv, key.P, key.Q} {
			if integer == nil || integer.Sign() <= 0 || integer.BitLen() > 4096 {
				return "unsupported_ssh_key_limit"
			}
		}
		var public struct {
			KeyType string
			E, N    *big.Int
		}
		if err := ssh.Unmarshal(wire.PubKey, &public); err != nil || public.N == nil || public.E == nil {
			return "unsupported_ssh_public_key"
		}
		if public.KeyType != ssh.KeyAlgoRSA || public.N.Cmp(key.N) != 0 || public.E.Cmp(key.E) != 0 {
			return "unsupported_ssh_key_mismatch"
		}
	default:
		return "unsupported_ssh_key_type"
	}
	return ""
}

func onePasswordSSHCheckPublic(expected ssh.PublicKey, public, fingerprint string) string {
	if len(public) > onePasswordSSHMaxKeyBytes || len(fingerprint) > onePasswordSSHMaxKeyBytes {
		return "unsupported_ssh_key_limit"
	}
	line := bytes.Trim([]byte(public), " \t\r\n")
	if bytes.ContainsAny(line, "\r\n") || (!bytes.HasPrefix(line, []byte(expected.Type()+" ")) && !bytes.HasPrefix(line, []byte(expected.Type()+"\t"))) {
		return "unsupported_ssh_public_key"
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil || len(options) > 0 || len(bytes.Trim(rest, " \t\r\n")) != 0 {
		return "unsupported_ssh_public_key"
	}
	if !bytes.Equal(expected.Marshal(), key.Marshal()) {
		return "unsupported_ssh_key_mismatch"
	}
	if fingerprint != ssh.FingerprintSHA256(expected) {
		return "unsupported_ssh_fingerprint"
	}
	return ""
}
