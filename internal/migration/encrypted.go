package migration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"

	"github.com/akvartz/Bitwarden21Password/internal/providercrypto"
	"github.com/akvartz/Bitwarden21Password/internal/safearchive"
)

func KnownFormat(format Format) bool {
	return IsBrowserFormat(format) || format == BitwardenJSON || format == OnePassword1PUX || format == ProtonPassZIP
}
func IsBrowserFormat(format Format) bool {
	return format == ChromeCSV || format == FirefoxCSV || format == SafariCSV
}

func DecodePasswordJSON(data []byte) ([]byte, error) {
	if len(data) > 6<<20 {
		return nil, &SafeError{Code: "invalid_password"}
	}
	value, err := parseStrictJSON(data)
	if err != nil {
		return nil, &SafeError{Code: "invalid_password"}
	}
	text, ok := value.(string)
	if !ok || len(text) > 1<<20 {
		return nil, &SafeError{Code: "invalid_password"}
	}
	return []byte(text), nil
}

// ParseWithPassword unlocks declared provider envelopes locally. A nil password
// requests a secret prompt; a non-nil empty password remains an exact value.
func ParseWithPassword(data []byte, source Format, password []byte) (*Document, error) {
	d, err := Parse(data, source)
	if err == nil {
		return d, nil
	}
	var safe *SafeError
	if !errors.As(err, &safe) || safe.Code != "unsupported_encrypted" {
		return nil, err
	}
	if source == ProtonPassZIP || source == "" && bytes.HasPrefix(data, []byte{'P', 'K', 3, 4}) {
		files, err := safearchive.ReadZIP(data)
		if err != nil {
			return nil, &SafeError{Code: "invalid_archive"}
		}
		ciphertext, present := files["Proton Pass/data.pgp"]
		if !present {
			return nil, &SafeError{Code: "unsupported_encrypted"}
		}
		if password == nil {
			return nil, &SafeError{Code: "password_required"}
		}
		plain, err := providercrypto.UnlockProton(ciphertext, password)
		if err != nil {
			return nil, cryptoFailure(err)
		}
		delete(files, "Proton Pass/data.pgp")
		files["Proton Pass/data.json"] = plain
		payload, err := archiveProviderFiles(files)
		if err != nil {
			return nil, err
		}
		d, err := Parse(payload, ProtonPassZIP)
		if err != nil {
			return nil, err
		}
		d.original = bytes.Clone(data)
		d.inventory.Caveats = append(d.inventory.Caveats, "encrypted_source_unlocked", "encrypted_source_recovery_requires_original_password")
		return d, nil
	}
	value, err := parseStrictJSON(data)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok || root["passwordProtected"] != true {
		return nil, &SafeError{Code: "unsupported_encrypted"}
	}
	envelope, err := bitwardenEnvelope(root)
	if err != nil {
		return nil, err
	}
	if password == nil {
		return nil, &SafeError{Code: "password_required"}
	}
	plain, err := providercrypto.UnlockBitwarden(envelope, password)
	if err != nil {
		return nil, cryptoFailure(err)
	}
	d, err = Parse(plain, BitwardenJSON)
	if err != nil {
		return nil, err
	}
	d.original = bytes.Clone(data)
	metadata := flattenFields(root, "/encrypted-envelope")
	if !fieldPathBudget(root, len("/encrypted-envelope")) {
		return nil, &SafeError{Code: "field_path_limit"}
	}
	d.provider.metadata = append(d.provider.metadata, metadata...)
	if !validProviderFields(d.provider) {
		return nil, &SafeError{Code: "field_limit"}
	}
	d.inventory.MetadataFields = len(d.provider.metadata)
	d.inventory.Caveats = append(d.inventory.Caveats, "encrypted_source_unlocked", "encrypted_source_recovery_requires_original_password")
	return d, nil
}

func bitwardenEnvelope(root map[string]any) (providercrypto.BitwardenEnvelope, error) {
	invalid := &SafeError{Code: "invalid_encrypted"}
	e := providercrypto.BitwardenEnvelope{Encrypted: root["encrypted"] == true, PasswordProtected: root["passwordProtected"] == true}
	if !e.Encrypted || !e.PasswordProtected {
		return e, &SafeError{Code: "unsupported_encrypted"}
	}
	var ok bool
	if e.Salt, ok = root["salt"].(string); !ok {
		return e, invalid
	}
	if e.Validation, ok = root["encKeyValidation_DO_NOT_EDIT"].(string); !ok {
		return e, invalid
	}
	if e.Data, ok = root["data"].(string); !ok {
		return e, invalid
	}
	for _, field := range []struct {
		name     string
		dst      *int
		required bool
	}{{"kdfType", &e.KDFType, true}, {"kdfIterations", &e.KDFIterations, true}, {"kdfMemory", &e.KDFMemory, false}, {"kdfParallelism", &e.KDFParallelism, false}} {
		value, present := root[field.name]
		if !present && !field.required {
			continue
		}
		number, ok := value.(json.Number)
		if !ok {
			return e, invalid
		}
		v, err := strconv.Atoi(number.String())
		if err != nil {
			return e, invalid
		}
		*field.dst = v
	}
	if e.KDFType != 0 && e.KDFType != 1 {
		return e, &SafeError{Code: "unsupported_kdf"}
	}
	return e, nil
}

func cryptoFailure(err error) error {
	var safe *providercrypto.Error
	if errors.As(err, &safe) {
		return &SafeError{Code: safe.Error()}
	}
	return &SafeError{Code: "invalid_encrypted"}
}

func archiveProviderFiles(files map[string][]byte) ([]byte, error) {
	keys := make([]string, 0, len(files))
	total := 0
	for name, value := range files {
		total += len(value)
		if total > MaxInputBytes {
			return nil, &SafeError{Code: "input_limit"}
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	for _, name := range keys {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0600)
		entry, err := w.CreateHeader(header)
		if err != nil {
			return nil, &SafeError{Code: "invalid_archive"}
		}
		if _, err := entry.Write(files[name]); err != nil {
			return nil, &SafeError{Code: "invalid_archive"}
		}
	}
	if w.Close() != nil {
		return nil, &SafeError{Code: "invalid_archive"}
	}
	if buffer.Len() > MaxInputBytes {
		return nil, &SafeError{Code: "input_limit"}
	}
	return buffer.Bytes(), nil
}
