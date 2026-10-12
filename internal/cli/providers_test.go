package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/recovery"
)

func cliArchiveFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for name, data := range files {
		entry, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "synthetic-export.zip")
	if err := os.WriteFile(path, out.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIPlansAllDeclaredDirectionalProviderRoutes(t *testing.T) {
	sources := []struct{ format, path string }{
		{"bitwarden-json", inputFixture(t, `{"encrypted":false,"items":[{"type":2,"name":"PRIVATE_TITLE","notes":" exact private note "}]}`)},
		{"onepassword-1pux", cliArchiveFixture(t, map[string]string{"export.attributes": `{"version":3,"description":"1Password Unencrypted Export"}`, "export.data": `{"accounts":[{"attrs":{},"vaults":[{"attrs":{},"items":[{"categoryUuid":"003","overview":{"title":"PRIVATE_TITLE"},"details":{"notesPlain":" exact private note "}}]}]}]}`})},
		{"proton-pass-zip", cliArchiveFixture(t, map[string]string{"Proton Pass/data.json": `{"version":"1.42.0","vaults":{"synthetic":{"name":"PRIVATE_VAULT","items":[{"data":{"type":"note","metadata":{"name":"PRIVATE_TITLE","note":" exact private note "},"content":{},"extraFields":[]},"state":1,"pinned":false}]}}}`})},
	}
	for _, source := range sources {
		for _, target := range []string{"bitwarden-json", "onepassword-1pux", "proton-pass-zip"} {
			if target == source.format {
				continue
			}
			code, stdout, stderr := invoke("plan", "--input", source.path, "--to", target, "--vault", "1", "--kind", "secure_note", "--json")
			if code != 0 || stderr != "" {
				t.Fatal("declared provider route did not plan through the CLI")
			}
			var plan struct {
				Source, Target, State string
				Selected              int  `json:"selected_records"`
				Output                bool `json:"output_emitted"`
				Verified              bool `json:"destination_import_verified"`
			}
			if json.Unmarshal([]byte(stdout), &plan) != nil || plan.Source != source.format || plan.Target != target || plan.State != "planned" || plan.Selected != 1 || plan.Output || plan.Verified {
				t.Fatal("provider CLI route misrepresented evidence or scope")
			}
			if strings.Contains(stdout, "PRIVATE_") || strings.Contains(stdout, "exact private note") || strings.Contains(stdout, source.path) {
				t.Fatal("provider CLI route leaked source payload")
			}
		}
	}
}

func TestCLIPlansDeclaredBrowserSchemasToEveryProvider(t *testing.T) {
	for _, source := range []struct{ format, fixture string }{
		{"chrome-csv", "name,url,username,password\nsynthetic-title,url,user,secret\n"},
		{"firefox-csv", "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\nurl,user,secret,,,,,,\n"},
		{"safari-csv", "Title,URL,Username,Password,Notes,OTPAuth\nsynthetic-title,url,user,secret,note,otpauth://synthetic\n"},
	} {
		path := inputFixture(t, source.fixture)
		for _, target := range []string{"bitwarden-json", "onepassword-1pux", "proton-pass-zip"} {
			code, stdout, stderr := invoke("plan", "--input", path, "--to", target, "--kind", "login", "--json")
			if code != 0 || stderr != "" {
				t.Fatal("declared browser route did not plan through CLI detection")
			}
			var plan struct {
				Source, Target, State string
				Selected              int  `json:"selected_records"`
				Output                bool `json:"output_emitted"`
			}
			if json.Unmarshal([]byte(stdout), &plan) != nil || plan.Source != source.format || plan.Target != target || plan.State != "planned" || plan.Selected != 1 || plan.Output {
				t.Fatal("browser route misrepresented source scope")
			}
		}
	}
}

const cliRichBitwarden = `{"encrypted":false,"folders":[{"id":"synthetic-folder-a","name":"PRIVATE_FOLDER_A"},{"id":"synthetic-folder-b","name":"PRIVATE_FOLDER_B"}],"items":[{"type":1,"name":"PRIVATE_ITEM_A","folderId":"synthetic-folder-a","login":{"username":" user ","password":" password "}},{"type":2,"name":"PRIVATE_ITEM_B","folderId":"synthetic-folder-a","notes":" note "},{"type":1,"name":"PRIVATE_ITEM_C","folderId":"synthetic-folder-b","login":{"username":" other ","password":" other "}}]}`

func TestProviderPlanFiltersIntersectAndAccountMetadata(t *testing.T) {
	path := inputFixture(t, cliRichBitwarden)
	code, stdout, stderr := invoke("plan", "--input", path, "--to", "onepassword-1pux", "--select", "3,1", "--vault", "1", "--folder", "1", "--kind", "login,card", "--json")
	if code != 0 || stderr != "" {
		t.Fatal("provider selection plan rejected")
	}
	var got struct {
		Selected int `json:"selected_records"`
		Excluded int `json:"excluded_records"`
		Fields   []struct {
			Record int `json:"record"`
		}
		Metadata []struct {
			Disposition string `json:"disposition"`
		}
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Selected != 1 || got.Excluded != 2 || len(got.Metadata) == 0 {
		t.Fatal("provider plan omitted scope or metadata")
	}
	for _, f := range got.Fields {
		if f.Record != 1 {
			t.Fatal("filters did not intersect source ordinals")
		}
	}
	if strings.Contains(stdout, "PRIVATE_") || strings.Contains(stdout, " password ") || strings.Contains(stdout, path) {
		t.Fatal("provider plan leaked data")
	}
}

func TestCompareCLIReportsSuppliedExportMultiplicity(t *testing.T) {
	source := inputFixture(t, "name,url,username,password\na,b,c,d\na,b,c,d\n")
	destination := inputFixture(t, `{"encrypted":false,"items":[{"type":1,"name":"a","login":{"username":"c","password":"d","uris":[{"uri":"b"}]},"fields":[]}]}`)
	for _, asJSON := range []bool{false, true} {
		args := []string{"compare", "--input", source, "--to", "bitwarden-json", "--destination", destination, "--kind", "login"}
		if asJSON {
			args = append(args, "--json")
		}
		code, stdout, stderr := invoke(args...)
		if code != 0 || stderr != "" {
			t.Fatal("comparison command rejected independent destination")
		}
		if asJSON {
			var got struct {
				State    string `json:"state"`
				Matched  int    `json:"matched_records"`
				Missing  int    `json:"missing_records"`
				Verified bool   `json:"destination_import_verified"`
				Groups   []struct {
					Code   string `json:"code"`
					Source []int  `json:"source_records"`
				} `json:"groups"`
			}
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatal(err)
			}
			if got.State != "destination_compared" || got.Matched != 1 || got.Missing != 1 || got.Verified || len(got.Groups) != 1 || got.Groups[0].Code != "ambiguous_match" || len(got.Groups[0].Source) != 2 {
				t.Fatal("comparison misrepresented duplicate observations")
			}
		} else {
			for _, term := range []string{"destination_compared", "matched_records: 1", "missing_records: 1", "ambiguous_match", "unverified"} {
				if !strings.Contains(stdout, term) {
					t.Fatal("human comparison omitted observation limits")
				}
			}
		}
		if strings.Contains(stdout+stderr, source) || strings.Contains(stdout+stderr, destination) {
			t.Fatal("comparison exposed input paths")
		}
	}
}

func TestProviderHumanReviewExplainsExactLossLocations(t *testing.T) {
	requireLinuxOutput(t)
	path := inputFixture(t, cliRichBitwarden)
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	code := RunContext(context.Background(), []string{"convert", "--input", path, "--to", "onepassword-1pux", "--output-dir", parent, "--select", "1"}, strings.NewReader(""), &stdout, &stderr)
	if code != 3 || !strings.HasSuffix(stderr.String(), "approval_required\n") {
		t.Fatal("provider conversion skipped explicit review")
	}
	for _, term := range []string{"metadata field", "required_issue:", "record 1 field", "unsupported", "experimental"} {
		if !strings.Contains(stdout.String()+stderr.String(), term) {
			t.Fatal("human provider review omitted exact loss scope")
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "PRIVATE_") || strings.Contains(stdout.String()+stderr.String(), path) {
		t.Fatal("provider review leaked source labels")
	}
	assertNoExport(t, parent)
}

func TestRecoveryCommandsRoundTripExactWholeSourceWithoutReportingKey(t *testing.T) {
	requireLinuxOutput(t)
	parent := privateOutputParent(t)
	code, stdout, stderr := invoke("recovery-key", "--output-dir", parent, "--json")
	if code != 0 || stderr != "" {
		t.Fatal("private recovery key generation rejected")
	}
	var keyReceipt struct {
		JobDirectory string `json:"job_directory"`
		FileName     string `json:"file_name"`
	}
	if err := json.Unmarshal([]byte(stdout), &keyReceipt); err != nil || keyReceipt.FileName != "recovery-key.txt" {
		t.Fatal("key receipt missing fixed output identity")
	}
	keyPath := filepath.Join(parent, keyReceipt.JobDirectory, keyReceipt.FileName)
	key, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, string(bytes.TrimSpace(key))) || strings.Contains(stdout, "AGE-SECRET-KEY") {
		t.Fatal("key escaped into report")
	}
	const source = "name,url,username,password\r\n\" exact title \",url,user,\" exact secret \"\r\n"
	ciphertext, err := recovery.Encrypt("chrome-csv", []byte(source), key)
	if err != nil {
		t.Fatal(err)
	}
	cipherPath := filepath.Join(t.TempDir(), "synthetic.age")
	if err := os.WriteFile(cipherPath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	outputParent := privateOutputParent(t)
	code, stdout, stderr = invoke("recover", "--input", cipherPath, "--key-file", keyPath, "--output-dir", outputParent, "--json")
	if code != 0 || stderr != "" {
		t.Fatal("authenticated recovery rejected")
	}
	var receipt struct {
		JobDirectory string `json:"job_directory"`
		FileName     string `json:"file_name"`
	}
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || receipt.FileName != "source.csv" {
		t.Fatal("recovery receipt missing fixed source identity")
	}
	got, err := os.ReadFile(filepath.Join(outputParent, receipt.JobDirectory, receipt.FileName))
	if err != nil || string(got) != source {
		t.Fatal("recovery changed original source bytes")
	}
	if strings.Contains(stdout+stderr, "exact secret") || strings.Contains(stdout+stderr, "AGE-SECRET-KEY") || strings.Contains(stdout+stderr, cipherPath) || strings.Contains(stdout+stderr, keyPath) {
		t.Fatal("recovery reports leaked material")
	}
}

func TestConvertRecoveryRetainsExcludedSourceAndRequiresExactIssue(t *testing.T) {
	requireLinuxOutput(t)
	const original = "name,url,username,password\nfirst,url,user, exact password \nexcluded,url,user,other\n"
	source := inputFixture(t, original)
	identity, err := recovery.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)
	keyPath := filepath.Join(t.TempDir(), "synthetic-key.txt")
	if err := os.WriteFile(keyPath, identity, 0600); err != nil {
		t.Fatal(err)
	}
	for _, acceptRecovery := range []bool{false, true} {
		parent := privateOutputParent(t)
		var stdout, stderr bytes.Buffer
		approval := &promptReply{prompt: &stderr}
		if !acceptRecovery {
			approval.transform = func(line string) string { return strings.Replace(line, " recovery-whole-source", "", 1) }
		}
		args := []string{"convert", "--input", source, "--to", "bitwarden-json", "--select", "1", "--output-dir", parent, "--recovery-key-file", keyPath, "--json"}
		code := RunContext(context.Background(), args, approval, &stdout, &stderr)
		if !acceptRecovery {
			if code != 3 || !strings.HasSuffix(stderr.String(), "approval_invalid\n") {
				t.Fatal("whole-source retention did not require exact issue acknowledgment")
			}
			assertNoExport(t, parent)
			continue
		}
		if code != 0 {
			t.Fatal("explicit recovery acknowledgment did not convert")
		}
		var completed struct {
			Receipt struct {
				RecoveryJobDirectory string `json:"recovery_job_directory"`
				RecoveryFileName     string `json:"recovery_file_name"`
			} `json:"receipt"`
		}
		lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
		if len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &completed) != nil || completed.Receipt.RecoveryFileName != "recovery.age" {
			t.Fatal("completion omitted fixed recovery location")
		}
		ciphertext, err := os.ReadFile(filepath.Join(parent, completed.Receipt.RecoveryJobDirectory, completed.Receipt.RecoveryFileName))
		if err != nil {
			t.Fatal(err)
		}
		payload, err := recovery.Decrypt(ciphertext, identity)
		if err != nil || string(payload.Source) != original || payload.Format != "chrome-csv" {
			t.Fatal("recovery omitted excluded records or changed source bytes")
		}
		for _, stage := range []string{"reading", "reviewing", "writing_and_validating", "recovery"} {
			if !strings.Contains(stderr.String(), "progress: "+stage+"\n") {
				t.Fatal("conversion omitted fixed progress stage")
			}
		}
		if strings.Contains(stdout.String()+stderr.String(), "exact password") || strings.Contains(stdout.String()+stderr.String(), "AGE-SECRET-KEY") || strings.Contains(stdout.String()+stderr.String(), keyPath) {
			t.Fatal("recovery conversion leaked private data")
		}
	}
}

func TestRecoverRejectsTamperedCiphertextBeforeAnyWrite(t *testing.T) {
	requireLinuxOutput(t)
	identity, err := recovery.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)
	ciphertext, err := recovery.Encrypt("chrome-csv", []byte("synthetic original bytes"), identity)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 1
	keyPath := filepath.Join(t.TempDir(), "synthetic-key.txt")
	cipherPath := filepath.Join(t.TempDir(), "synthetic-cipher.age")
	if err := os.WriteFile(keyPath, identity, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cipherPath, ciphertext, 0600); err != nil {
		t.Fatal(err)
	}
	parent := privateOutputParent(t)
	code, stdout, stderr := invoke("recover", "--input", cipherPath, "--key-file", keyPath, "--output-dir", parent, "--json")
	if code != 3 || stdout != "" || stderr != "recovery_authentication\n" {
		t.Fatal("tamper did not fail with safe authentication code")
	}
	assertNoExport(t, parent)
}

func TestRecoveryKeyLimitUsesActualBytesAndClosesHandle(t *testing.T) {
	stream := &syntheticStream{remaining: recoveryKeyFileLimit + 100}
	file := &testInput{reader: stream, info: testFileInfo{mode: 0600, size: 1}}
	_, err := readLimitedInput("synthetic-key-path", func(string) (inputFile, error) { return file, nil }, recoveryKeyFileLimit, "recovery_identity")
	if err == nil || err.Error() != "recovery_identity" || !file.closed || stream.read != recoveryKeyFileLimit+1 {
		t.Fatal("key loader trusted stale size or exceeded actual-byte bound")
	}
}

func TestRecoverySavePreservesUnsupportedOriginalWithoutParsing(t *testing.T) {
	requireLinuxOutput(t)
	identity, err := recovery.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(identity)
	keyPath := filepath.Join(t.TempDir(), "synthetic-key.txt")
	if err := os.WriteFile(keyPath, identity, 0600); err != nil {
		t.Fatal(err)
	}
	original := append([]byte("unsupported synthetic original\x00\r\n"), 0xff)
	input := filepath.Join(t.TempDir(), "synthetic-original.bin")
	if err := os.WriteFile(input, original, 0600); err != nil {
		t.Fatal(err)
	}
	parent := privateOutputParent(t)
	code, stdout, stderr := invoke("recovery-save", "--input", input, "--from", "bitwarden-json", "--key-file", keyPath, "--output-dir", parent, "--json")
	if code != 0 || stderr != "" {
		t.Fatal("unsupported original could not be privately retained")
	}
	var receipt struct {
		JobDirectory string `json:"job_directory"`
		FileName     string `json:"file_name"`
		Retention    string `json:"retention"`
		SourceBytes  int    `json:"source_bytes"`
	}
	if json.Unmarshal([]byte(stdout), &receipt) != nil || receipt.FileName != "recovery.age" || receipt.Retention != "whole_source_not_migrated" || receipt.SourceBytes != len(original) {
		t.Fatal("retention receipt misrepresented recovery as migration")
	}
	ciphertext, err := os.ReadFile(filepath.Join(parent, receipt.JobDirectory, receipt.FileName))
	if err != nil {
		t.Fatal(err)
	}
	retained, err := recovery.Decrypt(ciphertext, identity)
	if err != nil || retained.Format != "bitwarden-json" || !bytes.Equal(retained.Source, original) {
		t.Fatal("recovery-save changed failed original bytes")
	}
	if strings.Contains(stdout+stderr, "unsupported synthetic") || strings.Contains(stdout+stderr, "AGE-SECRET-KEY") || strings.Contains(stdout+stderr, input) || strings.Contains(stdout+stderr, keyPath) {
		t.Fatal("recovery-save reported private contents or paths")
	}
}
