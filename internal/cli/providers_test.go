package cli

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/akvartz/Bitwarden21Password/internal/recovery"
	"github.com/akvartz/Bitwarden21Password/internal/testsupport"
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
	testsupport.AssertPrivate(t, filepath.Dir(keyPath), true)
	testsupport.AssertPrivate(t, keyPath, false)
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
	testsupport.AssertPrivate(t, filepath.Join(outputParent, receipt.JobDirectory), true)
	testsupport.AssertPrivate(t, filepath.Join(outputParent, receipt.JobDirectory, receipt.FileName), false)
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

func TestBinaryProviderConversionAndRecoveryJourneys(t *testing.T) {
	requireLinuxOutput(t)
	binary := buildSyntheticCLI(t)
	const original = "name,url,username,password\nSYNTHETIC_SELECTED,https://synthetic.invalid, user ,\" exact\r\nsecret \"\nSYNTHETIC_EXCLUDED,https://synthetic.invalid,other,second\n"
	input := inputFixture(t, original)
	keyParent := privateOutputParent(t)
	keyReceipt := binaryArtifactCommand(t, binary, []string{"recovery-key", "--output-dir", keyParent, "--json"})
	if keyReceipt.FileName != "recovery-key.txt" {
		t.Fatal("binary key command returned an unexpected artifact")
	}
	keyPath := filepath.Join(keyParent, keyReceipt.JobDirectory, keyReceipt.FileName)
	testsupport.AssertPrivate(t, filepath.Dir(keyPath), true)
	testsupport.AssertPrivate(t, keyPath, false)
	for _, target := range []struct{ format, name string }{{"bitwarden-json", "bitwarden.json"}, {"onepassword-1pux", "onepassword.1pux"}, {"proton-pass-zip", "proton-pass.zip"}} {
		t.Run(target.format, func(t *testing.T) {
			parent := privateOutputParent(t)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			args := []string{"convert", "--input", input, "--to", target.format, "--select", "1", "--output-dir", parent, "--recovery-key-file", keyPath, "--json"}
			cmd := exec.CommandContext(ctx, binary, args...)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal("binary approval channel unavailable")
			}
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal("binary review channel unavailable")
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal("binary conversion did not start")
			}
			reader := bufio.NewReader(stdout)
			line, err := reader.ReadString('\n')
			if err != nil {
				_ = stdin.Close()
				_ = cmd.Wait()
				t.Fatal("binary conversion omitted review")
			}
			var review observedEvent
			if json.Unmarshal([]byte(line), &review) != nil || review.Event != "review" || review.Review.Plan.SelectedRecords != 1 || review.Review.Plan.ExcludedRecords != 1 {
				t.Fatal("binary review changed selected scope")
			}
			retention := false
			for _, issue := range review.Review.Issues {
				if issue.ID == "recovery-whole-source" {
					retention = true
				}
			}
			if !retention {
				t.Fatal("binary review omitted whole-source retention acknowledgment")
			}
			if _, err := io.WriteString(stdin, protocolApproval(review.Review)); err != nil {
				t.Fatal("binary exact acknowledgment failed")
			}
			_ = stdin.Close()
			remaining, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal("binary conversion completion unreadable")
			}
			if processExit(t, cmd.Wait()) != 0 || ctx.Err() != nil {
				t.Fatal("binary conversion failed")
			}
			var completed struct {
				Event   string `json:"event"`
				Receipt struct {
					JobDirectory         string `json:"job_directory"`
					FileName             string `json:"file_name"`
					RecoveryJobDirectory string `json:"recovery_job_directory"`
					RecoveryFileName     string `json:"recovery_file_name"`
					Plan                 struct {
						Verified bool `json:"destination_import_verified"`
					} `json:"plan"`
				} `json:"receipt"`
			}
			if json.Unmarshal(bytes.TrimSpace(remaining), &completed) != nil || completed.Event != "completed" || completed.Receipt.FileName != target.name || completed.Receipt.RecoveryFileName != "recovery.age" || completed.Receipt.Plan.Verified {
				t.Fatal("binary completion misrepresented local artifacts or provider evidence")
			}
			output := filepath.Join(parent, completed.Receipt.JobDirectory, completed.Receipt.FileName)
			testsupport.AssertPrivate(t, filepath.Dir(output), true)
			testsupport.AssertPrivate(t, output, false)
			assertBinaryDestinationPassword(t, output, target.format, " exact\r\nsecret ")
			recoveryPath := filepath.Join(parent, completed.Receipt.RecoveryJobDirectory, completed.Receipt.RecoveryFileName)
			testsupport.AssertPrivate(t, filepath.Dir(recoveryPath), true)
			testsupport.AssertPrivate(t, recoveryPath, false)
			recoveryParent := privateOutputParent(t)
			restored := binaryArtifactCommand(t, binary, []string{"recover", "--input", recoveryPath, "--key-file", keyPath, "--output-dir", recoveryParent, "--json"})
			if restored.FileName != "source.csv" {
				t.Fatal("binary recovery returned an unexpected source artifact")
			}
			restoredPath := filepath.Join(recoveryParent, restored.JobDirectory, restored.FileName)
			got, err := os.ReadFile(restoredPath)
			if err != nil || string(got) != original {
				t.Fatal("binary recovery changed or excluded original source bytes")
			}
			testsupport.AssertPrivate(t, filepath.Dir(restoredPath), true)
			testsupport.AssertPrivate(t, restoredPath, false)
			assertRedacted(t, line+string(remaining)+stderr.String(), input, keyPath, parent)
		})
	}
}

func binaryArtifactCommand(t *testing.T, binary string, args []string) struct{ JobDirectory, FileName string } {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if cmd.Run() != nil || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatal("binary private artifact command failed")
	}
	var receipt struct {
		JobDirectory string `json:"job_directory"`
		FileName     string `json:"file_name"`
	}
	if json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt.JobDirectory == "" || receipt.FileName == "" || strings.Contains(stdout.String(), "AGE-SECRET-KEY") {
		t.Fatal("binary artifact receipt was invalid or exposed a key")
	}
	return struct{ JobDirectory, FileName string }{receipt.JobDirectory, receipt.FileName}
}

func assertBinaryDestinationPassword(t *testing.T, path, format, expected string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("binary destination artifact unavailable")
	}
	if format != "bitwarden-json" {
		archive, err := zip.NewReader(bytes.NewReader(payload), int64(len(payload)))
		if err != nil {
			t.Fatal("binary destination archive invalid")
		}
		name := "export.data"
		if format == "proton-pass-zip" {
			name = "Proton Pass/data.json"
		}
		present := false
		for _, file := range archive.File {
			if file.Name == name {
				reader, err := file.Open()
				if err != nil {
					t.Fatal("binary native payload unavailable")
				}
				payload, err = io.ReadAll(reader)
				closeErr := reader.Close()
				if err != nil || closeErr != nil {
					t.Fatal("binary native payload unreadable")
				}
				present = true
			}
		}
		if !present {
			t.Fatal("binary native archive entry omitted")
		}
	}
	var root map[string]any
	if json.Unmarshal(payload, &root) != nil {
		t.Fatal("binary destination JSON invalid")
	}
	var items []any
	switch format {
	case "bitwarden-json":
		items, _ = root["items"].([]any)
	case "onepassword-1pux":
		accounts, _ := root["accounts"].([]any)
		if len(accounts) != 1 {
			t.Fatal("binary native account shape invalid")
		}
		account, _ := accounts[0].(map[string]any)
		vaults, _ := account["vaults"].([]any)
		if len(vaults) != 1 {
			t.Fatal("binary native vault shape invalid")
		}
		vault, _ := vaults[0].(map[string]any)
		items, _ = vault["items"].([]any)
	case "proton-pass-zip":
		vaults, _ := root["vaults"].(map[string]any)
		if len(vaults) != 1 {
			t.Fatal("binary native vault shape invalid")
		}
		for _, raw := range vaults {
			vault, _ := raw.(map[string]any)
			items, _ = vault["items"].([]any)
		}
	}
	if len(items) != 1 {
		t.Fatal("binary destination changed selection multiplicity")
	}
	item, _ := items[0].(map[string]any)
	var password any
	switch format {
	case "bitwarden-json":
		login, _ := item["login"].(map[string]any)
		password = login["password"]
	case "proton-pass-zip":
		data, _ := item["data"].(map[string]any)
		content, _ := data["content"].(map[string]any)
		password = content["password"]
	case "onepassword-1pux":
		details, _ := item["details"].(map[string]any)
		fields, _ := details["loginFields"].([]any)
		for _, raw := range fields {
			field, _ := raw.(map[string]any)
			if field["designation"] == "password" {
				password = field["value"]
			}
		}
	}
	if password != expected {
		t.Fatal("binary destination changed exact credential bytes")
	}
}
