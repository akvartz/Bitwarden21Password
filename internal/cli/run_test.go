package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/akvartz/Bitwarden21Password/internal/migration"
)

const syntheticCSV = "name,url,username,password,note,SYNTHETIC_CUSTOM_LABEL\n" +
	"SYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD_A,SYNTHETIC_NOTE,SYNTHETIC_CUSTOM_VALUE\n" +
	"SYNTHETIC_TITLE,https://synthetic.invalid,SYNTHETIC_USER,SYNTHETIC_PASSWORD_B,SYNTHETIC_NOTE,SYNTHETIC_CUSTOM_VALUE\n" +
	"SYNTHETIC_OTHER,https://other.invalid,SYNTHETIC_OTHER_USER,SYNTHETIC_PASSWORD_C,,\n"

func inputFixture(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "SYNTHETIC_PRIVATE_PATH.csv")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func invoke(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func assertRedacted(t *testing.T, output string, extra ...string) {
	t.Helper()
	sentinels := []string{"SYNTHETIC_", "https://synthetic.invalid", "https://other.invalid"}
	sentinels = append(sentinels, extra...)
	for _, sentinel := range sentinels {
		if sentinel != "" && strings.Contains(output, sentinel) {
			t.Fatalf("report exposed a synthetic private sentinel")
		}
	}
}

func TestInspectReportsSafeInventory(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	code, stdout, stderr := invoke("inspect", "--input", path, "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("want success with empty stderr, got exit %d", code)
	}
	var got migration.Inventory
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON report: %v", err)
	}
	if got.Format != "chrome-csv" || got.Records != 3 || got.Fields != 18 || got.MetadataFields != 0 {
		t.Fatalf("incorrect inventory counts: %+v", got)
	}
	if got.Kinds["login"] != 3 || got.DuplicateDetection != "exact_name_url_username" || !reflect.DeepEqual(got.DuplicateGroups, [][]int{{1, 2}}) {
		t.Fatalf("duplicates or kinds missing: %+v", got)
	}
	if !reflect.DeepEqual(got.Caveats, []string{"source_export_may_omit_account_data", "chrome_csv_limited_export"}) {
		t.Fatalf("missing coverage caveats: %v", got.Caveats)
	}
	assertRedacted(t, stdout+stderr, path)
}

func TestInspectBitwardenKeepsMetadataAndUnknownFieldsPrivate(t *testing.T) {
	path := inputFixture(t, `{"encrypted":false,"items":[{"type":1,"name":"SYNTHETIC_TITLE","login":{"username":"SYNTHETIC_USER","password":"SYNTHETIC_PASSWORD","totp":null},"SYNTHETIC_CUSTOM_LABEL":"SYNTHETIC_CUSTOM_VALUE"}],"folders":[],"SYNTHETIC_ROOT_LABEL":"SYNTHETIC_ROOT_VALUE"}`)
	code, stdout, stderr := invoke("inspect", "--input", path, "--from", "bitwarden-json", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("want success, got exit %d", code)
	}
	var got migration.Inventory
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if got.Records != 1 || got.Fields != 6 || got.MetadataFields != 3 || got.Kinds["login"] != 1 || got.DuplicateDetection != "not_evaluated" {
		t.Fatalf("incorrect Bitwarden accounting: %+v", got)
	}
	assertRedacted(t, stdout+stderr, path)
}

func TestEmptyExportProducesZeroRecordReports(t *testing.T) {
	path := inputFixture(t, "name,url,username,password\n")
	for _, command := range []string{"inspect", "plan"} {
		t.Run(command, func(t *testing.T) {
			args := []string{command, "--input", path, "--json"}
			if command == "plan" {
				args = append(args, "--to", "bitwarden-json")
			}
			code, stdout, stderr := invoke(args...)
			if code != 0 || stderr != "" {
				t.Fatalf("empty export failed: exit %d", code)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatal(err)
			}
			if command == "inspect" && string(got["records"]) != "0" {
				t.Fatal("empty inventory must have zero records")
			}
			if command == "plan" && (string(got["selected_records"]) != "0" || string(got["fields"]) != "[]" || string(got["output_emitted"]) != "false") {
				t.Fatal("empty plan must not invent records or output")
			}
		})
	}
}

func TestPlanSelectionAccountsForFieldsAndEvidence(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	cases := []struct {
		name               string
		selection          []string
		selected, excluded int
		records            []int
		duplicates         [][]int
	}{
		{"all", nil, 3, 0, []int{1, 2, 3}, [][]int{{1, 2}}},
		{"source_order", []string{"--select", "3,1"}, 2, 1, []int{1, 3}, [][]int{}},
		{"retains_duplicates", []string{"--select", "2,1"}, 2, 1, []int{1, 2}, [][]int{{1, 2}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"plan", "--input", path, "--to", "bitwarden-json", "--json"}
			args = append(args, tc.selection...)
			code, stdout, stderr := invoke(args...)
			if code != 0 || stderr != "" {
				t.Fatalf("plan failed: exit %d", code)
			}
			var got migration.Plan
			if err := json.Unmarshal([]byte(stdout), &got); err != nil {
				t.Fatal(err)
			}
			if got.Source != "chrome-csv" || got.Target != "bitwarden-json" || got.State != "planned" || got.OutputEmitted || got.DestinationImportVerified {
				t.Fatalf("incorrect evidence: %+v", got)
			}
			if got.TotalRecords != 3 || got.SelectedRecords != tc.selected || got.ExcludedRecords != tc.excluded || len(got.Fields) != tc.selected*6 || !reflect.DeepEqual(got.DuplicateGroups, tc.duplicates) {
				t.Fatalf("incorrect selected accounting: %+v", got)
			}
			labels := []string{"name", "login.uris[0].uri", "login.username", "login.password", "notes", "fields"}
			for i, field := range got.Fields {
				if field.Record != tc.records[i/6] || field.Field != i%6+1 || field.TargetField != labels[i%6] {
					t.Fatalf("incorrect field outcome at index %d", i)
				}
				if i%6 == 5 {
					if field.Disposition != "relocated" || !field.Concealed {
						t.Fatal("unknown column must relocate concealed")
					}
				} else if field.Disposition != "native" || field.Concealed {
					t.Fatal("known column must have native disposition")
				}
			}
			assertRedacted(t, stdout+stderr, path)
		})
	}
}

func TestHumanReportsUseSafeSummaries(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	cases := []struct {
		args  []string
		terms []string
	}{
		{[]string{"inspect", "--input", path}, []string{"chrome-csv", "records: 3", "fields: 18", "duplicate_groups: 1", "source_export_may_omit_account_data"}},
		{[]string{"plan", "--input", path, "--to", "bitwarden-json", "--select", "3,1"}, []string{"state: planned", "selected_records: 2", "excluded_records: 1", "output_emitted: false", "destination_import_verified: false", "relocated", "record 1 field 6"}},
	}
	for _, tc := range cases {
		code, stdout, stderr := invoke(tc.args...)
		if code != 0 || stderr != "" {
			t.Fatalf("human summary failed: exit %d", code)
		}
		for _, term := range tc.terms {
			if !strings.Contains(stdout, term) {
				t.Fatalf("missing safe summary %q", term)
			}
		}
		assertRedacted(t, stdout+stderr, path)
	}
}

func TestFormatsExposeOnlyM1Capabilities(t *testing.T) {
	code, stdout, stderr := invoke("formats", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("formats failed: exit %d", code)
	}
	var got struct {
		Formats []struct {
			ID          string   `json:"id"`
			Inspect     bool     `json:"inspect"`
			PlanTargets []string `json:"plan_targets"`
		} `json:"formats"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Formats) != 2 || got.Formats[0].ID != "chrome-csv" || got.Formats[1].ID != "bitwarden-json" || !got.Formats[0].Inspect || !got.Formats[1].Inspect || !reflect.DeepEqual(got.Formats[0].PlanTargets, []string{"bitwarden-json"}) || len(got.Formats[1].PlanTargets) != 0 {
		t.Fatalf("formats claim unsupported capabilities: %+v", got)
	}
	code, stdout, stderr = invoke("formats")
	if code != 0 || stderr != "" || !strings.Contains(stdout, "chrome-csv") || !strings.Contains(stdout, "bitwarden-json") || strings.Contains(stdout, "1password") {
		t.Fatal("human formats must describe the supported routes")
	}
	for _, term := range []string{"experimental convert to bitwarden-json on Linux", "explicit approval", "Other platforms: read-only", "Destination imports unverified"} {
		if !strings.Contains(stdout, term) {
			t.Fatalf("human formats omitted capability or limitation %q", term)
		}
	}
}

func TestHelpSucceedsWithoutReadingInputs(t *testing.T) {
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}, {"inspect", "--help"}, {"plan", "--help"}, {"formats", "--help"}, {"version", "--help"}} {
		code, stdout, stderr := invoke(args...)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "pwmigrate-go inspect") || !strings.Contains(stdout, "pwmigrate-go plan") || !strings.Contains(stdout, "pwmigrate-go version [--json]") {
			t.Fatalf("help failed: exit %d", code)
		}
	}
}

func TestVersionReportsBuildMetadataWithoutReadingExports(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}, {"version", "--json"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr, func(string) (inputFile, error) {
				t.Fatal("version must not open an export")
				return nil, errors.New("unexpected export read")
			})
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("version failed: exit %d, stderr %q", code, stderr.String())
			}
			if len(args) == 2 {
				var got map[string]string
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				want := map[string]string{
					"program": "pwmigrate-go", "version": "dev", "commit": "unknown",
					"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("unexpected build metadata: got %v, want %v", got, want)
				}
			} else {
				for _, term := range []string{"pwmigrate-go", "dev", "unknown", runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
					if !strings.Contains(stdout.String(), term) {
						t.Fatalf("version omitted %q", term)
					}
				}
			}
		})
	}
}

func TestArgumentErrorsAreRedacted(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	cases := []struct {
		name string
		args []string
	}{
		{"unknown_command", []string{"SYNTHETIC_COMMAND"}},
		{"missing_input", []string{"inspect"}},
		{"empty_input", []string{"inspect", "--input="}},
		{"missing_target", []string{"plan", "--input", path}},
		{"empty_target", []string{"plan", "--input", path, "--to="}},
		{"unknown_flag", []string{"inspect", "--input", path, "--SYNTHETIC_FLAG=SYNTHETIC_VALUE"}},
		{"invalid_bool", []string{"inspect", "--input", path, "--json=SYNTHETIC_BOOL"}},
		{"missing_flag_value", []string{"inspect", "--input"}},
		{"positional", []string{"inspect", "--input", path, "SYNTHETIC_POSITIONAL"}},
		{"after_double_dash", []string{"inspect", "--input", path, "--", "SYNTHETIC_POSITIONAL"}},
		{"irrelevant_target", []string{"inspect", "--input", path, "--to", "bitwarden-json"}},
		{"irrelevant_selection", []string{"inspect", "--input", path, "--select", "1"}},
		{"irrelevant_input", []string{"formats", "--input", path}},
		{"irrelevant_source", []string{"formats", "--from", "chrome-csv"}},
		{"output_flag", []string{"plan", "--input", path, "--to", "bitwarden-json", "--output", "SYNTHETIC_OUTPUT_PATH"}},
		{"help_leftover", []string{"help", "SYNTHETIC_POSITIONAL"}},
		{"version_input", []string{"version", "--input", path}},
		{"version_source", []string{"version", "--from", "chrome-csv"}},
		{"version_positional", []string{"version", "SYNTHETIC_POSITIONAL"}},
		{"version_invalid_bool", []string{"version", "--json=SYNTHETIC_BOOL"}},
		{"version_alias_json", []string{"--version", "--json"}},
		{"version_alias_positional", []string{"--version", "SYNTHETIC_POSITIONAL"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := invoke(tc.args...)
			if code != 2 || stdout != "" || !strings.Contains(stderr, "invalid_arguments") {
				t.Fatalf("want usage failure with safe code, got exit %d", code)
			}
			assertRedacted(t, stdout+stderr, path)
		})
	}
}

func TestInvalidInputsAndRoutesUseExitThree(t *testing.T) {
	valid := inputFixture(t, syntheticCSV)
	malformed := inputFixture(t, "name,url,username,password\nSYNTHETIC_TITLE,\"SYNTHETIC_BAD_QUOTE\n")
	encrypted := inputFixture(t, `{"encrypted":true,"items":[],"SYNTHETIC_LABEL":"SYNTHETIC_VALUE"}`)
	unknown := inputFixture(t, "SYNTHETIC_UNFAMILIAR_INPUT")
	bitwarden := inputFixture(t, `{"encrypted":false,"items":[]}`)
	cases := []struct {
		name string
		args []string
		code string
	}{
		{"malformed", []string{"inspect", "--input", malformed, "--from", "chrome-csv"}, "invalid_csv"},
		{"encrypted", []string{"inspect", "--input", encrypted}, "unsupported_encrypted"},
		{"unknown_input", []string{"inspect", "--input", unknown}, "unknown_format"},
		{"unknown_source", []string{"inspect", "--input", valid, "--from", "SYNTHETIC_FORMAT"}, "unknown_format"},
		{"unknown_target", []string{"plan", "--input", valid, "--to", "SYNTHETIC_TARGET"}, "unsupported_route"},
		{"unsupported_source_route", []string{"plan", "--input", bitwarden, "--to", "bitwarden-json"}, "unsupported_route"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := invoke(tc.args...)
			if code != 3 || stdout != "" || !strings.Contains(stderr, tc.code) {
				t.Fatalf("want invalid-input exit and code %s, got exit %d", tc.code, code)
			}
			assertRedacted(t, stdout+stderr, valid, malformed, encrypted, unknown, bitwarden)
		})
	}
}

func TestInvalidSelectionNeverFallsBackToAll(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	for _, value := range []string{"", "0", "-1", "4", "1,1", "1,", ",1", "1,,2", " 1", "1, 2", "+1", "1-2", "99999999999999999999999999", "SYNTHETIC_SELECTION"} {
		code, stdout, stderr := invoke("plan", "--input", path, "--to", "bitwarden-json", "--select="+value)
		if code != 3 || stdout != "" || !strings.Contains(stderr, "invalid_selection") {
			t.Fatalf("invalid selection must fail, got exit %d", code)
		}
		assertRedacted(t, stdout+stderr, path)
	}
}

func TestMissingFileIsRedactedIOFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SYNTHETIC_MISSING_PRIVATE_PATH")
	code, stdout, stderr := invoke("inspect", "--input", path)
	if code != 1 || stdout != "" || !strings.Contains(stderr, "input_open") {
		t.Fatalf("want file I/O failure, got exit %d", code)
	}
	assertRedacted(t, stdout+stderr, path)
}

func TestDirectoryIsRejectedAsInvalidInput(t *testing.T) {
	path := t.TempDir()
	code, stdout, stderr := invoke("inspect", "--input", path)
	if code != 3 || stdout != "" || !strings.Contains(stderr, "input_not_regular") {
		t.Fatalf("want nonregular input failure, got exit %d", code)
	}
	assertRedacted(t, stdout+stderr, path)
}

type failingWriter struct{ short bool }

func (w failingWriter) Write(p []byte) (int, error) {
	if w.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("SYNTHETIC_WRITER_ERROR")
}

func TestReportWriterFailuresCannotReturnSuccess(t *testing.T) {
	path := inputFixture(t, syntheticCSV)
	commands := [][]string{{"help"}, {"formats"}, {"formats", "--json"}, {"inspect", "--input", path}, {"inspect", "--input", path, "--json"}, {"plan", "--input", path, "--to", "bitwarden-json"}, {"plan", "--input", path, "--to", "bitwarden-json", "--json"}}
	commands = append(commands, []string{"version"}, []string{"version", "--json"}, []string{"--version"})
	for _, short := range []bool{false, true} {
		for _, args := range commands {
			var stderr bytes.Buffer
			code := Run(args, failingWriter{short: short}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "output_write") {
				t.Fatalf("report write must fail with I/O exit, got %d", code)
			}
			assertRedacted(t, stderr.String(), path)
		}
	}
}

func TestErrorWriterFailuresUseIOExit(t *testing.T) {
	for _, short := range []bool{false, true} {
		var stdout bytes.Buffer
		if code := Run([]string{"SYNTHETIC_COMMAND"}, &stdout, failingWriter{short: short}); code != 1 || stdout.Len() != 0 {
			t.Fatalf("stderr failure must override usage exit, got %d", code)
		}
		if code := Run([]string{"formats"}, failingWriter{short: short}, failingWriter{short: short}); code != 1 {
			t.Fatalf("both writers failing must return I/O exit, got %d", code)
		}
	}
}

type testFileInfo struct {
	mode os.FileMode
	size int64
}

func (f testFileInfo) Name() string       { return "SYNTHETIC_STAT_NAME" }
func (f testFileInfo) Size() int64        { return f.size }
func (f testFileInfo) Mode() os.FileMode  { return f.mode }
func (f testFileInfo) ModTime() time.Time { return time.Time{} }
func (f testFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f testFileInfo) Sys() any           { return nil }

type testInput struct {
	reader            io.Reader
	info              os.FileInfo
	statErr, closeErr error
	closed            bool
}

func (f *testInput) Read(p []byte) (int, error) { return f.reader.Read(p) }
func (f *testInput) Stat() (os.FileInfo, error) { return f.info, f.statErr }
func (f *testInput) Close() error               { f.closed = true; return f.closeErr }

type syntheticStream struct {
	remaining int64
	read      int64
}

func (r *syntheticStream) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > r.remaining {
		n = int(r.remaining)
	}
	clear(p[:n])
	r.remaining -= int64(n)
	r.read += int64(n)
	return n, nil
}

type readFailure struct{}

func (readFailure) Read([]byte) (int, error) { return 0, errors.New("SYNTHETIC_READ_ERROR") }

func TestReadInputBoundsActualBytesDespiteSmallStat(t *testing.T) {
	stream := &syntheticStream{remaining: int64(migration.MaxInputBytes) + 1000}
	f := &testInput{reader: stream, info: testFileInfo{mode: 0600, size: 1}}
	_, err := readInput("SYNTHETIC_PATH", func(string) (inputFile, error) { return f, nil })
	if err == nil || err.Error() != "input_limit" || !f.closed {
		t.Fatal("actual oversized input must fail safely and close")
	}
	if stream.read != int64(migration.MaxInputBytes)+1 {
		t.Fatalf("bounded loader read %d bytes", stream.read)
	}
	assertRedacted(t, err.Error())
}

func TestReadInputAcceptsExactByteLimit(t *testing.T) {
	stream := &syntheticStream{remaining: int64(migration.MaxInputBytes)}
	f := &testInput{reader: stream, info: testFileInfo{mode: 0600, size: 0}}
	data, err := readInput("SYNTHETIC_PATH", func(string) (inputFile, error) { return f, nil })
	if err != nil || len(data) != migration.MaxInputBytes || !f.closed {
		t.Fatal("exact byte limit must be accepted and closed")
	}
}

func TestInputIOFailuresStayRedactedAndCloseHandles(t *testing.T) {
	cases := []struct {
		name              string
		reader            io.Reader
		statErr, closeErr error
		code              string
	}{
		{"stat", strings.NewReader(syntheticCSV), errors.New("SYNTHETIC_STAT_ERROR"), nil, "input_stat"},
		{"read", readFailure{}, nil, nil, "input_read"},
		{"close", strings.NewReader(syntheticCSV), nil, errors.New("SYNTHETIC_CLOSE_ERROR"), "input_close"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &testInput{reader: tc.reader, info: testFileInfo{mode: 0600}, statErr: tc.statErr, closeErr: tc.closeErr}
			var stdout, stderr bytes.Buffer
			code := run([]string{"inspect", "--input", "SYNTHETIC_PATH"}, &stdout, &stderr, func(string) (inputFile, error) { return f, nil })
			if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.code) || !f.closed {
				t.Fatalf("want safe %s I/O failure with closed handle, got exit %d", tc.code, code)
			}
			assertRedacted(t, stdout.String()+stderr.String())
		})
	}
}
