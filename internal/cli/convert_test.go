package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/akvartz/Bitwarden21Password/internal/migration"
	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
)

type observedIssue struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Column  int    `json:"column"`
	Records int    `json:"records"`
}

type observedReview struct {
	Plan     migration.Plan  `json:"plan"`
	Profile  string          `json:"profile"`
	ReviewID string          `json:"review_id"`
	Issues   []observedIssue `json:"issues"`
}

type observedReceipt struct {
	Plan         migration.Plan `json:"plan"`
	Profile      string         `json:"profile"`
	JobDirectory string         `json:"job_directory"`
	FileName     string         `json:"file_name"`
}

type observedEvent struct {
	Event   string          `json:"event"`
	Review  observedReview  `json:"review"`
	Receipt observedReceipt `json:"receipt"`
}

// The reply copies only the protocol line displayed to the user. It never
// constructs expected export values using the migration implementation.
type promptReply struct {
	prompt      *bytes.Buffer
	transform   func(string) string
	reader      *strings.Reader
	reads       int
	lastReadErr error
}

func (r *promptReply) Read(p []byte) (int, error) {
	r.reads++
	if r.reader == nil {
		line := ""
		for _, candidate := range strings.Split(r.prompt.String(), "\n") {
			if strings.HasPrefix(candidate, "approve ") {
				line = candidate + "\n"
				break
			}
		}
		if line == "" {
			return 0, errors.New("SYNTHETIC_MISSING_PROMPT")
		}
		if r.transform != nil {
			line = r.transform(line)
		}
		r.reader = strings.NewReader(line)
	}
	n, err := r.reader.Read(p)
	if n > 0 && r.reader.Len() == 0 && r.lastReadErr != nil {
		return n, r.lastReadErr
	}
	return n, err
}

func convertArgs(source, parent string) []string {
	return []string{"convert", "--input", source, "--to", "bitwarden-json", "--output-dir", parent, "--json"}
}

func privateOutputParent(t *testing.T) string {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func requireLinuxOutput(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native protected output is Linux-only")
	}
}

func assertNoExport(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal("cannot inspect synthetic output directory")
	}
	if len(entries) != 0 {
		t.Fatal("rejected approval created output artifacts")
	}
}

func decodeEvents(t *testing.T, data string) []observedEvent {
	t.Helper()
	var events []observedEvent
	for _, line := range strings.Split(strings.TrimSuffix(data, "\n"), "\n") {
		var event observedEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal("events must be compact JSON objects, one per line")
		}
		events = append(events, event)
	}
	return events
}

func TestConvertJSONRequiresExactReviewAndPreservesSelection(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	args := append(convertArgs(source, parent), "--select", "2,1")
	code := RunContext(context.Background(), args, reply, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("approved conversion must succeed, got exit %d", code)
	}
	events := decodeEvents(t, stdout.String())
	if len(events) != 2 || events[0].Event != "review" || events[1].Event != "completed" {
		t.Fatal("successful conversion needs review then completion events")
	}
	review, receipt := events[0].Review, events[1].Receipt
	if review.Profile != "chrome-to-bitwarden-json-v1" || review.ReviewID == "" || review.Plan.State != "planned" || review.Plan.SelectedRecords != 2 || review.Plan.ExcludedRecords != 1 || review.Plan.OutputEmitted {
		t.Fatal("review must describe the selected planned job")
	}
	if !reflect.DeepEqual(review.Issues, []observedIssue{{"experimental-import", "experimental_import", 0, 2}, {"relocate-column-6", "concealed_custom_field", 6, 2}}) {
		t.Fatal("review must enumerate the exact required issue IDs and counts")
	}
	if receipt.Profile != review.Profile || receipt.Plan.State != "output_validated" || !receipt.Plan.OutputEmitted || receipt.Plan.DestinationImportVerified || receipt.FileName != "bitwarden.json" || receipt.JobDirectory == "" || filepath.Base(receipt.JobDirectory) != receipt.JobDirectory {
		t.Fatal("completion must identify only the validated generated output")
	}
	if strings.Contains(strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")[1], "review_id") {
		t.Fatal("receipt must omit the review correlation ID")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != receipt.JobDirectory {
		t.Fatal("approval must create exactly one job")
	}
	output := filepath.Join(parent, receipt.JobDirectory, receipt.FileName)
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal("completed export must exist")
	}
	var got any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal("completed export must be valid JSON")
	}
	const expected = `{"encrypted":false,"folders":[],"items":[{"type":1,"name":"SYNTHETIC_TITLE","notes":"SYNTHETIC_NOTE","login":{"username":"SYNTHETIC_USER","password":"SYNTHETIC_PASSWORD_A","uris":[{"uri":"https://synthetic.invalid"}]},"fields":[{"type":1,"name":"SYNTHETIC_CUSTOM_LABEL","value":"SYNTHETIC_CUSTOM_VALUE"}]},{"type":1,"name":"SYNTHETIC_TITLE","notes":"SYNTHETIC_NOTE","login":{"username":"SYNTHETIC_USER","password":"SYNTHETIC_PASSWORD_B","uris":[{"uri":"https://synthetic.invalid"}]},"fields":[{"type":1,"name":"SYNTHETIC_CUSTOM_LABEL","value":"SYNTHETIC_CUSTOM_VALUE"}]}]}`
	var want any
	if err := json.Unmarshal([]byte(expected), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("selected export changed exact values, labels, order or duplicate multiplicity")
	}
	for path, mode := range map[string]os.FileMode{filepath.Dir(output): 0700, output: 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatal("completed output must have private effective modes")
		}
	}
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

func TestConvertRejectsApprovalWithoutOutput(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	cases := []struct {
		name      string
		transform func(string) string
		reader    io.Reader
		wantExit  int
		wantCode  string
	}{
		{"eof", nil, strings.NewReader(""), 3, "approval_required"},
		{"decline", func(string) string { return "decline\n" }, nil, 3, "approval_invalid"},
		{"malformed", func(string) string { return "approve\n" }, nil, 3, "approval_invalid"},
		{"unfamiliar_tokens", func(string) string { return "SYNTHETIC_APPROVAL\n" }, nil, 3, "approval_invalid"},
		{"missing_id", func(s string) string { p := strings.Fields(s); return strings.Join(p[:len(p)-1], " ") + "\n" }, nil, 3, "approval_invalid"},
		{"extra_id", func(s string) string { return strings.TrimSuffix(s, "\n") + " SYNTHETIC_EXTRA\n" }, nil, 3, "approval_invalid"},
		{"duplicate_id", func(s string) string { return strings.TrimSuffix(s, "\n") + " experimental-import\n" }, nil, 3, "approval_invalid"},
		{"stale_review", func(s string) string {
			p := strings.Fields(s)
			p[1] = "SYNTHETIC_STALE_REVIEW"
			return strings.Join(p, " ") + "\n"
		}, nil, 3, "approval_invalid"},
		{"valid_but_unterminated", func(s string) string { return strings.TrimSuffix(s, "\n") }, nil, 3, "approval_required"},
		{"oversized", func(string) string { return strings.Repeat("x", 64*1024) + "\n" }, nil, 3, "approval_invalid"},
		{"read_error", nil, readFailure{}, 1, "approval_read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := privateOutputParent(t)
			var stdout, stderr bytes.Buffer
			reader := tc.reader
			if reader == nil {
				reader = &promptReply{prompt: &stderr, transform: tc.transform}
			}
			code := RunContext(context.Background(), convertArgs(source, parent), reader, &stdout, &stderr)
			if code != tc.wantExit || !strings.HasSuffix(stderr.String(), tc.wantCode+"\n") {
				t.Fatalf("approval rejection must use safe %s exit %d, got %d", tc.wantCode, tc.wantExit, code)
			}
			events := decodeEvents(t, stdout.String())
			if len(events) != 1 || events[0].Event != "review" {
				t.Fatal("rejected approval must have review only")
			}
			assertNoExport(t, parent)
			assertRedacted(t, stdout.String()+stderr.String(), source, parent)
		})
	}
}

func TestConvertReviewAndPromptWriteFailurePreventsApproval(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	for _, which := range []string{"review", "prompt"} {
		for _, short := range []bool{false, true} {
			t.Run(which+map[bool]string{false: "_error", true: "_short"}[short], func(t *testing.T) {
				parent := privateOutputParent(t)
				var stdout, stderr bytes.Buffer
				reply := &promptReply{prompt: &stderr}
				var out, diag io.Writer = &stdout, &stderr
				if which == "review" {
					out = failingWriter{short: short}
				} else {
					diag = failingWriter{short: short}
				}
				if code := RunContext(context.Background(), convertArgs(source, parent), reply, out, diag); code != 1 {
					t.Fatalf("report failure must use I/O exit 1, got %d", code)
				}
				if reply.reads != 0 {
					t.Fatal("failed review or prompt must not consume approval")
				}
				assertNoExport(t, parent)
			})
		}
	}
}

type finalEventFailure struct {
	bytes.Buffer
	completedWrites int
}

func (w *finalEventFailure) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"event":"completed"`)) {
		w.completedWrites++
		return 0, errors.New("SYNTHETIC_FINAL_REPORT_ERROR")
	}
	return w.Buffer.Write(p)
}

func TestConvertFinalReportFailureReturnsIOWithoutRetry(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	var stderr bytes.Buffer
	stdout := &finalEventFailure{}
	reply := &promptReply{prompt: &stderr}
	if code := RunContext(context.Background(), convertArgs(source, parent), reply, stdout, &stderr); code != 1 || !strings.HasSuffix(stderr.String(), "output_write\n") {
		t.Fatal("failed completion report must return I/O failure")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || stdout.completedWrites != 1 {
		t.Fatal("completion report failure must not retry the commit or report")
	}
	if _, err := os.Stat(filepath.Join(parent, entries[0].Name(), "bitwarden.json")); err != nil {
		t.Fatal("test must fail reporting after a valid export")
	}
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

type blockedApproval struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	closed  bool
}

func (r *blockedApproval) Read([]byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	return 0, io.EOF
}

func (r *blockedApproval) Close() error {
	r.closed = true
	return nil
}

func TestConvertCancellationReturnsWithoutClosingCallerInput(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &blockedApproval{started: make(chan struct{}), release: make(chan struct{})}
	defer close(reader.release)
	var stdout, stderr bytes.Buffer
	result := make(chan int, 1)
	go func() { result <- RunContext(ctx, convertArgs(source, parent), reader, &stdout, &stderr) }()
	select {
	case <-reader.started:
	case <-result:
		t.Fatal("conversion exited before waiting for approval")
	case <-time.After(3 * time.Second):
		t.Fatal("conversion did not begin the bounded approval read")
	}
	cancel()
	select {
	case code := <-result:
		if code != 1 || reader.closed {
			t.Fatal("approval cancellation must fail safely without closing caller input")
		}
	case <-time.After(time.Second):
		t.Fatal("approval cancellation did not return promptly")
	}
	assertNoExport(t, parent)
}

func TestConvertInvalidArgumentsDoNotReadApproval(t *testing.T) {
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	base := convertArgs(source, parent)
	cases := [][]string{
		{"convert"},
		{"convert", "--input", source, "--to", "bitwarden-json"},
		{"convert", "--input", source, "--output-dir", parent},
		append(append([]string{}, base...), "--yes"),
		append(append([]string{}, base...), "--force"),
		append(append([]string{}, base...), "--approve", "SYNTHETIC_ARGV_APPROVAL"),
		append(append([]string{}, base...), "SYNTHETIC_POSITIONAL"),
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		reply := &promptReply{prompt: &stderr}
		if code := RunContext(context.Background(), args, reply, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != "invalid_arguments\n" || reply.reads != 0 {
			t.Fatalf("bad convert arguments must fail before input, got exit %d", code)
		}
		assertNoExport(t, parent)
		assertRedacted(t, stderr.String(), source, parent)
	}
}

func TestConvertUnwritableParentFailsWithoutCompletion(t *testing.T) {
	requireLinuxOutput(t)
	if os.Geteuid() == 0 {
		t.Skip("root can bypass directory write permissions")
	}
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	if err := os.Chmod(parent, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	if code := RunContext(context.Background(), convertArgs(source, parent), reply, &stdout, &stderr); code != 1 {
		t.Fatalf("unwritable parent must return I/O failure, got %d", code)
	}
	if strings.Contains(stdout.String(), `"event":"completed"`) {
		t.Fatal("unwritable output cannot emit completion")
	}
	assertNoExport(t, parent)
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

func TestConvertHumanExplainsEveryConditionalProviderIssue(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, "name,url,username,password,note,SYNTHETIC_CUSTOM_LABEL\n ,,,, ,\n")
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	args := convertArgs(source, parent)
	args = args[:len(args)-1]
	code := RunContext(context.Background(), args, strings.NewReader(""), &stdout, &stderr)
	if code != 3 || !strings.HasSuffix(stderr.String(), "approval_required\n") {
		t.Fatalf("human review must await approval, got exit %d", code)
	}
	for _, term := range []string{"experimental-import", "relocate-column-6", "provider-blank-name", "provider-blank-notes", "provider-empty-username", "provider-empty-password", "provider-empty-url", "provider-import-rejection"} {
		if !strings.Contains(stdout.String(), term) {
			t.Fatalf("human review omitted required issue %s", term)
		}
	}
	for _, term := range []string{"plaintext", "experimental", "unverified", "encrypted", "placeholder", "null", "username", "password", "URI", "concealed", "sample", "reject"} {
		if !strings.Contains(strings.ToLower(stderr.String()), strings.ToLower(term)) {
			t.Fatalf("human explanation omitted provider consequence %s", term)
		}
	}
	assertNoExport(t, parent)
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

func TestConvertExplainsProviderImportBatchLimit(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, "name,url,username,password\n"+strings.Repeat("SYNTHETIC_TITLE,,,SYNTHETIC_PASSWORD\n", 7001))
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	code := RunContext(context.Background(), convertArgs(source, parent), strings.NewReader(""), &stdout, &stderr)
	if code != 3 || !strings.Contains(stdout.String(), `"id":"provider-large-export"`) || !strings.Contains(stdout.String(), `"records":7001`) || !strings.Contains(stderr.String(), "7,000") {
		t.Fatal("large export review must explain the inspected provider batch rejection")
	}
	assertNoExport(t, parent)
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

func TestConvertOutputExpansionUsesRejectedInputExit(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, "name,url,username,password\n"+strings.Repeat("\x01", 6*1024*1024)+",,,SYNTHETIC_PASSWORD\n")
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	code := RunContext(context.Background(), convertArgs(source, parent), reply, &stdout, &stderr)
	if code != 3 || stdout.Len() != 0 || !strings.HasSuffix(stderr.String(), "output_limit\n") || reply.reads != 0 {
		t.Fatalf("output expansion must be rejected before review, got exit %d", code)
	}
	assertNoExport(t, parent)
}

func TestConvertUnsupportedPlatformsFailBeforeApproval(t *testing.T) {
	if protectedoutput.Supported() {
		t.Skip("unsupported-platform execution needs a native unsupported host")
	}
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	code := RunContext(context.Background(), convertArgs(source, parent), reply, &stdout, &stderr)
	if code != 3 || stdout.Len() != 0 || stderr.String() != "output_platform\n" || reply.reads != 0 {
		t.Fatal("unsupported output platform must fail before review and approval")
	}
	assertNoExport(t, parent)
}

func TestConvertAlreadyCancelledDoesNotReadInputOrApproval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	code := RunContext(ctx, convertArgs("SYNTHETIC_MISSING_INPUT", "SYNTHETIC_OUTPUT_PARENT"), reply, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.Len() != 0 || reply.reads != 0 {
		t.Fatal("already cancelled conversion must fail before reading input")
	}
}

type releasedApprovalRead struct {
	started chan struct{}
	release chan struct{}
	second  chan struct{}
	reads   atomic.Int32
}

func (r *releasedApprovalRead) Read(p []byte) (int, error) {
	count := r.reads.Add(1)
	if count == 1 {
		close(r.started)
		<-r.release
	} else {
		close(r.second)
		return 0, io.EOF
	}
	p[0] = 'x'
	return 1, nil
}

func TestCancelledApprovalReaderStopsAfterCallerUnblocksIt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := &releasedApprovalRead{started: make(chan struct{}), release: make(chan struct{}), second: make(chan struct{})}
	result := make(chan error, 1)
	go func() {
		_, err := readApproval(ctx, reader)
		result <- err
	}()
	<-reader.started
	cancel()
	select {
	case err := <-result:
		if err == nil || err.Error() != "output_cancelled" {
			t.Fatal("approval must return cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("approval cancellation blocked on reader")
	}
	close(reader.release)
	select {
	case <-reader.second:
		t.Fatal("cancelled reader consumed further approval bytes after unblocking")
	case <-time.After(100 * time.Millisecond):
		if reader.reads.Load() != 1 {
			t.Fatal("cancelled reader exceeded its one blocked read")
		}
	}
}

func TestApprovalFinalByteHandlesEOFAndReadErrors(t *testing.T) {
	const line = "approve REVIEW_ID experimental-import\n"
	for _, tc := range []struct {
		name         string
		terminal     error
		unterminated bool
		wantLine     string
		wantCode     string
	}{
		{"newline_with_eof", io.EOF, false, line, ""},
		{"unterminated_with_eof", io.EOF, true, "", "approval_required"},
		{"newline_with_read_error", errors.New("SYNTHETIC_TERMINAL_READ_ERROR"), false, "", "approval_read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &promptReply{prompt: bytes.NewBufferString(line), lastReadErr: tc.terminal}
			if tc.unterminated {
				reader.transform = func(s string) string { return strings.TrimSuffix(s, "\n") }
			}
			got, err := readApprovalLine(context.Background(), reader)
			if got != tc.wantLine {
				t.Fatal("approval reader discarded or accepted the wrong final bytes")
			}
			if tc.wantCode == "" {
				if err != nil {
					t.Fatal("newline completed with EOF must be accepted")
				}
			} else if err == nil || err.Error() != tc.wantCode {
				t.Fatalf("want fixed terminal read code %s", tc.wantCode)
			}
		})
	}
}

func TestConvertAcceptsApprovalNewlineReturnedWithEOF(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	var stdout, stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr, lastReadErr: io.EOF}
	if code := RunContext(context.Background(), convertArgs(source, parent), reply, &stdout, &stderr); code != 0 {
		t.Fatalf("complete approval returned with EOF must convert, got exit %d", code)
	}
	events := decodeEvents(t, stdout.String())
	if len(events) != 2 || events[1].Event != "completed" {
		t.Fatal("valid final EOF approval must complete exactly once")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("valid final EOF approval must create exactly one export")
	}
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}

type cancellingCompletionWriter struct {
	bytes.Buffer
	cancel          context.CancelFunc
	parent          string
	completedWrites int
	outputPath      string
	validatedBytes  []byte
	snapshotErr     error
	finished        chan struct{}
}

func (w *cancellingCompletionWriter) Write(p []byte) (int, error) {
	completed := bytes.Contains(p, []byte(`"event":"completed"`))
	if completed {
		w.completedWrites++
		var event observedEvent
		w.snapshotErr = json.Unmarshal(p, &event)
		if w.snapshotErr == nil {
			w.outputPath = filepath.Join(w.parent, event.Receipt.JobDirectory, event.Receipt.FileName)
			w.validatedBytes, w.snapshotErr = os.ReadFile(w.outputPath)
		}
		w.cancel()
	}
	n, err := w.Buffer.Write(p)
	if completed {
		close(w.finished)
	}
	return n, err
}

func TestConvertCancellationDuringCompletionWriteReturnsFailureOnce(t *testing.T) {
	requireLinuxOutput(t)
	source := inputFixture(t, syntheticCSV)
	parent := privateOutputParent(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stdout := &cancellingCompletionWriter{cancel: cancel, parent: parent, finished: make(chan struct{})}
	var stderr bytes.Buffer
	reply := &promptReply{prompt: &stderr}
	code := RunContext(ctx, convertArgs(source, parent), reply, stdout, &stderr)
	if code != 1 {
		t.Fatalf("cancellation during successful completion Write must fail, got exit %d", code)
	}
	// Cancellation returns without waiting for borrowed writers. The caller
	// waits for its pending writer before inspecting or reusing its buffers.
	select {
	case <-stdout.finished:
	case <-time.After(time.Second):
		t.Fatal("completion writer did not finish")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || stdout.completedWrites != 1 {
		t.Fatal("completion cancellation must not retry export or report")
	}
	if stdout.snapshotErr != nil || len(stdout.validatedBytes) == 0 {
		t.Fatal("completion Write must observe the validated export before cancellation")
	}
	data, err := os.ReadFile(stdout.outputPath)
	if err != nil || !bytes.Equal(data, stdout.validatedBytes) {
		t.Fatal("completion cancellation changed the already validated file")
	}
	assertRedacted(t, stdout.String()+stderr.String(), source, parent)
}
