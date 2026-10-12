package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/testsupport"
)

func mustJob(t *testing.T, d *Document, selection []int, parent string) *Job {
	t.Helper()
	if !protectedoutput.Supported() {
		t.Skip("public protected output is not qualified on this platform")
	}
	job, err := d.NewJob(BitwardenJSON, selection, parent)
	if err != nil {
		t.Fatalf("NewJob failed with safe code: %v", err)
	}
	if job == nil {
		t.Fatal("NewJob returned no handle")
	}
	return job
}

func issueIDs(review Review) []string {
	ids := make([]string, len(review.Issues))
	for i, issue := range review.Issues {
		ids[i] = issue.ID
	}
	return ids
}

func approveJob(t *testing.T, job *Job) {
	t.Helper()
	review := job.Review()
	if err := job.Approve(review.ReviewID, issueIDs(review)); err != nil {
		t.Fatalf("exact approval failed: %v", err)
	}
}

func TestJobReviewAccountsForSelectionAndProviderEffects(t *testing.T) {
	d := mustParse(t, []byte("password,note, Custom ,username,name,url\n\ufeff,\ufeff,v,,\ufeff,\n,,, ,\u0085, \nexcluded,excluded,v,u,n,url\n"), ChromeCSV)
	job := mustJob(t, d, []int{2, 1}, t.TempDir())
	got := job.Review()
	wantIssues := []Issue{
		{ID: "experimental-import", Code: "experimental_import", Records: 2},
		{ID: "relocate-column-3", Code: "concealed_custom_field", Column: 3, Records: 2},
		{ID: "provider-blank-name", Code: "import_name_placeholder", Column: 5, Records: 1},
		{ID: "provider-blank-notes", Code: "import_notes_null", Column: 2, Records: 2},
		{ID: "provider-empty-username", Code: "import_username_absent", Column: 4, Records: 1},
		{ID: "provider-empty-password", Code: "import_password_absent", Column: 1, Records: 1},
		{ID: "provider-empty-url", Code: "import_uri_removed", Column: 6, Records: 1},
	}
	if got.Profile != "chrome-to-bitwarden-json-v1" || got.ReviewID == "" || !reflect.DeepEqual(got.Issues, wantIssues) {
		t.Fatal("review profile, binding, issue ordinals, or affected counts are incorrect")
	}
	wantFields := []FieldDisposition{
		{Record: 1, Field: 1, Disposition: "native", TargetField: "login.password"},
		{Record: 1, Field: 2, Disposition: "native", TargetField: "notes"},
		{Record: 1, Field: 3, Disposition: "relocated", TargetField: "fields", Concealed: true},
		{Record: 1, Field: 4, Disposition: "native", TargetField: "login.username"},
		{Record: 1, Field: 5, Disposition: "native", TargetField: "name"},
		{Record: 1, Field: 6, Disposition: "native", TargetField: "login.uris[0].uri"},
		{Record: 2, Field: 1, Disposition: "native", TargetField: "login.password"},
		{Record: 2, Field: 2, Disposition: "native", TargetField: "notes"},
		{Record: 2, Field: 3, Disposition: "relocated", TargetField: "fields", Concealed: true},
		{Record: 2, Field: 4, Disposition: "native", TargetField: "login.username"},
		{Record: 2, Field: 5, Disposition: "native", TargetField: "name"},
		{Record: 2, Field: 6, Disposition: "native", TargetField: "login.uris[0].uri"},
	}
	if !reflect.DeepEqual(got.Plan.Fields, wantFields) || got.Plan.TotalRecords != 3 || got.Plan.SelectedRecords != 2 || got.Plan.ExcludedRecords != 1 || got.Plan.State != "planned" || got.Plan.OutputEmitted || got.Plan.DestinationImportVerified {
		t.Fatal("review did not account for every selected source cell")
	}
}

func TestJobProviderBlankUsesECMAScriptWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		blank       bool
	}{
		{"bom", "\ufeff", true}, {"next_line", "\u0085", false},
		{"ecmascript_set", "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff", true},
		{"historic_mongolian", "\u180e", false}, {"zero_width", "\u200b", false}, {"visible", " \ufeffx ", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cell := "\"" + strings.ReplaceAll(tc.value, "\"", "\"\"") + "\""
			d := mustParse(t, []byte("name,url,username,password,note\n"+cell+", , , ,"+cell+"\n"), ChromeCSV)
			job := mustJob(t, d, nil, t.TempDir())
			issues := job.Review().Issues
			var nameBlank, noteBlank bool
			for _, issue := range issues {
				switch issue.ID {
				case "provider-blank-name":
					nameBlank = true
				case "provider-blank-notes":
					noteBlank = true
				case "provider-empty-username", "provider-empty-password", "provider-empty-url":
					t.Fatal("whitespace-only cell was treated as exact empty")
				}
			}
			if nameBlank != tc.blank || noteBlank != tc.blank {
				t.Fatal("provider blank semantics differ from ECMAScript trim")
			}
		})
	}
}

func TestJobProviderLargeExportBoundaryPreservesAllRecords(t *testing.T) {
	for _, n := range []int{7000, 7001} {
		d := mustParse(t, []byte("name,url,username,password\n"+strings.Repeat("n,u,a,p\n", n)), ChromeCSV)
		job := mustJob(t, d, nil, t.TempDir())
		var large *Issue
		for _, issue := range job.Review().Issues {
			if issue.ID == "provider-large-export" {
				copied := issue
				large = &copied
			}
		}
		if (n == 7001) != (large != nil) {
			t.Fatal("provider item-limit boundary differs from >7000")
		}
		if large != nil && (large.Code != "import_item_limit" || large.Column != 0 || large.Records != 7001) {
			t.Fatal("provider item-limit counts incorrect")
		}
		if job.Review().Plan.SelectedRecords != n {
			t.Fatal("provider limit silently dropped records")
		}
	}
}

func TestJobProviderImportRejectionUsesSelectedSourceOrderSamples(t *testing.T) {
	for _, tc := range []struct {
		name, rows string
		selection  []int
		rejected   bool
		count      int
	}{
		{"literal_placeholder", "--,u,a, \n", nil, true, 1},
		{"bom_whitespace", "\ufeff,u,a,\ufeff\n", nil, true, 1},
		{"three_bad_samples", "--,u,a, \ngood,u,a,p\n ,u,a,\ufeff\ngood,u,a,p\n\ufeff,u,a, \n", nil, true, 5},
		{"good_middle", "--,u,a, \n ,u,a, \ngood,u,a, \n ,u,a, \n--,u,a, \n", nil, false, 5},
		{"selected_good", "--,u,a, \ngood,u,a,p\n ,u,a, \ngood,u,a,p\n--,u,a, \n", []int{4, 2}, false, 2},
		{"selected_bad", "--,u,a, \ngood,u,a,p\n ,u,a, \ngood,u,a,p\n--,u,a, \n", []int{5, 1, 3}, true, 3},
		{"password_visible", "--,u,a, x \n", nil, false, 1},
		{"non_ecma_name", "\u0085,u,a, \n", nil, false, 1},
		{"empty_export", "", nil, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := mustParse(t, []byte("name,url,username,password\n"+tc.rows), ChromeCSV)
			job := mustJob(t, d, tc.selection, t.TempDir())
			var found *Issue
			for _, issue := range job.Review().Issues {
				if issue.ID == "provider-import-rejection" {
					copied := issue
					found = &copied
				}
			}
			if (found != nil) != tc.rejected {
				t.Fatal("provider rejection guard did not use the exact selected samples")
			}
			if found != nil && (found.Code != "import_sample_rejected" || found.Column != 0 || found.Records != tc.count) {
				t.Fatal("provider rejection count or code incorrect")
			}
		})
	}
}

func TestJobApprovalRequiresExactCurrentReviewAndIssueSet(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password,custom\nn,u,a,p,v\n"), ChromeCSV)
	for _, tc := range []struct {
		name    string
		wrongID bool
		ids     []string
	}{
		{"missing", false, []string{"experimental-import"}},
		{"extra", false, []string{"experimental-import", "relocate-column-5", "unexpected"}},
		{"duplicate", false, []string{"experimental-import", "relocate-column-5", "experimental-import"}},
		{"same_count_duplicate", false, []string{"experimental-import", "experimental-import"}},
		{"same_count_unknown", false, []string{"experimental-import", "unexpected"}},
		{"empty", false, nil},
		{"wrong_review", true, []string{"experimental-import", "relocate-column-5"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := mustJob(t, d, nil, t.TempDir())
			reviewID := job.Review().ReviewID
			if tc.wrongID {
				reviewID = "stale-review"
			}
			requireErrorCode(t, job.Approve(reviewID, tc.ids), "approval_invalid")
			if job.State() != "planned" {
				t.Fatal("failed approval changed job state")
			}
			approveJob(t, job)
			if job.State() != "approved" {
				t.Fatal("exact approval did not enable the job")
			}
			review := job.Review()
			requireErrorCode(t, job.Approve(review.ReviewID, issueIDs(review)), "invalid_state")
		})
	}
	job := mustJob(t, d, nil, t.TempDir())
	review := job.Review()
	if err := job.Approve(review.ReviewID, []string{"relocate-column-5", "experimental-import"}); err != nil {
		t.Fatal("exact issue set depended on response order")
	}
}

func TestJobCrossJobReviewCannotAuthorizeDifferentSnapshotsSelectionsOrParents(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\nn,u,a,p\nsecond,u,a,p\n"), ChromeCSV)
	parent := t.TempDir()
	first := mustJob(t, d, []int{1}, parent)
	review := first.Review()
	for _, other := range []*Job{
		mustJob(t, d, []int{1}, parent),
		mustJob(t, d, []int{2}, parent),
		mustJob(t, d, []int{1}, t.TempDir()),
		mustJob(t, mustParse(t, []byte("name,url,username,password\nother,u,a,p\n"), ChromeCSV), nil, parent),
	} {
		if other.Review().ReviewID == review.ReviewID {
			t.Fatal("independent jobs reused a review binding")
		}
		requireErrorCode(t, other.Approve(review.ReviewID, issueIDs(review)), "approval_invalid")
		if other.State() != "planned" {
			t.Fatal("another job's response changed approval state")
		}
	}
}

func TestJobPreapprovalCommitCannotWrite(t *testing.T) {
	parent := t.TempDir()
	job := mustJob(t, mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV), nil, parent)
	receipt, err := job.Commit(context.Background())
	requireErrorCode(t, err, "approval_required")
	if !reflect.DeepEqual(receipt, Receipt{}) || job.State() != "planned" {
		t.Fatal("preapproval commit emitted a receipt or changed state")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("preapproval commit touched the output parent")
	}
}

func TestJobOwnedInputsAndReviewMutationCannotChangeExecution(t *testing.T) {
	data := []byte("name,url,username,password, Custom \nsame,u,a,first,v\nexcluded,u,a,second,v\nsame,u,a,third,v\n")
	d := mustParse(t, data, ChromeCSV)
	selection := []int{3, 1}
	parent := testsupport.PrivateParent(t)
	job := mustJob(t, d, selection, parent)
	want := job.Review()
	for i := range data {
		data[i] = 'x'
	}
	selection[0] = 2
	review := job.Review()
	review.Plan.Fields[0].Record = 999
	review.Plan.Fields[0].TargetField = "changed"
	review.Plan.DuplicateGroups[0][0] = 999
	review.Plan.Caveats[0] = "changed"
	review.Plan.SelectedRecords = 0
	review.Issues[0].ID = "changed"
	review.Profile = "changed"
	review.ReviewID = "changed"
	if !reflect.DeepEqual(job.Review(), want) {
		t.Fatal("public review mutation changed private job state")
	}
	approveJob(t, job)
	receipt, err := job.Commit(context.Background())
	if err != nil {
		t.Fatalf("protected commit failed: %v", err)
	}
	if receipt.Plan.State != "output_validated" || !receipt.Plan.OutputEmitted || receipt.Plan.DestinationImportVerified || job.State() != "completed" {
		t.Fatal("completion evidence is incorrect")
	}
	for _, caveat := range receipt.Plan.Caveats {
		if caveat == "planned_only_no_output" {
			t.Fatal("successful receipt retained planned-only caveat")
		}
	}
	if !containsString(receipt.Plan.Caveats, "chrome_csv_limited_export") || !containsString(receipt.Plan.Caveats, "destination_import_not_verified") {
		t.Fatal("completion lost coverage or provider caveats")
	}
	if receipt.JobDirectory == "" || filepath.Base(receipt.JobDirectory) != receipt.JobDirectory || receipt.JobDirectory == "." || receipt.FileName != "bitwarden.json" {
		t.Fatal("receipt exposed an unsafe output identifier")
	}
	payload, err := os.ReadFile(filepath.Join(parent, receipt.JobDirectory, receipt.FileName))
	if err != nil {
		t.Fatal("completed output not readable")
	}
	literal := []byte(`{"encrypted":false,"folders":[],"items":[{"type":1,"name":"same","login":{"username":"a","password":"first","uris":[{"uri":"u"}]},"fields":[{"name":" Custom ","value":"v","type":1}]},{"type":1,"name":"same","login":{"username":"a","password":"third","uris":[{"uri":"u"}]},"fields":[{"name":" Custom ","value":"v","type":1}]}]}`)
	if !reflect.DeepEqual(decodeLiteralJSON(t, payload), decodeLiteralJSON(t, literal)) {
		t.Fatal("caller mutation or selection order changed the saved values")
	}
	receipt.Plan.Fields[0].Record = 998
	receipt.Plan.DuplicateGroups[0][0] = 998
	receipt.Plan.Caveats[0] = "changed"
	if !reflect.DeepEqual(job.Review(), want) {
		t.Fatal("receipt mutation changed private review")
	}
	repeated, err := job.Commit(context.Background())
	requireErrorCode(t, err, "invalid_state")
	if !reflect.DeepEqual(repeated, Receipt{}) {
		t.Fatal("replay returned a receipt")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("replay created another output")
	}
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestJobCopiesShareOneConcurrentCommitAuthority(t *testing.T) {
	job := mustJob(t, mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV), nil, t.TempDir())
	approveJob(t, job)
	copied := *job
	started, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	job.private.writeOutput = func(ctx context.Context, parent string, payload []byte) (protectedoutput.Result, error) {
		if writes.Add(1) == 1 {
			close(started)
		}
		<-release
		return protectedoutput.Result{JobDirectory: "job-test", FileName: "bitwarden.json"}, nil
	}
	type result struct {
		receipt Receipt
		err     error
	}
	results := make(chan result, 20)
	for i := 0; i < 20; i++ {
		handle := job
		if i%2 == 1 {
			handle = &copied
		}
		go func() { receipt, err := handle.Commit(context.Background()); results <- result{receipt, err} }()
	}
	<-started
	if job.State() != "writing" || copied.State() != "writing" {
		t.Fatal("copied handles did not share active state")
	}
	review := copied.Review()
	requireErrorCode(t, copied.Approve(review.ReviewID, issueIDs(review)), "invalid_state")
	close(release)
	winners := 0
	for i := 0; i < 20; i++ {
		got := <-results
		if got.err == nil {
			winners++
			if !got.receipt.Plan.OutputEmitted {
				t.Fatal("winning commit lacked evidence")
			}
		} else {
			requireErrorCode(t, got.err, "invalid_state")
			if !reflect.DeepEqual(got.receipt, Receipt{}) {
				t.Fatal("losing commit returned a receipt")
			}
		}
	}
	if winners != 1 || writes.Load() != 1 || job.State() != "completed" || copied.State() != "completed" {
		t.Fatal("concurrent or copied job committed more than once")
	}
}

func TestJobOutputErrorsAndCancellationAreTerminalAndRedacted(t *testing.T) {
	const sentinel = "SensitiveSyntheticPathValue"
	for _, tc := range []struct {
		name, code                string
		err                       error
		cancelBefore, cancelAfter bool
	}{
		{"parent", "output_parent", &protectedoutput.Error{Code: "output_parent"}, false, false},
		{"create", "output_create", &protectedoutput.Error{Code: "output_create"}, false, false},
		{"write", "output_write", &protectedoutput.Error{Code: "output_write"}, false, false},
		{"sync", "output_sync", &protectedoutput.Error{Code: "output_sync"}, false, false},
		{"readback", "output_readback", &protectedoutput.Error{Code: "output_readback"}, false, false},
		{"close", "output_close", &protectedoutput.Error{Code: "output_close"}, false, false},
		{"publish", "output_publish", &protectedoutput.Error{Code: "output_publish"}, false, false},
		{"cancelled", "output_cancelled", &protectedoutput.Error{Code: "output_cancelled"}, false, false},
		{"unknown_output", "output_write", &protectedoutput.Error{Code: sentinel}, false, false},
		{"raw_error", "output_write", errors.New(sentinel), false, false},
		{"cancel_before", "output_cancelled", nil, true, false},
		{"cancel_after", "output_cancelled", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job := mustJob(t, mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV), nil, t.TempDir())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			writes := 0
			job.private.writeOutput = func(context.Context, string, []byte) (protectedoutput.Result, error) {
				writes++
				if tc.cancelAfter {
					cancel()
				}
				return protectedoutput.Result{JobDirectory: sentinel, FileName: sentinel}, tc.err
			}
			approveJob(t, job)
			if tc.cancelBefore {
				cancel()
			}
			receipt, err := job.Commit(ctx)
			requireErrorCode(t, err, tc.code)
			if !reflect.DeepEqual(receipt, Receipt{}) {
				t.Fatal("failed or canceled commit returned output identifiers")
			}
			if tc.cancelBefore && writes != 0 {
				t.Fatal("pre-canceled job invoked output")
			}
			wantedState := "failed"
			if tc.code == "output_cancelled" {
				wantedState = "cancelled"
			}
			if job.State() != wantedState {
				t.Fatal("failure was not terminal")
			}
			encoded, marshalErr := json.Marshal(err)
			if marshalErr != nil || strings.Contains(err.Error(), sentinel) || bytes.Contains(encoded, []byte(sentinel)) {
				t.Fatal("output error exposed a raw path or value")
			}
			review := job.Review()
			requireErrorCode(t, job.Approve(review.ReviewID, issueIDs(review)), "invalid_state")
			again, err := job.Commit(context.Background())
			requireErrorCode(t, err, "invalid_state")
			if !reflect.DeepEqual(again, Receipt{}) {
				t.Fatal("terminal replay produced a receipt")
			}
		})
	}
}

func TestJobRelativeParentIsCapturedBeforeProcessDirectoryChanges(t *testing.T) {
	base, other := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "private"), 0700); err != nil {
		t.Fatal("test setup failed")
	}
	t.Chdir(base)
	job := mustJob(t, mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV), nil, "private")
	t.Chdir(other)
	var captured string
	job.private.writeOutput = func(_ context.Context, parent string, _ []byte) (protectedoutput.Result, error) {
		captured = parent
		return protectedoutput.Result{JobDirectory: "job-test", FileName: "bitwarden.json"}, nil
	}
	approveJob(t, job)
	if _, err := job.Commit(context.Background()); err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	if captured != filepath.Join(base, "private") {
		t.Fatal("relative parent changed after review")
	}
}

func TestJobPublicJSONContainsOnlySafeDTOs(t *testing.T) {
	const sentinel = "DistinctiveSyntheticSentinel"
	d := mustParse(t, []byte("name,url,username,password,note,"+sentinel+"Label\n"+strings.Repeat(sentinel+",", 5)+sentinel+"\n"), ChromeCSV)
	job := mustJob(t, d, nil, filepath.Join(t.TempDir(), sentinel))
	for _, value := range []any{job, job.Review(), job.Review().Issues} {
		data, err := json.Marshal(value)
		if err != nil || bytes.Contains(data, []byte(sentinel)) {
			t.Fatal("public job DTO leaked source or output parent")
		}
	}
	job.private.writeOutput = func(context.Context, string, []byte) (protectedoutput.Result, error) {
		return protectedoutput.Result{JobDirectory: "job-test", FileName: "bitwarden.json"}, nil
	}
	approveJob(t, job)
	receipt, err := job.Commit(context.Background())
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}
	data, err := json.Marshal(receipt)
	if err != nil || bytes.Contains(data, []byte(sentinel)) || bytes.Contains(data, []byte(`"review_id"`)) {
		t.Fatal("completion leaked source, parent, or review correlation")
	}
	for _, required := range []string{`"job_directory"`, `"file_name":"bitwarden.json"`, `"output_emitted":true`, `"destination_import_verified":false`} {
		if !bytes.Contains(data, []byte(required)) {
			t.Fatal("safe completion JSON contract incomplete")
		}
	}
}

func TestJobRejectsInvalidRoutesSelectionsAndZeroHandles(t *testing.T) {
	d := mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV)
	for _, target := range []Format{ChromeCSV, "", "arbitrary"} {
		_, err := d.NewJob(target, nil, t.TempDir())
		requireErrorCode(t, err, "unsupported_route")
	}
	for _, selection := range [][]int{{}, {0}, {2}, {1, 1}} {
		_, err := d.NewJob(BitwardenJSON, selection, t.TempDir())
		requireErrorCode(t, err, "invalid_selection")
	}
	var absent *Document
	_, err := absent.NewJob(BitwardenJSON, nil, t.TempDir())
	requireErrorCode(t, err, "unsupported_route")
	for _, job := range []*Job{nil, {}} {
		if job.State() != "invalid" || !reflect.DeepEqual(job.Review(), Review{}) {
			t.Fatal("zero handle produced actionable review")
		}
		requireErrorCode(t, job.Approve("", nil), "invalid_state")
		receipt, err := job.Commit(context.Background())
		requireErrorCode(t, err, "invalid_state")
		if !reflect.DeepEqual(receipt, Receipt{}) {
			t.Fatal("zero handle returned a receipt")
		}
	}
}

func TestJobEmptyExportRequiresOnlyExperimentalIssue(t *testing.T) {
	job := mustJob(t, mustParse(t, []byte("name,url,username,password,custom\n"), ChromeCSV), nil, t.TempDir())
	if !reflect.DeepEqual(job.Review().Issues, []Issue{{ID: "experimental-import", Code: "experimental_import"}}) {
		t.Fatal("empty selection acquired relocation or provider issues")
	}
}

func TestJobLimitFailureDoesNotTouchFilesystem(t *testing.T) {
	if !protectedoutput.Supported() {
		t.Skip("public protected output is not qualified on this platform")
	}
	parent := t.TempDir()
	d := mustParse(t, []byte("name,url,username,password,"+strings.Repeat("A", 1<<20)+"\n"+strings.Repeat("n,u,a,p,\n", 33)), ChromeCSV)
	job, err := d.NewJob(BitwardenJSON, nil, parent)
	requireErrorCode(t, err, "output_limit")
	if job != nil {
		t.Fatal("invalid payload produced an approvable job")
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatal("preapproval validation touched the filesystem")
	}
}

func TestJobUnsupportedPlatformFailsBeforeApproval(t *testing.T) {
	if protectedoutput.Supported() {
		t.Skip("unsupported platform test")
	}
	d := mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV)
	job, err := d.NewJob(BitwardenJSON, nil, t.TempDir())
	requireErrorCode(t, err, "output_platform")
	if job != nil {
		t.Fatal("unsupported output platform produced an approvable job")
	}
}

func TestOutputSafeErrorCodesAreAllowlisted(t *testing.T) {
	for _, code := range []string{"output_platform", "output_parent", "output_create", "output_write", "output_sync", "output_readback", "output_close", "output_publish", "output_cancelled", "approval_required", "approval_invalid", "invalid_state", "output_limit", "output_validation"} {
		if (&SafeError{Code: code}).Error() != code {
			t.Fatal("fixed engine failure code was hidden by stale allowlist")
		}
	}
	if (&SafeError{Code: "UntrustedValue"}).Error() != "invalid_input" {
		t.Fatal("arbitrary engine error code leaked")
	}
}

// This context observes the pre-completion Err read without changing its result.
// The writer deliberately holds the state lock, forcing a deterministic gap.
type completionLockContext struct {
	context.Context
	checks  atomic.Int32
	checked chan struct{}
}

func (c *completionLockContext) Err() error {
	err := c.Context.Err()
	if c.checks.Add(1) == 2 {
		close(c.checked)
	}
	return err
}

func TestJobCancellationWhileWaitingForCompletionLockReturnsNoReceipt(t *testing.T) {
	job := mustJob(t, mustParse(t, []byte("name,url,username,password\nn,u,a,p\n"), ChromeCSV), nil, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &completionLockContext{Context: ctx, checked: make(chan struct{})}
	job.private.writeOutput = func(context.Context, string, []byte) (protectedoutput.Result, error) {
		job.private.mu.Lock()
		return protectedoutput.Result{JobDirectory: "job-test", FileName: "bitwarden.json"}, nil
	}
	approveJob(t, job)
	type result struct {
		receipt Receipt
		err     error
	}
	finished := make(chan result, 1)
	go func() { receipt, err := job.Commit(observed); finished <- result{receipt, err} }()
	<-observed.checked
	cancel()
	job.private.mu.Unlock()
	got := <-finished
	requireErrorCode(t, got.err, "output_cancelled")
	if !reflect.DeepEqual(got.receipt, Receipt{}) || job.State() != "cancelled" {
		t.Fatal("cancellation during completion-lock contention produced success")
	}
}
