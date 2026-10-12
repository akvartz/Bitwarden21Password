package migration

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
)

const chromeBitwardenProfile = "chrome-to-bitwarden-json-v1"

// Review contains only safe counts, ordinals, fixed codes, and issue IDs.
// ReviewID correlates an in-memory response; it contains no source-derived data.
type Review struct {
	Plan     Plan    `json:"plan"`
	Profile  string  `json:"profile"`
	ReviewID string  `json:"review_id"`
	Issues   []Issue `json:"issues"`
}

type Issue struct {
	ID      string `json:"id"`
	Code    string `json:"code"`
	Column  int    `json:"column,omitempty"`
	Records int    `json:"records,omitempty"`
}

type Receipt struct {
	Plan         Plan   `json:"plan"`
	Profile      string `json:"profile"`
	JobDirectory string `json:"job_directory"`
	FileName     string `json:"file_name"`
}

// Job is a handle: copying its value preserves the same one-shot authority.
// The document, canonical selection, output parent, payload, and review are
// privately captured before approval and never returned through public DTOs.
type Job struct{ private *jobState }

type jobState struct {
	mu          sync.Mutex
	state       string
	document    *Document
	selection   []int
	parent      string
	payload     []byte
	review      Review
	writeOutput func(context.Context, string, []byte) (protectedoutput.Result, error)
}

// NewJob validates output entirely in memory before permitting approval or I/O.
func (d *Document) NewJob(target Format, selection []int, parent string) (*Job, error) {
	plan, err := d.Plan(target, selection)
	if err != nil {
		return nil, err
	}
	if !protectedoutput.Supported() {
		return nil, &SafeError{Code: "output_platform"}
	}
	if parent == "" || strings.IndexByte(parent, 0) >= 0 {
		return nil, &SafeError{Code: "output_parent"}
	}
	absolute, err := filepath.Abs(parent)
	if err != nil {
		return nil, &SafeError{Code: "output_parent"}
	}
	selected := make([]int, 0, plan.SelectedRecords)
	if selection == nil {
		for record := 1; record <= len(d.chromeRows); record++ {
			selected = append(selected, record)
		}
	} else {
		selected = append(selected, selection...)
		sort.Ints(selected)
	}
	payload, err := exportChrome(d, selected)
	if err != nil {
		return nil, err
	}
	review := Review{Plan: plan, Profile: chromeBitwardenProfile, ReviewID: rand.Text(), Issues: reviewIssues(d, selected)}
	return &Job{private: &jobState{
		state: "planned", document: d, selection: selected, parent: absolute,
		payload: payload, review: review, writeOutput: protectedoutput.Write,
	}}, nil
}

func clonePlan(plan Plan) Plan {
	plan.Fields = append([]FieldDisposition{}, plan.Fields...)
	plan.DuplicateGroups = cloneGroups(plan.DuplicateGroups)
	plan.Caveats = append([]string{}, plan.Caveats...)
	return plan
}

func (j *Job) Review() Review {
	if j == nil || j.private == nil {
		return Review{}
	}
	p := j.private
	p.mu.Lock()
	defer p.mu.Unlock()
	review := p.review
	review.Plan = clonePlan(review.Plan)
	review.Issues = append([]Issue{}, review.Issues...)
	return review
}

// Approve requires the current review correlation and the exact issue-ID set.
// Invalid responses leave planned state intact; authority is consumed once.
func (j *Job) Approve(reviewID string, ids []string) error {
	if j == nil || j.private == nil {
		return &SafeError{Code: "invalid_state"}
	}
	p := j.private
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != "planned" {
		return &SafeError{Code: "invalid_state"}
	}
	if reviewID != p.review.ReviewID || len(ids) != len(p.review.Issues) {
		return &SafeError{Code: "approval_invalid"}
	}
	required := make(map[string]bool, len(p.review.Issues))
	for _, issue := range p.review.Issues {
		required[issue.ID] = true
	}
	for _, id := range ids {
		if !required[id] {
			return &SafeError{Code: "approval_invalid"}
		}
		delete(required, id)
	}
	p.state = "approved"
	return nil
}

// Commit claims approved -> writing under the shared lock before any output.
// Every attempted write is terminal, including cancellation and publication errors.
func (j *Job) Commit(ctx context.Context) (Receipt, error) {
	if j == nil || j.private == nil {
		return Receipt{}, &SafeError{Code: "invalid_state"}
	}
	p := j.private
	p.mu.Lock()
	if p.state != "approved" {
		code := "invalid_state"
		if p.state == "planned" {
			code = "approval_required"
		}
		p.mu.Unlock()
		return Receipt{}, &SafeError{Code: code}
	}
	p.state = "writing"
	p.mu.Unlock()
	if ctx == nil {
		return j.fail("invalid_state")
	}
	if ctx.Err() != nil {
		return j.fail("output_cancelled")
	}
	result, err := p.writeOutput(ctx, p.parent, p.payload)
	if ctx.Err() != nil {
		return j.fail("output_cancelled")
	}
	if err != nil {
		return j.fail(outputErrorCode(err))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Serialize the last observed cancellation with the completion decision.
	if ctx.Err() != nil {
		p.state = "cancelled"
		return Receipt{}, &SafeError{Code: "output_cancelled"}
	}
	p.state = "completed"
	plan := clonePlan(p.review.Plan)
	plan.State = "output_validated"
	plan.OutputEmitted = true
	caveats := make([]string, 0, len(plan.Caveats))
	for _, caveat := range plan.Caveats {
		if caveat != "planned_only_no_output" {
			caveats = append(caveats, caveat)
		}
	}
	plan.Caveats = caveats
	return Receipt{Plan: plan, Profile: p.review.Profile, JobDirectory: result.JobDirectory, FileName: result.FileName}, nil
}

func (j *Job) fail(code string) (Receipt, error) {
	p := j.private
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = "failed"
	if code == "output_cancelled" {
		p.state = "cancelled"
	}
	return Receipt{}, &SafeError{Code: code}
}

func outputErrorCode(err error) string {
	var output *protectedoutput.Error
	if errors.As(err, &output) && output != nil {
		switch output.Code {
		case "output_platform", "output_parent", "output_create", "output_write", "output_sync", "output_readback", "output_close", "output_publish", "output_cancelled":
			return output.Code
		}
	}
	return "output_write"
}

func (j *Job) State() string {
	if j == nil || j.private == nil {
		return "invalid"
	}
	p := j.private
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

func reviewIssues(d *Document, selected []int) []Issue {
	count := len(selected)
	issues := []Issue{{ID: "experimental-import", Code: "experimental_import", Records: count}}
	if count == 0 {
		return issues
	}
	for column, header := range d.chromeHeaders {
		switch header {
		case "name", "url", "username", "password", "note":
		default:
			issues = append(issues, Issue{ID: fmt.Sprintf("relocate-column-%d", column+1), Code: "concealed_custom_field", Column: column + 1, Records: count})
		}
	}
	conditions := []struct {
		header, id, code string
		blank            bool
	}{
		{"name", "provider-blank-name", "import_name_placeholder", true},
		{"note", "provider-blank-notes", "import_notes_null", true},
		{"username", "provider-empty-username", "import_username_absent", false},
		{"password", "provider-empty-password", "import_password_absent", false},
		{"url", "provider-empty-url", "import_uri_removed", false},
	}
	nameColumn, passwordColumn := 0, 0
	for _, condition := range conditions {
		for column, header := range d.chromeHeaders {
			if header != condition.header {
				continue
			}
			if header == "name" {
				nameColumn = column
			}
			if header == "password" {
				passwordColumn = column
			}
			affected := 0
			for _, record := range selected {
				cell := d.chromeRows[record-1][column]
				if cell == "" || (condition.blank && ecmaBlank(cell)) {
					affected++
				}
			}
			if affected != 0 {
				issues = append(issues, Issue{ID: condition.id, Code: condition.code, Column: column + 1, Records: affected})
			}
		}
	}
	rejected := true
	for _, sample := range []int{0, count / 2, count - 1} {
		row := d.chromeRows[selected[sample]-1]
		if (row[nameColumn] != "--" && !ecmaBlank(row[nameColumn])) || !ecmaBlank(row[passwordColumn]) {
			rejected = false
			break
		}
	}
	if rejected {
		issues = append(issues, Issue{ID: "provider-import-rejection", Code: "import_sample_rejected", Records: count})
	}
	if count > 7000 {
		issues = append(issues, Issue{ID: "provider-large-export", Code: "import_item_limit", Records: count})
	}
	return issues
}

// ECMAScript trim includes FEFF and excludes Unicode White_Space's U+0085.
// Do not use strings.TrimSpace: its set changes the inspected provider behavior.
func ecmaBlank(value string) bool {
	for _, r := range value {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', '\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
		default:
			if r < '\u2000' || r > '\u200a' {
				return false
			}
		}
	}
	return true
}
