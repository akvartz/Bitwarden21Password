package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/akvartz/Bitwarden21Password/internal/migration"
	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
)

const approvalLineLimit = 64 * 1024

type conversionOptions struct {
	input           string
	source          migration.Format
	target          migration.Format
	filters         migration.Selection
	parent          string
	asJSON          bool
	passwordStdin   bool
	passwordJSON    bool
	recoveryKeyPath string
}

func runConvert(ctx context.Context, options conversionOptions, stdin io.Reader, stdout, stderr io.Writer, open fileOpener) int {
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if !protectedoutput.Supported() {
		return reportError(stderr, &migration.SafeError{Code: "output_platform"})
	}
	if err := renderProgress(ctx, stderr, "reading"); err != nil {
		return reportError(stderr, err)
	}
	data, err := readInput(options.input, open)
	if err != nil {
		return reportError(stderr, err)
	}
	document, err := loadDocument(ctx, data, options.source, options.passwordStdin, options.passwordJSON, stdin, stderr)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	selection, err := document.Select(options.filters)
	if err != nil {
		return reportError(stderr, err)
	}
	if len(selection) == 0 {
		selection = nil
	}
	var identity []byte
	if options.recoveryKeyPath != "" {
		identity, err = readLimitedInput(options.recoveryKeyPath, open, recoveryKeyFileLimit, "recovery_identity")
		if err != nil {
			return reportError(stderr, err)
		}
		defer clear(identity)
	}
	job, err := document.NewJobWithRecovery(options.target, selection, options.parent, identity)
	if err != nil {
		return reportError(stderr, err)
	}
	review := job.Review()
	if err := renderProgress(ctx, stderr, "reviewing"); err != nil {
		return reportError(stderr, err)
	}
	if err := renderReview(stdout, review, options.asJSON); err != nil {
		return finishReport(err, stderr)
	}
	if err := renderApproval(checkedWriter{stderr}, review); err != nil {
		return finishReport(err, stderr)
	}
	line, err := readApproval(ctx, stdin)
	if err != nil {
		return reportError(stderr, err)
	}
	words := strings.Fields(line)
	if len(words) < 3 || words[0] != "approve" {
		return reportError(stderr, &migration.SafeError{Code: "approval_invalid"})
	}
	if err := job.Approve(words[1], words[2:]); err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if err := renderProgress(ctx, stderr, "writing_and_validating"); err != nil {
		return reportError(stderr, err)
	}
	if identity != nil {
		if err := renderProgress(ctx, stderr, "recovery"); err != nil {
			return reportError(stderr, err)
		}
	}
	receipt, err := job.Commit(ctx)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	// A report error can happen after successful publication. Return failure
	// without retrying either the consumed job or the completion report.
	reportErr := renderCompletion(stdout, receipt, options.asJSON)
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	return finishReport(reportErr, stderr)
}

func renderProgress(ctx context.Context, writer io.Writer, stage string) error {
	if ctx.Err() != nil {
		return &failure{"output_cancelled", 1}
	}
	switch stage {
	case "reading", "reviewing", "writing_and_validating", "recovery":
	default:
		return &failure{"invalid_state", 3}
	}
	// Every caller supplies a fixed local stage; input-derived values are never
	// accepted as progress text. Commit owns writing, readback and recovery.
	if _, err := fmt.Fprintf(checkedWriter{writer}, "progress: %s\n", stage); err != nil {
		return &failure{"output_write", 1}
	}
	if ctx.Err() != nil {
		return &failure{"output_cancelled", 1}
	}
	return nil
}

func renderReview(writer io.Writer, review migration.Review, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(writer).Encode(struct {
			Event  string           `json:"event"`
			Review migration.Review `json:"review"`
		}{"review", review})
	}
	if _, err := fmt.Fprintf(writer, "review_id: %s\nprofile: %s\n", review.ReviewID, review.Profile); err != nil {
		return err
	}
	if err := renderPlan(writer, review.Plan, false); err != nil {
		return err
	}
	for _, issue := range review.Issues {
		if _, err := fmt.Fprintf(writer, "required_issue: %s (code=%s, column=%d, records=%d)\n", issue.ID, issue.Code, issue.Column, issue.Records); err != nil {
			return err
		}
		for _, location := range issue.Locations {
			if location.Record == 0 {
				if _, err := fmt.Fprintf(writer, "issue_location %s: metadata field %d\n", issue.ID, location.Field); err != nil {
					return err
				}
			} else {
				if _, err := fmt.Fprintf(writer, "issue_location %s: record %d field %d\n", issue.ID, location.Record, location.Field); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func renderApproval(writer io.Writer, review migration.Review) error {
	var explanation strings.Builder
	explanation.WriteString("Review the required issues before approving. Output is plaintext and this route is experimental. Destination provider acceptance is unverified.\n")
	for _, issue := range review.Issues {
		switch issue.Code {
		case "experimental_import":
			explanation.WriteString("Provider versions, encrypted field-size limits and importer behavior vary. Generated exports may be rejected or changed despite local validation; no values are truncated. A synthetic provider import is still required.\n")
		case "concealed_custom_field":
			fmt.Fprintf(&explanation, "Column %d relocates to concealed custom fields for %d selected records; original labels and values remain in the export.\n", issue.Column, issue.Records)
		case "import_name_placeholder":
			explanation.WriteString("The provider replaces blank names with a placeholder. Blank names together with blank passwords can also cause import rejection.\n")
		case "import_notes_null":
			explanation.WriteString("The provider changes blank notes to null. Original note values remain in the local JSON.\n")
		case "import_username_absent":
			explanation.WriteString("The provider may omit exactly empty username values after import.\n")
		case "import_password_absent":
			explanation.WriteString("The provider may omit exactly empty password values after import. A blank name with an empty password can also cause rejection.\n")
		case "import_uri_removed":
			explanation.WriteString("The provider removes exactly empty URI values after import.\n")
		case "import_sample_rejected":
			explanation.WriteString("The inspected provider sample checks may reject this import because all sampled names are blank or -- and their passwords are blank.\n")
		case "import_item_limit":
			explanation.WriteString("The inspected cloud individual-import path rejects batches above 7,000 records. Published limits and provider versions can differ.\n")
		case "fields_unsupported":
			explanation.WriteString("Unsupported source fields listed by record and field ordinal are absent from the destination export. Review each location; encrypted recovery retention does not migrate these fields.\n")
		case "fields_omitted":
			explanation.WriteString("The listed source fields are deliberately omitted from destination output. Their original representations cannot be verified by destination comparison.\n")
		case "fields_transformed":
			explanation.WriteString("The listed source fields change representation in the destination schema. Review the transformation before acknowledging its exact issue ID.\n")
		case "fields_relocated":
			explanation.WriteString("The listed values move to different destination fields. Their placement and concealment can differ in the destination application.\n")
		case "metadata_unsupported":
			explanation.WriteString("Source metadata listed by metadata field ordinal is absent from the destination export, including unsupported container relationships and provider bookkeeping.\n")
		case "intermediary_mapping":
			explanation.WriteString("This route passes through an intermediate Bitwarden representation. Source-field accounting includes losses at both mappings.\n")
		case "recovery_whole_source":
			explanation.WriteString("Encrypted recovery retains the entire original source, including excluded records and unsupported fields. It is preserved but not migrated. Keep the private key separately; losing it makes recovery unreadable.\n")
		case "browser_generated_title":
			explanation.WriteString("Firefox exports have no source title. The destination title is generated from the exact source URL; the original URL value is also retained.\n")
		case "browser_totp_profile":
			explanation.WriteString("Safari OTPAuth values map to the destination TOTP URI representation. Functional acceptance and authentication remain unverified; test the generated item in the destination application.\n")
		default:
			fmt.Fprintf(&explanation, "Required issue %s (code=%s) needs explicit acknowledgment for the listed scope.\n", issue.ID, issue.Code)
		}
	}
	explanation.WriteString("To approve this review, enter exactly this line:\n")
	explanation.WriteString("approve ")
	explanation.WriteString(review.ReviewID)
	for _, issue := range review.Issues {
		explanation.WriteByte(' ')
		explanation.WriteString(issue.ID)
	}
	explanation.WriteByte('\n')
	_, err := io.WriteString(writer, explanation.String())
	return err
}

func renderCompletion(writer io.Writer, receipt migration.Receipt, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(writer).Encode(struct {
			Event   string            `json:"event"`
			Receipt migration.Receipt `json:"receipt"`
		}{"completed", receipt})
	}
	if _, err := fmt.Fprintf(writer, "completed\nprofile: %s\njob_directory: %s\nfile_name: %s\n", receipt.Profile, receipt.JobDirectory, receipt.FileName); err != nil {
		return err
	}
	if receipt.RecoveryJobDirectory != "" {
		if _, err := fmt.Fprintf(writer, "recovery_job_directory: %s\nrecovery_file_name: %s\nRecovery is preserved but not migrated; keep the private key separately.\n", receipt.RecoveryJobDirectory, receipt.RecoveryFileName); err != nil {
			return err
		}
	}
	return renderPlan(writer, receipt.Plan, false)
}

type approvalResult struct {
	line string
	err  error
}

func readApproval(ctx context.Context, stdin io.Reader) (string, error) {
	if ctx.Err() != nil {
		return "", &failure{"output_cancelled", 1}
	}
	if stdin == nil {
		return "", &migration.SafeError{Code: "approval_required"}
	}
	// A generic io.Reader cannot be interrupted without closing caller-owned
	// input. One bounded goroutine and a buffered result let cancellation return
	// while the caller remains responsible for unblocking that read.
	result := make(chan approvalResult, 1)
	go func() {
		line, err := readApprovalLine(ctx, stdin)
		result <- approvalResult{line, err}
	}()
	select {
	case <-ctx.Done():
		return "", &failure{"output_cancelled", 1}
	case received := <-result:
		if ctx.Err() != nil {
			return "", &failure{"output_cancelled", 1}
		}
		return received.line, received.err
	}
}

func readApprovalLine(ctx context.Context, stdin io.Reader) (string, error) {
	line := make([]byte, 0, 256)
	var one [1]byte
	emptyReads := 0
	for len(line) < approvalLineLimit {
		if ctx.Err() != nil {
			return "", &failure{"output_cancelled", 1}
		}
		// Read exactly through the first newline without buffering a second
		// response. The bound includes the newline and any final carriage return.
		n, err := stdin.Read(one[:])
		if ctx.Err() != nil {
			return "", &failure{"output_cancelled", 1}
		}
		if err != nil && err != io.EOF {
			return "", &failure{"approval_read", 1}
		}
		if n < 0 || n > 1 {
			return "", &failure{"approval_read", 1}
		}
		if n == 1 {
			line = append(line, one[0])
			// A conforming Reader may return the final newline with EOF.
			// Other read errors remain failures even when a line is complete.
			if one[0] == '\n' {
				return string(line), nil
			}
		}
		if err == io.EOF {
			return "", &migration.SafeError{Code: "approval_required"}
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return "", &failure{"approval_read", 1}
			}
			continue
		}
		emptyReads = 0
	}
	return "", &migration.SafeError{Code: "approval_invalid"}
}
