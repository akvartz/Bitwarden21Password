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
	input     string
	source    migration.Format
	target    migration.Format
	selection []int
	parent    string
	asJSON    bool
}

func runConvert(ctx context.Context, options conversionOptions, stdin io.Reader, stdout, stderr io.Writer, open fileOpener) int {
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if !protectedoutput.Supported() {
		return reportError(stderr, &migration.SafeError{Code: "output_platform"})
	}
	data, err := readInput(options.input, open)
	if err != nil {
		return reportError(stderr, err)
	}
	document, err := migration.Parse(data, options.source)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	job, err := document.NewJob(options.target, options.selection, options.parent)
	if err != nil {
		return reportError(stderr, err)
	}
	review := job.Review()
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
	}
	return nil
}

func renderApproval(writer io.Writer, review migration.Review) error {
	var explanation strings.Builder
	explanation.WriteString("Review the required issues before approving. Output is plaintext and this route is experimental. Destination provider acceptance is unverified.\n")
	for _, issue := range review.Issues {
		switch issue.Code {
		case "experimental_import":
			explanation.WriteString("Encrypted field-size limits vary by provider version, so generated JSON may be rejected despite local validation. Values are preserved without truncation.\n")
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
