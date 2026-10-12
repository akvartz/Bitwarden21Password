// Package cli exposes redacted inspection, planning and protected conversion.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/akvartz/Bitwarden21Password/internal/buildinfo"
	"github.com/akvartz/Bitwarden21Password/internal/migration"
)

type inputFile interface {
	io.Reader
	io.Closer
	Stat() (os.FileInfo, error)
}

type fileOpener func(string) (inputFile, error)

type failure struct {
	code string
	exit int
}

func (e *failure) Error() string { return e.code }

const helpText = `pwmigrate-go: local export inspection, planning and experimental conversion

pwmigrate-go inspect --input PATH [--from chrome-csv|bitwarden-json] [--json]
pwmigrate-go plan --input PATH [--from chrome-csv] --to bitwarden-json [--select 1,3] [--json]
pwmigrate-go convert --input PATH [--from chrome-csv] --to bitwarden-json --output-dir DIRECTORY [--select 1,3] [--json]
pwmigrate-go formats [--json]
pwmigrate-go version [--json]
pwmigrate-go --version
pwmigrate-go help

Format IDs are exact. Selection uses positive, unique one-based record ordinals.
Plans emit no vault output and do not verify destination imports.
Conversion requires explicit review in the same process and private Linux output.
Generated exports are plaintext; destination provider acceptance is unverified.
`

// Run retains the process-input entry point for existing callers.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, os.Stdin, stdout, stderr)
}

// RunContext returns 0 for success/help, 2 for argument errors, 3 for rejected
// input/approval/state/platform, and 1 for I/O, validation or cancellation.
// Context cancellation applies to convert; read-only commands do not use it.
// The caller retains ownership of stdin, including unblocking a generic reader
// after cancellation. Each conversion starts at most one bounded read goroutine.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(ctx, args, stdin, stdout, stderr, openInput)
}

// run preserves the existing injectable opener for read-only loader tests.
func run(args []string, stdout, stderr io.Writer, open fileOpener) int {
	return runContext(context.Background(), args, os.Stdin, stdout, stderr, open)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, open fileOpener) int {
	output := checkedWriter{stdout}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
		_, err := io.WriteString(output, helpText)
		return finishReport(err, stderr)
	}
	command := args[0]
	if len(args) == 1 && command == "--version" {
		command = "version"
	}
	if command != "inspect" && command != "plan" && command != "convert" && command != "formats" && command != "version" {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}

	options := flag.NewFlagSet(command, flag.ContinueOnError)
	// flag's diagnostics contain user tokens and values. Only our safe codes leave.
	options.SetOutput(io.Discard)
	asJSON := options.Bool("json", false, "render JSON report")
	var input, source, target, selected, parent string
	if command != "formats" && command != "version" {
		options.StringVar(&input, "input", "", "input export")
		options.StringVar(&source, "from", "", "source format")
	}
	if command == "plan" || command == "convert" {
		options.StringVar(&target, "to", "", "target format")
		options.StringVar(&selected, "select", "", "record ordinals")
	}
	if command == "convert" {
		options.StringVar(&parent, "output-dir", "", "existing private output parent")
	}
	if err := options.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err := io.WriteString(output, helpText)
			return finishReport(err, stderr)
		}
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}
	if options.NArg() != 0 {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}
	if command == "formats" {
		return finishReport(renderFormats(output, *asJSON), stderr)
	}
	if command == "version" {
		return finishReport(renderVersion(output, *asJSON), stderr)
	}
	if input == "" || ((command == "plan" || command == "convert") && target == "") || (command == "convert" && parent == "") {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}
	if source != "" && source != string(migration.ChromeCSV) && source != string(migration.BitwardenJSON) {
		return reportError(stderr, &migration.SafeError{Code: "unknown_format"})
	}
	if (command == "plan" || command == "convert") && target != string(migration.BitwardenJSON) {
		return reportError(stderr, &migration.SafeError{Code: "unsupported_route"})
	}
	var selection []int
	selectionSupplied := false
	options.Visit(func(f *flag.Flag) {
		if f.Name == "select" {
			selectionSupplied = true
		}
	})
	if selectionSupplied {
		var err error
		selection, err = parseSelection(selected)
		if err != nil {
			return reportError(stderr, err)
		}
	}

	if command == "convert" {
		return runConvert(ctx, conversionOptions{input, migration.Format(source), migration.Format(target), selection, parent, *asJSON}, stdin, output, stderr, open)
	}

	data, err := readInput(input, open)
	if err != nil {
		return reportError(stderr, err)
	}
	document, err := migration.Parse(data, migration.Format(source))
	if err != nil {
		return reportError(stderr, err)
	}
	if command == "inspect" {
		return finishReport(renderInventory(output, document.Inspect(), *asJSON), stderr)
	}
	plan, err := document.Plan(migration.Format(target), selection)
	if err != nil {
		return reportError(stderr, err)
	}
	return finishReport(renderPlan(output, plan, *asJSON), stderr)
}

func parseSelection(value string) ([]int, error) {
	invalid := &migration.SafeError{Code: "invalid_selection"}
	if value == "" || strings.Count(value, ",") >= migration.MaxRecords {
		return nil, invalid
	}
	parts := strings.Split(value, ",")
	selection := make([]int, len(parts))
	for i, part := range parts {
		if part == "" {
			return nil, invalid
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return nil, invalid
			}
		}
		record, err := strconv.Atoi(part)
		if err != nil || record <= 0 {
			return nil, invalid
		}
		selection[i] = record
	}
	return selection, nil
}

func readInput(path string, open fileOpener) ([]byte, error) {
	file, err := open(path)
	if err != nil {
		var safe *failure
		if errors.As(err, &safe) {
			return nil, safe
		}
		return nil, &failure{"input_open", 1}
	}
	data, readErr := readOpenedInput(file)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, &failure{"input_close", 1}
	}
	return data, nil
}

func readOpenedInput(file inputFile) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, &failure{"input_stat", 1}
	}
	// Validate the opened handle, not an earlier path lookup that can be replaced.
	if !info.Mode().IsRegular() {
		return nil, &failure{"input_not_regular", 3}
	}
	// Size metadata can be stale or misleading; bound the bytes actually read.
	data, err := io.ReadAll(io.LimitReader(file, int64(migration.MaxInputBytes)+1))
	if err != nil {
		return nil, &failure{"input_read", 1}
	}
	if len(data) > migration.MaxInputBytes {
		return nil, &migration.SafeError{Code: "input_limit"}
	}
	return data, nil
}

// checkedWriter also rejects broken writers that report a short write with no error.
type checkedWriter struct{ io.Writer }

func (w checkedWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	return n, err
}

func finishReport(err error, stderr io.Writer) int {
	if err != nil {
		return reportError(stderr, &failure{"output_write", 1})
	}
	return 0
}

func reportError(stderr io.Writer, err error) int {
	message, exit := "invalid_input", 3
	var inputErr *migration.SafeError
	var ioErr *failure
	switch {
	case errors.As(err, &inputErr):
		message = inputErr.Error()
		switch inputErr.Code {
		case "output_parent", "output_create", "output_write", "output_sync",
			"output_readback", "output_close", "output_publish", "output_cancelled", "output_validation":
			exit = 1
		}
	case errors.As(err, &ioErr):
		message, exit = ioErr.code, ioErr.exit
	}
	if _, err := fmt.Fprintln(checkedWriter{stderr}, message); err != nil {
		return 1
	}
	return exit
}

func renderJSON(writer io.Writer, report any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func renderVersion(writer io.Writer, asJSON bool) error {
	info := buildinfo.Current()
	if asJSON {
		return renderJSON(writer, info)
	}
	_, err := fmt.Fprintf(writer, "%s %s (commit %s; %s; %s/%s)\n", info.Program, info.Version, info.Commit, info.GoVersion, info.GOOS, info.GOARCH)
	return err
}

type formatCapability struct {
	ID          migration.Format   `json:"id"`
	Inspect     bool               `json:"inspect"`
	PlanTargets []migration.Format `json:"plan_targets"`
}

func renderFormats(writer io.Writer, asJSON bool) error {
	if asJSON {
		report := struct {
			Formats []formatCapability `json:"formats"`
		}{
			[]formatCapability{
				{migration.ChromeCSV, true, []migration.Format{migration.BitwardenJSON}},
				{migration.BitwardenJSON, true, []migration.Format{}},
			},
		}
		return renderJSON(writer, report)
	}
	_, err := io.WriteString(writer, "chrome-csv: inspect; plan to bitwarden-json; experimental convert to bitwarden-json on Linux with explicit approval\nbitwarden-json: inspect\nOther platforms: read-only. Destination imports unverified.\n")
	return err
}

func renderInventory(writer io.Writer, report migration.Inventory, asJSON bool) error {
	if asJSON {
		return renderJSON(writer, report)
	}
	if _, err := fmt.Fprintf(writer, "format: %s\nrecords: %d\nfields: %d\nmetadata_fields: %d\nduplicate_detection: %s\nduplicate_groups: %d\n", report.Format, report.Records, report.Fields, report.MetadataFields, report.DuplicateDetection, len(report.DuplicateGroups)); err != nil {
		return err
	}
	for _, kind := range []string{"login", "secure_note", "card", "identity", "ssh_key", "unknown"} {
		if _, err := fmt.Fprintf(writer, "kind %s: %d\n", kind, report.Kinds[kind]); err != nil {
			return err
		}
	}
	return renderCoverage(writer, report.DuplicateGroups, report.Caveats)
}

func renderPlan(writer io.Writer, report migration.Plan, asJSON bool) error {
	if asJSON {
		return renderJSON(writer, report)
	}
	if _, err := fmt.Fprintf(writer, "source: %s\ntarget: %s\nstate: %s\ntotal_records: %d\nselected_records: %d\nexcluded_records: %d\noutput_emitted: %t\ndestination_import_verified: %t\nduplicate_groups: %d\n", report.Source, report.Target, report.State, report.TotalRecords, report.SelectedRecords, report.ExcludedRecords, report.OutputEmitted, report.DestinationImportVerified, len(report.DuplicateGroups)); err != nil {
		return err
	}
	for _, field := range report.Fields {
		if _, err := fmt.Fprintf(writer, "record %d field %d: %s -> %s (concealed=%t)\n", field.Record, field.Field, field.Disposition, field.TargetField, field.Concealed); err != nil {
			return err
		}
	}
	return renderCoverage(writer, report.DuplicateGroups, report.Caveats)
}

func renderCoverage(writer io.Writer, groups [][]int, caveats []string) error {
	for _, group := range groups {
		if _, err := fmt.Fprintf(writer, "duplicate_group: %v\n", group); err != nil {
			return err
		}
	}
	for _, caveat := range caveats {
		if _, err := fmt.Fprintf(writer, "caveat: %s\n", caveat); err != nil {
			return err
		}
	}
	return nil
}
