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
	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/recovery"
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

const helpText = `pwmigrate-go: local password export migration with explicit review

pwmigrate-go inspect --input PATH [--from FORMAT] [PASSWORD] [--json]
pwmigrate-go plan --input PATH [--from FORMAT] --to FORMAT [SELECTION] [PASSWORD] [--json]
pwmigrate-go convert --input PATH [--from FORMAT] --to FORMAT --output-dir DIRECTORY [SELECTION] [PASSWORD] [--recovery-key-file PATH] [--json]
pwmigrate-go compare --input PATH [--from FORMAT] --to FORMAT --destination PATH [SELECTION] [PASSWORD] [--json]
pwmigrate-go recovery-key --output-dir DIRECTORY [--json]
pwmigrate-go recovery-save --input PATH --from FORMAT --key-file PATH --output-dir DIRECTORY [--json]
pwmigrate-go recover --input PATH --key-file PATH --output-dir DIRECTORY [--json]
pwmigrate-go formats [--json]
pwmigrate-go version [--json]
pwmigrate-go --version
pwmigrate-go help

Format IDs: chrome-csv, firefox-csv, safari-csv, bitwarden-json,
onepassword-1pux, proton-pass-zip.
SELECTION: --select 1,3 --vault 1,2 --folder 1 --kind login,card.
Selection criteria intersect; omitted criteria select the whole export.
Container and item ordinals are positive and one-based; labels never enter reports.
Plans emit no vault output and do not verify destination imports.
Conversion requires exact issue acknowledgment in the same process and private output.
Generated exports are plaintext; destination provider acceptance is unverified.
Supported encrypted inputs prompt locally with terminal echo disabled.
--password-stdin reads one password line before any conversion approval line.
PASSWORD: --password-stdin [--password-json]. JSON mode reads one JSON string
line; use escapes for CR/LF or Unicode to preserve multiline passwords exactly.
Recovery preserves the whole original source, including excluded records; it is not migration.
Keep the private recovery key separately. Losing it makes recovery unreadable.
Quote paths containing spaces; terminal path drag-and-drop can insert a quoted path.
`

// Run retains the process-input entry point for existing callers.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunContext(context.Background(), args, os.Stdin, stdout, stderr)
}

// RunContext returns 0 for success/help, 2 for argument errors, 3 for rejected
// input/approval/state/platform, and 1 for I/O, validation or cancellation.
// Context cancellation applies to output commands and secret input. Ordinary
// read-only reports retain default process signal behavior. The caller owns
// stdin and must unblock pending reads after cancellation. A terminal handle
// must remain open until its pending secret read finishes, before closing or
// reusing it. Secret and approval input phases do not consume each other's data.
// The caller must also unblock pending borrowed output writers before reusing
// them. Cancellation can return without a final diagnostic or completion event.
func RunContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runContext(ctx, args, stdin, stdout, stderr, openInput)
}

// run preserves the existing injectable opener for read-only loader tests.
func run(args []string, stdout, stderr io.Writer, open fileOpener) int {
	return runContext(context.Background(), args, os.Stdin, stdout, stderr, open)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, open fileOpener) int {
	stdout, stderr = withWriteContext(ctx, stdout), withWriteContext(ctx, stderr)
	output := checkedWriter{stdout}
	if len(args) == 0 || (len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")) {
		_, err := io.WriteString(output, helpText)
		return finishReport(err, stderr)
	}
	command := args[0]
	if len(args) == 1 && command == "--version" {
		command = "version"
	}
	if command != "inspect" && command != "plan" && command != "convert" && command != "compare" && command != "recovery-key" && command != "recovery-save" && command != "recover" && command != "formats" && command != "version" {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}

	options := flag.NewFlagSet(command, flag.ContinueOnError)
	// flag's diagnostics contain user tokens and values. Only our safe codes leave.
	options.SetOutput(io.Discard)
	asJSON := options.Bool("json", false, "render JSON report")
	var input, source, target, selected, vaults, folders, kinds, parent, destination, keyPath string
	var passwordStdin, passwordJSON bool
	isMigration := command == "inspect" || command == "plan" || command == "convert" || command == "compare"
	hasSelection := command == "plan" || command == "convert" || command == "compare"
	if isMigration || command == "recover" || command == "recovery-save" {
		options.StringVar(&input, "input", "", "input export")
	}
	if isMigration {
		options.StringVar(&source, "from", "", "source format")
		options.BoolVar(&passwordStdin, "password-stdin", false, "read one local password line")
		options.BoolVar(&passwordJSON, "password-json", false, "decode password stdin line as one JSON string")
	}
	if command == "recovery-save" {
		options.StringVar(&source, "from", "", "declared original source format")
	}
	if hasSelection {
		options.StringVar(&target, "to", "", "target format")
		options.StringVar(&selected, "select", "", "record ordinals")
		options.StringVar(&vaults, "vault", "", "vault ordinals")
		options.StringVar(&folders, "folder", "", "folder ordinals")
		options.StringVar(&kinds, "kind", "", "fixed item kind codes")
	}
	if command == "convert" || command == "recovery-key" || command == "recover" || command == "recovery-save" {
		options.StringVar(&parent, "output-dir", "", "existing private output parent")
	}
	if command == "compare" {
		options.StringVar(&destination, "destination", "", "supplied destination export")
	}
	if command == "convert" {
		options.StringVar(&keyPath, "recovery-key-file", "", "private recovery identity file")
	}
	if command == "recover" || command == "recovery-save" {
		options.StringVar(&keyPath, "key-file", "", "private recovery identity file")
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
	if passwordJSON && !passwordStdin {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}
	if command == "formats" {
		return finishReport(renderFormats(output, *asJSON), stderr)
	}
	if command == "version" {
		return finishReport(renderVersion(output, *asJSON), stderr)
	}
	if command == "recovery-key" {
		if parent == "" {
			return reportError(stderr, &failure{"invalid_arguments", 2})
		}
		return runRecoveryKey(ctx, parent, output, stderr, *asJSON)
	}
	if command == "recovery-save" {
		if input == "" || keyPath == "" || parent == "" || source == "" {
			return reportError(stderr, &failure{"invalid_arguments", 2})
		}
		if !migration.KnownFormat(migration.Format(source)) {
			return reportError(stderr, &migration.SafeError{Code: "unknown_format"})
		}
		return runRecoverySave(ctx, input, migration.Format(source), keyPath, parent, output, stderr, open, *asJSON)
	}
	if command == "recover" {
		if input == "" || keyPath == "" || parent == "" {
			return reportError(stderr, &failure{"invalid_arguments", 2})
		}
		return runRecover(ctx, input, keyPath, parent, output, stderr, open, *asJSON)
	}
	if input == "" || (hasSelection && target == "") || (command == "convert" && parent == "") || (command == "compare" && destination == "") {
		return reportError(stderr, &failure{"invalid_arguments", 2})
	}
	if source != "" && !migration.KnownFormat(migration.Format(source)) {
		return reportError(stderr, &migration.SafeError{Code: "unknown_format"})
	}
	if hasSelection && (!migration.KnownFormat(migration.Format(target)) || migration.IsBrowserFormat(migration.Format(target))) {
		return reportError(stderr, &migration.SafeError{Code: "unsupported_route"})
	}
	filters := migration.Selection{}
	var selectionErr error
	options.Visit(func(f *flag.Flag) {
		if selectionErr != nil {
			return
		}
		switch f.Name {
		case "select":
			filters.Items, selectionErr = parseSelection(selected)
		case "vault":
			filters.Vaults, selectionErr = parseSelection(vaults)
		case "folder":
			filters.Folders, selectionErr = parseSelection(folders)
		case "kind":
			if kinds == "" || strings.Count(kinds, ",") >= 6 {
				selectionErr = &migration.SafeError{Code: "invalid_selection"}
				return
			}
			filters.Kinds = strings.Split(kinds, ",")
		case "recovery-key-file":
			if keyPath == "" {
				selectionErr = &failure{"invalid_arguments", 2}
			}
		}
	})
	if selectionErr != nil {
		return reportError(stderr, selectionErr)
	}

	if command == "convert" {
		return runConvert(ctx, conversionOptions{input: input, source: migration.Format(source), target: migration.Format(target), filters: filters, parent: parent, asJSON: *asJSON, passwordStdin: passwordStdin, passwordJSON: passwordJSON, recoveryKeyPath: keyPath}, stdin, output, stderr, open)
	}

	data, err := readInput(input, open)
	if err != nil {
		return reportError(stderr, err)
	}
	document, err := loadDocument(ctx, data, migration.Format(source), passwordStdin, passwordJSON, stdin, stderr)
	if err != nil {
		return reportError(stderr, err)
	}
	if command == "inspect" {
		return finishReport(renderInventory(output, document.Inspect(), *asJSON), stderr)
	}
	selection, err := document.Select(filters)
	if err != nil {
		return reportError(stderr, err)
	}
	if len(selection) == 0 {
		selection = nil
	}
	if command == "compare" {
		destinationData, err := readInput(destination, open)
		if err != nil {
			return reportError(stderr, err)
		}
		destinationDocument, err := loadDocument(ctx, destinationData, migration.Format(target), passwordStdin, passwordJSON, stdin, stderr)
		if err != nil {
			return reportError(stderr, err)
		}
		comparison, err := document.Compare(migration.Format(target), selection, destinationDocument)
		if err != nil {
			return reportError(stderr, err)
		}
		return finishReport(renderComparison(output, comparison, *asJSON), stderr)
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
	return readLimitedInput(path, open, migration.MaxInputBytes, "input_limit")
}

func readLimitedInput(path string, open fileOpener, limit int, limitCode string) ([]byte, error) {
	file, err := open(path)
	if err != nil {
		var safe *failure
		if errors.As(err, &safe) {
			return nil, safe
		}
		return nil, &failure{"input_open", 1}
	}
	data, readErr := readOpenedLimitedInput(file, limit, limitCode)
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
	return readOpenedLimitedInput(file, migration.MaxInputBytes, "input_limit")
}

func readOpenedLimitedInput(file inputFile, limit int, limitCode string) ([]byte, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, &failure{"input_stat", 1}
	}
	// Validate the opened handle, not an earlier path lookup that can be replaced.
	if !info.Mode().IsRegular() {
		return nil, &failure{"input_not_regular", 3}
	}
	// Size metadata can be stale or misleading; bound the bytes actually read.
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return nil, &failure{"input_read", 1}
	}
	if len(data) > limit {
		clear(data)
		return nil, &failure{limitCode, 3}
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
		var canceled *canceledReport
		if errors.As(err, &canceled) {
			return 1
		}
		return reportError(stderr, &failure{"output_write", 1})
	}
	return 0
}

func reportError(stderr io.Writer, err error) int {
	var canceled *canceledReport
	if errors.As(err, &canceled) {
		return 1
	}
	message, exit := "invalid_input", 3
	var inputErr *migration.SafeError
	var ioErr *failure
	var outputErr *protectedoutput.Error
	var recoveryErr *recovery.Error
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
	case errors.As(err, &outputErr):
		message, exit = outputErr.Error(), 1
		if outputErr.Code == "output_platform" {
			exit = 3
		}
	case errors.As(err, &recoveryErr):
		message = recoveryErr.Error()
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
	ID                     migration.Format   `json:"id"`
	Inspect                bool               `json:"inspect"`
	PlanTargets            []migration.Format `json:"plan_targets"`
	ConvertTargets         []migration.Format `json:"convert_targets"`
	DestinationComparison  bool               `json:"destination_comparison"`
	ProviderImportVerified bool               `json:"provider_import_verified"`
}

func renderFormats(writer io.Writer, asJSON bool) error {
	formats := []formatCapability{
		{migration.ChromeCSV, true, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, true, false},
		{migration.FirefoxCSV, true, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, true, false},
		{migration.SafariCSV, true, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX, migration.ProtonPassZIP}, true, false},
		{migration.BitwardenJSON, true, []migration.Format{migration.OnePassword1PUX, migration.ProtonPassZIP}, []migration.Format{migration.OnePassword1PUX, migration.ProtonPassZIP}, true, false},
		{migration.OnePassword1PUX, true, []migration.Format{migration.BitwardenJSON, migration.ProtonPassZIP}, []migration.Format{migration.BitwardenJSON, migration.ProtonPassZIP}, true, false},
		{migration.ProtonPassZIP, true, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX}, []migration.Format{migration.BitwardenJSON, migration.OnePassword1PUX}, true, false},
	}
	if asJSON {
		report := struct {
			Formats                 []formatCapability `json:"formats"`
			OutputPlatformSupported bool               `json:"output_platform_supported"`
		}{formats, protectedoutput.Supported()}
		return renderJSON(writer, report)
	}
	for _, format := range formats {
		if _, err := fmt.Fprintf(writer, "%s: inspect; plan and experimental convert to %v with explicit approval; compare supplied destination exports\n", format.ID, format.PlanTargets); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "output_platform_supported: %t\n", protectedoutput.Supported()); err != nil {
		return err
	}
	_, err := io.WriteString(writer, "All routes are experimental. Destination imports unverified.\nBrowser inputs require the declared Chrome, Firefox or Safari CSV schemas; arbitrary browser schemas are refused.\nPrivate output uses platform protection; unsupported platforms and unsafe volumes are refused.\n")
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
	for _, field := range report.Metadata {
		if _, err := fmt.Fprintf(writer, "metadata field %d: %s\n", field.Field, field.Disposition); err != nil {
			return err
		}
	}
	return renderCoverage(writer, report.DuplicateGroups, report.Caveats)
}

func renderComparison(writer io.Writer, report migration.Comparison, asJSON bool) error {
	if asJSON {
		return renderJSON(writer, report)
	}
	if _, err := fmt.Fprintf(writer, "source: %s\ntarget: %s\nstate: %s\nexpected_records: %d\ndestination_records: %d\nmatched_records: %d\nmissing_records: %d\nunexpected_records: %d\nsource_metadata_fields_unobservable: %d\ndestination_metadata_fields_unobservable: %d\ndestination_import_verified: %t\nSupplied re-export observations only; destination provider acceptance remains unverified.\n", report.Source, report.Target, report.State, report.ExpectedRecords, report.DestinationRecords, report.MatchedRecords, report.MissingRecords, report.UnexpectedRecords, report.SourceMetadataFields, report.DestinationMetadataFields, report.DestinationImportVerified); err != nil {
		return err
	}
	for _, group := range report.Groups {
		if _, err := fmt.Fprintf(writer, "comparison_group: %s source_records=%v destination_records=%v matched=%d missing=%d unexpected=%d\n", group.Code, group.SourceRecords, group.DestinationRecords, group.MatchedRecords, group.MissingRecords, group.UnexpectedRecords); err != nil {
			return err
		}
	}
	for _, field := range report.SourceUnobservableFields {
		if _, err := fmt.Fprintf(writer, "source record %d field %d: %s\n", field.Record, field.Field, field.Code); err != nil {
			return err
		}
	}
	for _, field := range report.DestinationUnobservableFields {
		if _, err := fmt.Fprintf(writer, "destination record %d field %d: %s\n", field.Record, field.Field, field.Code); err != nil {
			return err
		}
	}
	return renderCoverage(writer, nil, report.Caveats)
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
