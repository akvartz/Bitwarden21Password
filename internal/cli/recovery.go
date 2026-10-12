package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/akvartz/Bitwarden21Password/internal/migration"
	"github.com/akvartz/Bitwarden21Password/internal/protectedoutput"
	"github.com/akvartz/Bitwarden21Password/internal/recovery"
)

const recoveryKeyFileLimit = 4 << 10

type artifactReceipt struct {
	JobDirectory string `json:"job_directory"`
	FileName     string `json:"file_name"`
}

func runRecoverySave(ctx context.Context, input string, source migration.Format, keyPath, parent string, stdout, stderr io.Writer, open fileOpener, asJSON bool) int {
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if !protectedoutput.Supported() {
		return reportError(stderr, &protectedoutput.Error{Code: "output_platform"})
	}
	original, err := readInput(input, open)
	if err != nil {
		return reportError(stderr, err)
	}
	defer clear(original)
	identity, err := readLimitedInput(keyPath, open, recoveryKeyFileLimit, "recovery_identity")
	if err != nil {
		return reportError(stderr, err)
	}
	defer clear(identity)
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	ciphertext, err := recovery.Encrypt(string(source), original, identity)
	if err != nil {
		return reportError(stderr, err)
	}
	retained, err := recovery.Decrypt(ciphertext, identity)
	if err != nil {
		return reportError(stderr, err)
	}
	valid := retained.Format == string(source) && bytes.Equal(retained.Source, original)
	clear(retained.Source)
	if !valid {
		return reportError(stderr, &failure{"output_validation", 1})
	}
	result, err := protectedoutput.WriteNamed(ctx, parent, "recovery.age", ciphertext)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	var reportErr error
	if asJSON {
		reportErr = renderJSON(stdout, struct {
			artifactReceipt
			Retention    string           `json:"retention"`
			SourceFormat migration.Format `json:"source_format"`
			SourceBytes  int              `json:"source_bytes"`
		}{artifactReceipt{result.JobDirectory, result.FileName}, "whole_source_not_migrated", source, len(original)})
	} else {
		reportErr = renderArtifactReceipt(stdout, result, false)
		if reportErr == nil {
			_, reportErr = io.WriteString(stdout, "retention: whole_source_not_migrated\nEncrypted recovery preserves the exact whole original source; it is not destination migration.\n")
		}
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	return finishReport(reportErr, stderr)
}

func runRecoveryKey(ctx context.Context, parent string, stdout, stderr io.Writer, asJSON bool) int {
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if !protectedoutput.Supported() {
		return reportError(stderr, &protectedoutput.Error{Code: "output_platform"})
	}
	identity, err := recovery.GenerateIdentity()
	if err != nil {
		return reportError(stderr, err)
	}
	defer clear(identity)
	result, err := protectedoutput.WriteNamed(ctx, parent, "recovery-key.txt", identity)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	reportErr := renderArtifactReceipt(stdout, result, asJSON)
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	return finishReport(reportErr, stderr)
}

func runRecover(ctx context.Context, input, keyPath, parent string, stdout, stderr io.Writer, open fileOpener, asJSON bool) int {
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	if !protectedoutput.Supported() {
		return reportError(stderr, &protectedoutput.Error{Code: "output_platform"})
	}
	ciphertext, err := readLimitedInput(input, open, recovery.MaxCiphertextBytes, "recovery_ciphertext_limit")
	if err != nil {
		return reportError(stderr, err)
	}
	identity, err := readLimitedInput(keyPath, open, recoveryKeyFileLimit, "recovery_identity")
	if err != nil {
		return reportError(stderr, err)
	}
	defer clear(identity)
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	payload, err := recovery.Decrypt(ciphertext, identity)
	if err != nil {
		return reportError(stderr, err)
	}
	defer clear(payload.Source)
	name := ""
	switch payload.Format {
	case "chrome-csv", "firefox-csv", "safari-csv":
		name = "source.csv"
	case "bitwarden-json":
		name = "source.json"
	case "onepassword-1pux":
		name = "source.1pux"
	case "proton-pass-zip":
		name = "source.zip"
	default:
		return reportError(stderr, &recovery.Error{Code: "recovery_format"})
	}
	result, err := protectedoutput.WriteNamed(ctx, parent, name, payload.Source)
	if err != nil {
		return reportError(stderr, err)
	}
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	reportErr := renderArtifactReceipt(stdout, result, asJSON)
	if ctx.Err() != nil {
		return reportError(stderr, &failure{"output_cancelled", 1})
	}
	return finishReport(reportErr, stderr)
}

func renderArtifactReceipt(writer io.Writer, result protectedoutput.Result, asJSON bool) error {
	receipt := artifactReceipt{result.JobDirectory, result.FileName}
	if asJSON {
		return renderJSON(writer, receipt)
	}
	_, err := fmt.Fprintf(writer, "completed\njob_directory: %s\nfile_name: %s\n", receipt.JobDirectory, receipt.FileName)
	return err
}
