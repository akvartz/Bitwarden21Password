# pwmigrate

The Go implementation provides export inspection, field planning, and an
**experimental Linux Chrome CSV to Bitwarden JSON converter for synthetic
evaluation**. Conversion requires review and explicit approval in the same
process. It is not yet a production-qualified replacement. The legacy Rust
implementation remains available while Go milestones are validated.

## Build and use

Requires the installed Go 1.26.0 toolchain and standard library only. Build
without downloading a toolchain or dependencies:

```sh
GOTOOLCHAIN=local GOPROXY=off go build -o pwmigrate-go ./cmd/pwmigrate
```

Use `pwmigrate-go.exe` on Windows. The legacy Rust binary remains `pwmigrate`.
Read-only commands are available on Linux, macOS and Windows; export writing
currently runs only on Linux. macOS ACL/volume policy and Windows DACL handling
need implementation/review and native tests before enabling those writers.

```sh
./pwmigrate-go inspect --input synthetic-chrome.csv
./pwmigrate-go inspect --input synthetic-bitwarden.json --from bitwarden-json --json
./pwmigrate-go plan --input synthetic-chrome.csv --to bitwarden-json --json
./pwmigrate-go plan --input synthetic-chrome.csv --to bitwarden-json --select 1,3
./pwmigrate-go formats --json
./pwmigrate-go help

# Linux: choose a private existing parent directory for the export job.
mkdir -m 700 synthetic-output
./pwmigrate-go convert --input synthetic-chrome.csv --to bitwarden-json --output-dir synthetic-output
```

`convert` shows a review and an approval instruction. Enter the displayed
`approve REVIEW_ID ISSUE_ID ...` line only after reviewing the issues. The
review ID is new for every job; a response from an earlier job cannot authorize
this one. Missing, additional, repeated or incorrect issue IDs are rejected.
There is no `--yes`, `--force`, saved approval token or automatic retry.

`convert` also supports `--from chrome-csv`, `--select 1,3` and `--json`.
JSON mode emits newline-separated `review` and `completed` event objects,
with approval instructions on stderr and the same approval response on stdin.
It is a stream of events, not one JSON document. Other commands retain their
single JSON-report format. SIGINT/SIGTERM request cancellation of a conversion.
Read-only commands retain normal operating-system signal termination.

| Exact format ID | Inspect | Plan target | Convert target |
| --- | --- | --- | --- |
| `chrome-csv` | Yes | `bitwarden-json` | `bitwarden-json` on Linux |
| `bitwarden-json` | Unencrypted JSON only | None | None |

Omitting `--from` enables detection. Chrome requires `name`, `url`, `username`,
and `password` headers; `note` and unfamiliar columns are retained. Bitwarden
requires `encrypted:false` and an `items` array. Format aliases are unsupported.

## What the evidence means

Inspection reports counts, fixed item-kind labels, duplicate record ordinals
and export-coverage caveats. Plans account for every selected field. Selection
defaults to the whole export; `--select` accepts positive, unique one-based
record ordinals. Empty, repeated, malformed or out-of-range selections fail.
Duplicates remain separate records, in source order.

Generated JSON retains exact credential whitespace, embedded line endings,
Unicode, explicit empty cells and ordinary notes. Unknown columns become
concealed custom fields with their original label and value. No normalization,
merging, metadata-marker decoding or silent truncation is performed.

A successful conversion reports `output_validated`: decoded generated values
were compared against the selected source cells, then the saved bytes were
read back from the same opened file and compared. It still reports
`destination_import_verified:false`. This is local validation, not proof that
Bitwarden accepted the file or preserved all values after import.

The review calls out known importer risks. Inspected Bitwarden code replaces
blank names, collapses blank notes and empty credentials, and removes empty
URIs from its login view. Some blank-name/password combinations can reject an
entire batch. Large batches and encrypted field lengths have version-dependent
limits. The converter preserves the source values in JSON and requires the
applicable issue acknowledgments before writing. Unknown-column relocation
also requires acknowledgment. Every job requires `experimental-import`.

Reports exclude values, titles, URLs, usernames, arbitrary custom labels,
source/parent paths and source-derived fingerprints. A review includes a random
correlation ID; a completed receipt identifies only the generated job-directory
basename and fixed `bitwarden.json` filename, relative to the directory supplied
by the user. A read-only plan reports `planned` and `output_emitted:false`.
An empty export does not prove an empty account.

## Output handling and limits

On Linux, the existing output parent must be owned by the effective user and
not writable by group or others. Each attempt creates a new private `0700`
job directory and exclusively creates a `0600` partial file. Completed file
publication uses a no-clobber hard link; existing files are never replaced.
The writer checks writes, readback, sync and close before reporting success.
It needs a filesystem supporting those operations.

The complete job is not an atomic transaction. A failed or interrupted job may
leave private partial artifacts, or a complete file if a later operation fails.
**Require exit 0 and a successful completion receipt before importing a job.**
No recursive cleanup, source deletion or retry occurs. A broken or interrupted
final report can return failure even when a complete file and a completion event
already exist. Review the failed job locally instead of assuming a second
conversion is necessary.

The permission boundary covers ordinary other-user access on suitable local
Linux filesystems. It does not isolate root or another process running as the
same user. Secure erasure on SSDs/snapshots and perfect memory zeroization are
not guaranteed. Output is plaintext; encryption and recovery are later work.

Input and generated output are each bounded at 32 MiB. Output also passes the
existing strict JSON field/container/depth budgets. A valid Chrome input may
expand past those output limits and be rejected before any export file is
created. Other parser limits and malformed-input rules are documented in the
[design](docs/superpowers/specs/2026-10-11-go-migration-design.md).
The input loader checks the opened regular-file handle and bounds actual bytes;
Unix nonblocking opens reject FIFOs/devices without waiting for a writer.
Windows native device/pipe replacement behavior remains unqualified.

| Exit code | Meaning |
| --- | --- |
| `0` | Successful report/conversion or help |
| `2` | Invalid arguments or missing flags |
| `3` | Rejected input/selection/route/limits/approval/state or unsupported platform |
| `1` | I/O, local output validation or cancellation failure |

The table describes normal returns; operating-system signal termination of
read-only commands retains its normal signal exit status.

Runtime processing is local: no network, telemetry, account access, remote
assets or Rust fallback. No desktop UI, encrypted input unlocking, recovery
writer or destination re-export comparison is implemented yet.

## Development and qualification

```sh
GOTOOLCHAIN=local GOPROXY=off go test ./...
GOTOOLCHAIN=local GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOPROXY=off go vet ./...
```

The shared engine is in `internal/migration`, protected filesystem operations
in `internal/protectedoutput`, the CLI in `internal/cli`, and the entry point in
`cmd/pwmigrate`. Tests use synthetic temporary exports. See the
[M2 plan](docs/superpowers/plans/2026-10-11-protected-export.md),
[milestone status](docs/agentic/go-migration-status.md), and
[provider acceptance checklist](docs/agentic/bitwarden-import-qualification.md)
for actual evidence and remaining gates. Cross-compilation is not a native
platform test; self-roundtrips are not provider acceptance. No passkey transfer
or release-readiness claim is made.

## Legacy Rust reference

Rust source is preserved under `src/` and its existing fixtures/tests remain
available. Its adapters reference Bitwarden, 1Password CSV, Proton Pass,
LastPass, Chromium browsers, Firefox, Apple Passwords, KeePassXC, Dashlane,
NordPass, Keeper, and a canonical JSON representation. This adapter list does
not describe Go support or independently verified provider compatibility.

With an existing Rust toolchain, its documented build and test commands are:

```sh
cargo build --release
cargo test
cargo clippy
```

The legacy binary provides `convert`, `verify`, `inspect`, and `formats`.
The design review identified credential trimming, secret-bearing errors,
incomplete mappings, ambiguous notes-marker encoding, and unprotected output
in that implementation. Do not treat Rust as a correctness oracle or infer
complete preservation from a legacy round-trip. Retaining provider passkey
payloads does not demonstrate working passkey authentication or cross-provider
compatibility. Go M1 never silently falls back to Rust.

## License

MIT — see [LICENSE](LICENSE).
