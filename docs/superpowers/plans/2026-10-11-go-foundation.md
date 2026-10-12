# Go inspection and planning foundation implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a dependency-free read-only Go CLI that inventories Chrome CSV/Bitwarden JSON and plans Chrome-to-Bitwarden mappings without exposing credentials or writing vaults.

**Architecture:** A private source document and strict parsers live in internal/migration, with safe report DTOs and one explicit planning route. A thin CLI renders those DTOs and bounds file reads. Rust remains unchanged.

**Tech Stack:** Go 1.26.0 standard library; no frontend, new dependencies, or tool downloads.

**Spec:** docs/superpowers/specs/2026-10-11-go-migration-design.md

## Global Constraints

- M1 is a read-only tool for synthetic evaluation, not a production converter replacement. No `convert`, output-file flag, password prompt, recovery writer, desktop code, or network access.
- Module `github.com/akvartz/Bitwarden21Password`; Go floor `1.26.0`; standard library only. Keep Rust unchanged. Build the Go binary as `pwmigrate-go` during coexistence.
- Limits: 32 MiB bytes, 50,000 records, JSON depth 64, 1,000,000 total source fields, 1,024 CSV columns, and 250,000 JSON containers.
- Preserve exact values and unknown data; keep duplicates; never reinterpret legacy notes markers.
- Reports/errors contain only fixed codes, counts, safe schema labels, and numeric locations. No source values, arbitrary field names, input paths, raw parser errors, or source-derived hashes.
- All checks use `GOTOOLCHAIN=local GOPROXY=off`; use approved scratch caches where sandbox requires. No installs, live vaults, or provider account actions.
- Main owns docs, integration, and Git. Workers own only assigned files and preserve others' edits. Native scoped escalation remains necessary when a project-scope hook rejects an authorized write.

## Review Focus

- CRLF inside quoted passwords/notes must survive exactly, despite encoding/csv newline normalization (Task 1).
- Unicode and duplicate JSON keys, including escaped spelling collisions, must not be silently replaced/merged (Task 1).
- Sparse/malformed records and large field counts must fail safely before producing a partial inventory or oversized plan (Task 1).
- Secret-looking filenames, option values, custom names, and malformed payloads must not leak in any stdout/stderr path (Tasks 1 and 2).
- Non-regular files, over-limit reads, and output-writer failures must not hang, truncate silently, or return success (Task 2).

## Interfaces frozen for M1

The package name is migration; its types are intentionally internal to this repo.

```go
type Format string
const ChromeCSV Format = "chrome-csv"
const BitwardenJSON Format = "bitwarden-json"
const MaxInputBytes = 32 << 20
const MaxRecords = 50000
const MaxJSONDepth = 64
const MaxFields = 1000000
const MaxCSVColumns = 1024
const MaxJSONContainers = 250000
func Parse(data []byte, source Format) (*Document, error)
func (d *Document) Inspect() Inventory
func (d *Document) Plan(target Format, selection []int) (Plan, error)

type SafeError struct { Code string; Record, Column int }
func (e *SafeError) Error() string
```

Document stores only unexported fields, owns a copied source snapshot, and never appears in report serialization. Parse empty source to autodetect. nil selection means all; a non-nil empty selection is invalid. Reports returned to callers must not permit later mutation of document state.

Inventory fields and JSON keys: `Format Format`/format, `Records int`/records, `Fields int`/fields (record fields), `MetadataFields int`/metadata_fields, `Kinds map[string]int`/kinds, `DuplicateGroups [][]int`/duplicate_groups, `DuplicateDetection string`/duplicate_detection, `Caveats []string`/caveats. Fixed kind keys: login, secure_note, card, identity, ssh_key, unknown. Chrome metadata fields count zero. Header labels are schema metadata retained in snapshot, not separate cells.

Plan fields/keys: `Source Format`/source, `Target Format`/target, `State string`/state, `TotalRecords int`/total_records, `SelectedRecords int`/selected_records, `ExcludedRecords int`/excluded_records, `Fields []FieldDisposition`/fields, `DuplicateGroups [][]int`/duplicate_groups, `OutputEmitted bool`/output_emitted, `DestinationImportVerified bool`/destination_import_verified, `Caveats []string`/caveats.

FieldDisposition fields/keys: `Record int`/record, `Field int`/field, `Disposition string`/disposition, `TargetField string`/target_field, `Concealed bool`/concealed. Known target labels: name -> name; url -> login.uris[0].uri; username -> login.username; password -> login.password; note -> notes. Unknown columns -> fields, disposition relocated, concealed true. Known columns -> native. Report source-column order for each selected record and source-record order regardless of selection order. Duplicate groups include only selected records for plans, and only groups of at least two.

Safe codes include unknown_format, unsupported_encrypted, unsupported_route, invalid_utf8, invalid_json, duplicate_json_key, invalid_csv, duplicate_header, empty_header, missing_header, uneven_row, invalid_item, invalid_selection, input_limit, record_limit, field_limit, depth_limit, column_limit, container_limit. Optional numeric positions never include source text. User-format strings are not echoed.

### Task 1: strict inventory and complete read-only planning

**Owner:** one coder; main integrates. Do not delegate further or commit.

**Files:**
- Create: go.mod
- Create: internal/migration/document.go, errors.go, chrome.go, bitwarden.go, report.go, plan.go
- Tests: internal/migration/chrome_test.go, bitwarden_test.go, plan_test.go, fuzz_test.go

**Consumes:** synthetic byte slices and the frozen API above.
**Produces:** Parse/Inspect/Plan with immutable private source data and redacted DTOs.

- [x] Write behavioral tests first. Record a meaningful RED result with stub API where necessary; failure must be missing behavior, not a malformed test.
- [x] Chrome tests: literal leading/trailing spaces, whitespace-only/empty passwords, UTF-8, literal backslash-n, embedded CRLF and LF, trailing empty cells, old extras marker notes, unknown custom names/values, BOM and CRLF headers. Verify exact retained internal values against hand-written expectations.
- [x] Reject duplicate/empty normalized headers, missing required name/url/username/password, short/long rows, malformed quoting, blank logical rows, invalid UTF-8, over-limit bytes/records/columns/fields. Header-only CSV is a valid empty export. A final record terminator is not a blank logical row.
- [x] Bitwarden tests: validate encrypted:false + items array, integer item type/string name, login object/null, username/password/totp string/null when present. Retain unknown root/item fields and types, nulls/empties, identities/SSH/passkey payloads, exact source snapshot, and integer precision. Count scalar leaves/empty containers, separating root metadata from item fields. Empty items list is zero records, not one record field.
- [x] Reject duplicate keys at all levels (including decoded-key collisions), invalid UTF-8, malformed/trailing JSON, nested depth >64, record/field limits, invalid item shapes, and encrypted inputs. Parse generic numbers with json.Number or raw tokens; do not round through float64. Include unpaired UTF-16 escape rejection or exact retention without replacement; tests must prove no credential replacement.
- [x] Planning tests: one row with six columns gives five native + one relocated concealed outcome; all fields accounted once. Two identical name/url/username records with different passwords remain two records and one duplicate group. Selection [3,1] reports records 1 then 3; reject zero/negative/out-of-range/repeated/explicit-empty selection. Mutating returned report slices/maps or caller input cannot mutate later output. Unsupported routes fail with safe code.
- [x] Redaction tests marshal every public DTO and exercise every relevant error using distinctive synthetic sentinels in values, custom names, invalid type strings, and duplicate keys. None appears in output; no fingerprints. Planning always states planned/not emitted/not import verified.
- [x] Implement the smallest standard-library solution. For exact CSV newlines, choose a bounded parser strategy that preserves raw cell data; do not normalize source bytes silently. Protect empty-row detection that encoding/csv normally skips.
- [x] Add parser fuzz entrypoints seeded with the above independent fixtures; assert no panic and no non-SafeError input failures. Use ordinary unit assertions for preservation, not tautological self-roundtrips.
- [x] Run focused tests, then `go test ./internal/migration` and gofmt on owned Go files. Report test counts, RED/GREEN commands/results, and actual concerns in the task report. Do not claim provider validation.
- [x] Adversarial refinement: bound all JSON objects/arrays before allocation at MaxJSONContainers without changing leaf-field counts. Test below/at/over budget and compact nested forests; no partial document.
- [x] Main obtains task review for spec compliance and code quality, resolves material issues with the original worker, then stages explicit owned files and commits `feat(core): add strict export inventory and migration planning`.

### Task 2: safe CLI and user-facing evidence boundaries

**Owner:** fresh coder after Task 1 review; main integrates. Do not delegate further or commit.

**Files:**
- Create: cmd/pwmigrate/main.go
- Create: internal/cli/run.go, run_test.go, process_test.go, open_unix.go, open_windows.go, open_unix_test.go
- Modify: README.md (add clear Go M1 section above legacy documentation)
- Modify: .gitignore (ignore /pwmigrate-go and /pwmigrate-go.exe only if needed)

**Consumes:** Task 1 Parse/Inspect/Plan and frozen report DTOs/constants.
**Produces:** `func Run(args []string, stdout, stderr io.Writer) int` and the CLI described in the spec.

- [x] Write RED CLI tests before implementation for inspect/plan/formats/help, required flags, unsupported commands/formats, explicit empty selection, malformed input, file failures, and redacted option/path errors. Standard flag package diagnostics must not echo raw tokens; discard them and render safe codes.
- [x] Tests use temporary synthetic files. Verify header-only empty exports, selected record counts, duplicate retention, JSON field outcomes/evidence flags, and human summaries without credential values/custom names/file paths. Reject positional leftovers and irrelevant flags; missing --to is usage error.
- [x] Test actual bytes-read limit even if stat size is small or changes, non-regular input rejection without blocking on FIFOs, invalid selection syntax, input close errors when testable, and stdout/stderr writer failures. All errors have the specified exit class; never return success if a report write fails.
- [x] Implement regular-file loading with a nonblocking Unix open and opened-handle validation (a pre-open stat alone races with FIFO replacement); add deterministic FIFO/replacement coverage. Put OS-specific helpers in the assigned files, document Windows native-validation gaps, and use bounded reads (limit+1) with safe errors. No output paths, hidden writes, network, or subprocess fallback. Keep main to process signal setup, Run, and os.Exit; handle Unix SIGPIPE at the executable boundary so closed standard streams return I/O exit 1.
- [x] Add actual binary subprocess tests (build into t.TempDir with local toolchain) for exit codes, closed stdout/stderr pipes returning exit 1, and absence of mutations to source/sibling files on success/failure. Fixtures and assertions are independent of report-building helpers.
- [x] Update README with commands, supported M1 scope, plaintext source handling, explicit no conversion/encryption/UI yet, and links to design/plan/status. Clearly separate the legacy Rust description and unverified preservation claims from Go capability. Do not claim all 14 formats work in Go.
- [x] Run focused CLI tests, `go test ./...`, `go vet ./...`, and gofmt. Record RED/GREEN evidence and substantive gaps.
- [x] Main obtains task review, fixes/reviews material findings, stages explicit paths, and commits `feat(cli): expose safe export inspection and planning`.

## Integration and milestone gate

Main owns these steps and docs/agentic/go-migration-status.md.

- [x] Review plan/spec consistency before dispatch. Record task/interface ownership and any decisions in the scoped SDD ledger.
- [x] Run `go test -race ./...` and bounded fuzzing: each fuzz target for 10 seconds with a bounded worker count. Record exact commands/results, not only 'all passed'.
- [x] Cross-compile cmd/pwmigrate with CGO_ENABLED=0 for linux/amd64, windows/amd64, darwin/amd64, darwin/arm64 into an approved scratch directory. This is not native OS testing.
- [x] Inspect owned diffs, gofmt, go vet and whole suite results. Rust tests remain unavailable; unchanged Rust is not silently counted as checked.
- [x] Fresh whole-branch reviewer and separate adversarial reviewer examine actual changes against the baseline. Resolve concrete blockers and re-review material fixes.
- [x] Update durable ledger with delivered behavior, actual evidence, reviewed head, limitations, and next ready M2 task. Preserve future gates.
- [ ] Commit final evidence/docs, inspect git show --stat and clean status, push feature branch, open and attach PR using exact body file. Read CI/review state for that head. Do not merge this security-sensitive implementation.
- [ ] Complete the bounded native goal only after its design/plan/M1/PR requirements are met. Report remaining product milestones and any provisioning/native-provider checks separately.

## Preflight consistency record

Task 1 owns shared API/core; Task 2 consumes it without redesign. Only main owns docs/status and Git; README ownership is Task 2. The review-focus cases map to named tests above. M2-M6 remain roadmap entries, not incomplete M1 tasks. User waived routine approval; continue through the loop without new design sign-offs.
