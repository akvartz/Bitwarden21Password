# Protected Chrome Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Deliver the reviewed experimental M2 Linux protected-output slice and an unmerged feature PR.

**Architecture:** An immutable in-memory migration Job owns review and one-shot approval. A separate stdlib protectedoutput package creates private exclusive files and verifies saved bytes; a thin CLI drives review and commit.

**Tech Stack:** Installed Go 1.26.0 standard library only.

**Spec:** docs/superpowers/specs/2026-10-11-protected-export.md and docs/superpowers/specs/2026-10-11-go-migration-design.md.

## Global Constraints

- Preserve exact credentials, unknown fields/types, and duplicates. Never silently normalize, merge, drop, or reinterpret data.
- Synthetic tests only. No real vaults/secret files, raw parser excerpts, sensitive labels/values, or source-derived fingerprints in logs/reports/commits.
- No runtime network, telemetry, remote UI assets, or automatic source deletion.
- No new tools/dependencies installed. Use GOTOOLCHAIN=local GOPROXY=off and approved scratch caches.
- Preserve legacy Rust. Windows/macOS writes fail closed; macOS cross-builds are not native tests; local JSON validation is not provider acceptance.
- Main owns Git/docs/integration; workers own explicitly assigned files, do not spawn agents or commit, and preserve other workers' changes.
- Security-sensitive PRs remain unmerged; releases/tags/production remain user actions.

## Review Focus

- Same-looking credentials with spaces, CRLF, empty values or Unicode must survive exactly (Task 2 literal-value tests).
- Public DTO mutation, reused approval or simultaneous commits cannot redirect or repeat a write (Task 2 job tests).
- Existing files/links and renamed parent/job paths cannot cause clobber or source deletion (Task 1 rooted filesystem tests).
- Readback, sync, close, link or cancellation failures cannot produce a success receipt (Tasks 1 and 2 fault tests).
- Broken stdout or approval input must not silently authorize conversion; reports never expose source labels/values/paths (Task 3 process tests).

## Task 1: Private no-clobber output

**Files:** Create internal/protectedoutput/output.go, output_linux.go, output_unsupported.go, output_test.go, output_linux_test.go. Additional focused test files in that package allowed.

**Interfaces:** Write(ctx context.Context,parent string,payload []byte) (Result,error). Result {JobDirectory string; FileName string}. Error {Code string}, Error() allowlists fixed codes: output_platform, output_parent, output_create, output_write, output_sync, output_readback, output_close, output_publish, output_cancelled. Supported() bool is read-only and lets callers fail before prompting on unsupported platforms. FileName is bitwarden.json. No migration-package dependency.

- [x] Write compiling stubs and behavioral tests: real temp parent creates 0700 child/0600 file with exact payload; existing source/sibling/hardlink contents unchanged; collision refuses reuse; insecure parent rejected; canceled context writes nothing; fault injection returns no result for short write, write/readback/sync/close/link failures; cancellation before/after publication yields no success; rooted rename does not escape or clobber. Assert no recursive cleanup and no path/raw error leakage.
- [x] Run focused tests and record expected behavioral RED in task report.
- [x] Implement opened-root parent/ownership/mode validation, crypto/rand job name, exclusive partial, same-handle write-sync-readback-close, exclusive Link publication, owned-partial removal, checked directory sync/close. Leave private artifacts on failure. Keep narrow package-private test seams for unavoidable fault injection.
- [x] Run gofmt, package tests/race and full go test ./... once; report actual output. Cross-build unsupported platform stub with shared packages later.
- [x] Main creates supplied diff package; independent task review covers spec and quality. Fix/review material findings, then main stages explicit paths and commits.

## Task 2: Exact conversion and one-shot approval

**Files:** Modify internal/migration/document.go, chrome.go, errors.go; create export.go, job.go and corresponding tests. Existing report.go/plan.go/test files may change only for compatible shared DTO/helpers.

**Interfaces:** Consume protectedoutput interfaces above. Produce (d *Document) NewJob(target Format,selection []int,parent string) (*Job,error); (*Job) Review() Review; Approve(reviewID string,ids []string) error; Commit(ctx context.Context) (Receipt,error); State() string. Review {Plan Plan; Profile,ReviewID string; Issues []Issue}; Issue {ID,Code string; Column,Records int}; Receipt {Plan Plan; Profile,JobDirectory,FileName string}. JSON names snake_case. Profile chrome-to-bitwarden-json-v1. Exact output limit32MiB. Errors extend allowlist with output codes above plus approval_required, approval_invalid, invalid_state, output_limit, output_validation.

- [x] Write behavioral RED tests using independent literal JSON expectations: exact all known cells and original unknown labels, notes absent vs empty, duplicate multiplicity/source-order selection, full field accounting, copied input/selection/review mutations cannot affect job; copied Job handles share one approval state and cannot replay; relative parent resolved at construction survives later chdir; output expansion and strict-parser budget failures happen before filesystem output.
- [x] Write approval/state RED tests: missing/extra/duplicate issue IDs fail; another job's approval cannot authorize this one; preapproval commit fails; approve/commit replay and concurrent commit have exactly one winner; context/fault failures terminal with empty receipt; reports include only fixed codes/counts/ordinals/generated output names.
- [x] Implement original-header retention; bounded JSON encoding; independent decoded structure/source-cell comparison; immutable private job handle to shared private pointer state with mutex-protected transition and defensive DTO copies. Always require experimental-import, selected unknown-column relocation issues, and the five conditional per-column provider issues, sampled provider-import-rejection, and >7,000-record provider-large-export issues from the spec. Blank-name/notes detection must match ECMAScript trim including U+FEFF; empty credential/URL detection is exact-empty.
- [x] Run gofmt, focused/race tests and full go test ./... once. Record RED/GREEN evidence without raw data dumps.
- [x] Main supplies diff and report to independent task reviewer. Fix/re-review, stage explicit task paths and commit after Task 1 integration.

## Task 3: CLI review and execution

**Files:** Modify internal/cli/run.go, cmd/pwmigrate/main.go; create internal/cli/convert.go, convert_test.go, convert_process_test.go. Existing CLI process/help tests updated for compatible behavior only.

**Interfaces:** Consume Job APIs above. Produce RunContext(ctx context.Context,args []string,stdin io.Reader,stdout,stderr io.Writer) int. Preserve existing Run signature and injectable input opener tests. New convert exact flags/response/exit codes match spec. Main provides signal context while retaining SIGPIPE handling.

- [x] Write RED tests for no approval/EOF/malformed/oversized/readerror/cancellation/closed review pipe: no export; exact issue acceptance yields one private output and safe completion; select/unknown labels/duplicates preserved; broken final receipt returns1 without second write; unsupported Windows/macOS returns output_platform before output; actual binary source/siblings remain unchanged.
- [x] Implement convert parsing/review, bounded approval line, safe typed JSON events and readable human explanations, Job approval/commit, exit-code mapping and signal cancellation. Never print user-supplied tokens, arbitrary paths or values.
- [x] Run gofmt, focused real-binary tests, race/full suite once and vet. Cross-build Linuxamd64, Windowsamd64, Darwinamd64/arm64 with CGO_ENABLED=0 into approved scratch.
- [x] Independent task review and separate adversarial review cover current files/diff and meaningful tests; fix and re-review findings. Main integrates explicit files.

## Task 4: Evidence, review and publication

**Files:** Main owns README.md, docs/agentic/go-migration-status.md, this plan/spec, and a concise synthetic provider-acceptance checklist under docs/agentic.

- [x] Update capabilities/examples/limits/approval instructions and failed-job behavior; explicitly distinguish native Linux, cross-builds, provider acceptance and pending Windows DACL work. Keep legacy section intact.
- [ ] Verify full tests/race/vet and whitespace on final source; do not repeat successful checks without source changes or new concerns. Prepare whole-branch supplied diff against e99b08fe10860d8afb5611ed2c0273e1d0e9d570 and fresh independent final review. Resolve/re-review material findings.
- [ ] Commit only reviewed owned paths with conventional commits. Publish feature branch through available authenticated transport, compare exact remote/local tree if Git-data API is needed, and create stacked PR against unmerged feat/go-migration-foundation. Inspect live PR2 first; if already merged use current appropriate base. Attach PR, inspect exact-head CI/reviews, leave unmerged.
- [ ] Record final commit/tree/PR and gaps in durable status; complete only this bounded goal. Keep private ledger while PR remains in active review.
