# Go migration status

The experimental M2 Linux protected-export slice is implemented. Full M2 provider/platform qualification and the desktop converter remain incomplete. The current route is Chrome CSV to unencrypted Bitwarden JSON, intended for synthetic evaluation.

Designs: [overall migration](../superpowers/specs/2026-10-11-go-migration-design.md) and [protected export](../superpowers/specs/2026-10-11-protected-export.md). Plans: [M1](../superpowers/plans/2026-10-11-go-foundation.md) and [M2 slice](../superpowers/plans/2026-10-11-protected-export.md).

## Delivered behavior

- M1 provides strict Chrome CSV and unencrypted Bitwarden JSON inspection, field accounting, source-order selection, duplicate flags and fixed redacted reports. It is published as [PR #2](https://github.com/akvartz/Bitwarden21Password/pull/2), currently open and unmerged.
- M2 adds `convert`: an immutable source snapshot, random per-job review ID, exact issue acknowledgment and one-shot execution. Copied handles, report mutation, stale approvals and concurrent commits cannot authorize a second write.
- Generated JSON preserves exact selected credentials, notes, original custom labels/values and duplicate multiplicity. Unknown columns become concealed custom fields with explicit review. Known downstream importer changes and rejection risks require acknowledgment.
- Linux output uses a new private 0700 job directory, exclusive 0600 partial file, same-handle readback, checked sync/close and non-replacing publication. Failures can leave private artifacts; no automatic retry or recursive cleanup occurs.
- A completion receipt proves local value validation and file readback only. DestinationImportVerified remains false. Require a successful receipt and exit 0; cancellation or report failure can happen after the output file or completion event exists.
- macOS and Windows retain read-only commands and fail closed for writes. Legacy Rust source, tests, fixtures and manifests are unchanged. There is no runtime network, telemetry, account access, source deletion, encrypted input unlocking, recovery writer or desktop UI.

## Verification

Installed toolchain: Go 1.26.0 linux/amd64. Commands used GOTOOLCHAIN=local GOPROXY=off and approved build/module caches. No tools or dependencies were installed.

- Behavioral RED preceded implementation and review fixes. Tests cover exact literal values, notes absent versus empty, source-order selection, duplicates, original custom headers, field accounting and redaction.
- Approval tests cover missing/extra/duplicate issue IDs, cross-job review IDs, mutation, copied handles, replay, concurrent commit and terminal failures. Output byte/JSON-container budgets reject amplification before filesystem writes.
- Native Linux filesystem tests cover effective permissions, collisions, existing source/sibling/link preservation, anchored directory renames and cancellation. Injected write, short-write, sync, readback, close, link and removal failures exercise empty-result behavior. Injection is separate from native filesystem evidence. A foreign-owner negative fixture requires chown privileges and was skipped on this non-root host.
- Actual binary tests cover successful/rejected conversions, EOF/read boundaries, closed pipes, SIGINT/SIGTERM during approval and read-only signal termination. Synthetic source/sibling contents, size, mode and mtime are checked; reading may change atime.
- Final integrated `go test -race ./...` passed after both CLI signal fixes (CLI 4.316s; unchanged migration/protectedoutput results cached). `go vet ./...` passed. Package tests and focused RED/GREEN checks also passed. Formatting and Git whitespace checks are clean.
- Final CGO_ENABLED=0 `go build -trimpath ./cmd/pwmigrate` passed for linux/amd64, windows/amd64, darwin/amd64 and darwin/arm64. These are compilation checks, not native non-Linux tests or release artifacts.

## Review and implementation decisions

The writer and migration engine have independent spec/quality review and adversarial review with no remaining findings. The CLI's valid-final-newline-plus-EOF case was fixed and independently re-reviewed. Two adversarial findings were reproduced and fixed: cancellation inside completion reporting must return failure, and conversion signal handling must not swallow read-only command signals. Independent and adversarial scoped re-reviews passed with no remaining findings. Final whole-branch review is pending.

The bounded implementation deliberately uses in-memory approval; a durable automation protocol is later work. Linux alone enables output until platform privacy evidence exists. Failed jobs retain private artifacts to avoid unsafe cleanup. A source-independent random review ID binds approval without exposing a source fingerprint.

Native worktree creation could not target this repository from the chat workspace. Work therefore uses the initially clean selected checkout, feature branch feat/protected-chrome-export, and disjoint worker ownership. Main owns Git, documentation and integration. Resume from the ignored .superpowers/sdd/2026-10-11-protected-export/progress.md ledger; do not redispatch completed implementation tasks.

## Publication

Local M2 starts at M1 commit e99b08fe10860d8afb5611ed2c0273e1d0e9d570. Writer commit: 374ca61. Engine commit: fa4714a. CLI commit: bf90906. Documentation integration, final review and M2 PR publication are pending. The security-sensitive PR must remain unmerged.

M1 was published through the authenticated GitHub Git-data connector after shell SSH/HTTPS transport failed on this host. Its remote head cd90d9fb881d6ac59e2c581787705ca4f872df40 and local M1 head have the same tree ffde1f58ecf629a72dcda4f1da26c55427831242, but different commit identities. Preserve both histories. M2 publication must recheck live PR #2, use its branch as the base while unmerged, and compare the exact reviewed local tree with the API-created remote tree before moving a ref. Do not force-push, rewrite history or change system SSH configuration.

At M1 publication no commit statuses, pull-request workflow runs or submitted GitHub reviews were returned. This was not a CI pass or GitHub approval. Check M2's exact published head separately; local independent reviews are distinct from GitHub reviews.

## Remaining qualification and next work

1. Run the [synthetic Bitwarden import checklist](bitwarden-import-qualification.md) manually in a disposable test vault. Record client/server version and exact route. Source-code inspection and local JSON validation cannot replace this gate.
2. Design and independently review Windows DACL and macOS ACL/volume handling, then exercise native Windows VM and macOS tests before enabling output there.
3. Continue the overall migration plan with qualified profiles, destination re-export comparison, recovery/encryption and a desktop shell. Wails and maintained crypto dependencies require user provisioning; do not install them or substitute custom cryptography.

Native Windows/macOS behavior, actual provider acceptance, passkey transfer, encryption interoperability, signing and release readiness remain unverified. Rust/Cargo is unavailable, so legacy tests were not run. No releases, tags, merge or production deployment occurred.
