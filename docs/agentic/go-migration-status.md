# Go migration status

The experimental M2 Linux protected-export slice is merged via [PR #3](https://github.com/akvartz/Bitwarden21Password/pull/3) at d4e1dc219a3c50fb3de36608122c0f894c84cf9a. Full M2 provider/platform qualification remains incomplete. The user selected CLI-only delivery; the desktop/Wails milestone is retired. The current route is Chrome CSV to unencrypted Bitwarden JSON, intended for synthetic evaluation.

Designs: [overall migration](../superpowers/specs/2026-10-11-go-migration-design.md) and [protected export](../superpowers/specs/2026-10-11-protected-export.md). Plans: [M1](../superpowers/plans/2026-10-11-go-foundation.md) and [M2 slice](../superpowers/plans/2026-10-11-protected-export.md).

## Delivered behavior

- M1 provides strict Chrome CSV and unencrypted Bitwarden JSON inspection, field accounting, source-order selection, duplicate flags and fixed redacted reports. It is published as [PR #2](https://github.com/akvartz/Bitwarden21Password/pull/2), now merged into main at 62bd064f2582b4569eaf7a78f66ec610e41c692d. PR #3 was subsequently merged.
- M2 adds `convert`: an immutable source snapshot, random per-job review ID, exact issue acknowledgment and one-shot execution. Copied handles, report mutation, stale approvals and concurrent commits cannot authorize a second write.
- Generated JSON preserves exact selected credentials, notes, original custom labels/values and duplicate multiplicity. Unknown columns become concealed custom fields with explicit review. Known downstream importer changes and rejection risks require acknowledgment.
- Linux output uses a new private 0700 job directory, exclusive 0600 partial file, same-handle readback, checked sync/close and non-replacing publication. Failures can leave private artifacts; no automatic retry or recursive cleanup occurs.
- A completion receipt proves local value validation and file readback only. DestinationImportVerified remains false. Require a successful receipt and exit 0; cancellation or report failure can happen after the output file or completion event exists.
- macOS and Windows retain read-only commands and fail closed for writes. Legacy Rust source, tests, fixtures and manifest contents are unchanged; the delivery milestone relocates them together into legacy/rust. There is no runtime network, telemetry, account access, source deletion, encrypted input unlocking, recovery writer or desktop UI.

## M2 verification (historical evidence)

Installed toolchain: Go 1.26.0 linux/amd64. Commands used GOTOOLCHAIN=local GOPROXY=off and approved build/module caches. No tools or dependencies were installed.

- Behavioral RED preceded implementation and review fixes. Tests cover exact literal values, notes absent versus empty, source-order selection, duplicates, original custom headers, field accounting and redaction.
- Approval tests cover missing/extra/duplicate issue IDs, cross-job review IDs, mutation, copied handles, replay, concurrent commit and terminal failures. Output byte/JSON-container budgets reject amplification before filesystem writes.
- Native Linux filesystem tests cover effective permissions, collisions, existing source/sibling/link preservation, anchored directory renames and cancellation. Injected write, short-write, sync, readback, close, link and removal failures exercise empty-result behavior. Injection is separate from native filesystem evidence. A foreign-owner negative fixture requires chown privileges and was skipped on this non-root host.
- Actual binary tests cover successful/rejected conversions, EOF/read boundaries, closed pipes, SIGINT/SIGTERM during approval and read-only signal termination. Synthetic source/sibling contents, size, mode and mtime are checked; reading may change atime.
- Final integrated `go test -race ./...` passed after both CLI signal fixes (CLI 4.316s; unchanged migration/protectedoutput results cached). `go vet ./...` passed. Package tests and focused RED/GREEN checks also passed. Formatting and Git whitespace checks are clean. The later human formats wording correction passed its focused RED/GREEN check, independent focused test and full CLI package test (0.779s); unchanged race/vet/cross-build checks were not repeated for that text-only correction.
- Final CGO_ENABLED=0 `go build -trimpath ./cmd/pwmigrate` passed for linux/amd64, windows/amd64, darwin/amd64 and darwin/arm64. These are compilation checks, not native non-Linux tests or release artifacts.

## Review and implementation decisions

The writer and migration engine have independent spec/quality review and adversarial review with no remaining findings. The CLI's valid-final-newline-plus-EOF case was fixed and independently re-reviewed. Two adversarial findings were reproduced and fixed: cancellation inside completion reporting must return failure, and conversion signal handling must not swallow read-only command signals. Independent and adversarial scoped re-reviews passed with no remaining findings. Fresh whole-branch review of e99b08f through e41b1e6 found no blocking or should-fix issues. Its one wording nit (formats still described M1 as read-only) was corrected in a3cf1e6 and independently re-reviewed. There are no remaining review findings in this slice.

The bounded implementation deliberately uses in-memory approval; a durable automation protocol is later work. Linux alone enables output until platform privacy evidence exists. Failed jobs retain private artifacts to avoid unsafe cleanup. A source-independent random review ID binds approval without exposing a source fingerprint.

Native worktree creation could not target this repository from the chat workspace. Work therefore uses the initially clean selected checkout, feature branch feat/protected-chrome-export, and disjoint worker ownership. Main owns Git, documentation and integration. Resume from the ignored .superpowers/sdd/2026-10-11-protected-export/progress.md ledger; do not redispatch completed implementation tasks.

## M1/M2 publication history

Local M2 starts at M1 commit e99b08fe10860d8afb5611ed2c0273e1d0e9d570. Writer commit: 374ca61. Engine commit: fa4714a. CLI commit: bf90906. Initial reviewed source commit: a3cf1e6fc5d594d651032d3894bb48c0e3f2ce8c. Subsequent review corrections are recorded below. The security-sensitive PR was left for the user and has since been merged by the user.

M1 was published through the authenticated GitHub Git-data connector after shell SSH/HTTPS transport failed on this host. Its remote head cd90d9fb881d6ac59e2c581787705ca4f872df40 and local M1 head have the same tree ffde1f58ecf629a72dcda4f1da26c55427831242, but different commit identities. Preserve both histories. M2 publication rechecked live PR #2 and used its unchanged branch as the base. Initial remote M2 commit 1348115fda41e1bc5c816e853862ae11ae9a3655 has exactly the reviewed local source tree 9e3993c36ef51ec424a1febc5f4cf37d3faf3124. The documentation closeout uses the same exact-tree comparison and a non-forced update with an expected-head lease. PR #3 is attached to the task. Before future publication, inspect the live PR head and preserve the mapping between local and remote histories. Do not force-push, rewrite history or change system SSH configuration.

At initial M2 publication, exact-head queries returned no commit statuses, pull-request workflow runs or submitted GitHub reviews. These missing results are not a CI pass or GitHub approval. Recheck the final documentation head after updating the branch; local independent and adversarial reviews are distinct from GitHub reviews. The local ignored task ledger records final publication SHAs and checks.

## Remaining qualification and next work

1. Run the [synthetic Bitwarden import checklist](bitwarden-import-qualification.md) manually in a disposable test vault. Record client/server version and exact route. Source-code inspection and local JSON validation cannot replace this gate.
2. Design and independently review Windows DACL and macOS ACL/volume handling, then exercise native Windows VM and macOS tests before enabling output there.
3. Continue the overall migration plan with qualified profiles, destination re-export comparison, recovery/encryption and CLI usability/automation. Maintained crypto dependencies require user provisioning; do not install them or substitute custom cryptography.

Native Windows/macOS behavior, actual provider acceptance, passkey transfer, encryption interoperability, signing and release readiness remain unverified. Rust/Cargo is unavailable, so legacy tests were not run. The agent created no releases, tags or production deployments. The user subsequently merged PRs #2 and #3.

## PR #3 permission-test feedback

Review comment [4244149977](https://github.com/akvartz/Bitwarden21Password/pull/3#discussion_r4244149977) identified a test-only portability issue: UID0 can create directories under a 0500 parent. TestConvertUnwritableParentFailsWithoutCompletion now skips for effective UID0 before creating fixtures. Unprivileged execution and deterministic protectedoutput mkdir/open fault tests retain failure coverage; production code is unchanged. Independent scoped review passed. The existing CLI test passed before the correction at UID1000; no native-root failing run is claimed. Full go test ./... and the focused injected-mkdir test passed after the correction on the same unprivileged host. Native UID0 execution remains unverified.

## CLI delivery milestone (in progress)

Design: [CLI delivery](../superpowers/specs/2026-10-11-cli-delivery.md). Plan: [bounded execution loop](../superpowers/plans/2026-10-11-cli-delivery.md). Branch: chore/cli-delivery. Canonical base: d4e1dc219a3c50fb3de36608122c0f894c84cf9a.

The authenticated connector confirmed PRs #2/#3 were merged. Terminal HTTPS Git still cannot resolve GitHub. Seven exact canonical commit objects, including both signed merge payloads, were reconstructed from GitHub's Git-data responses and verified by Git object SHA before import. Every referenced tree/blob already existed locally; the merged tree equals the reviewed local M2 tree. The new feature branch fast-forwarded to canonical main; older local feature branches are preserved. This is object-identity verification, not independent cryptographic signature verification.

Accepted direction: CLI-only on Linux, macOS and Windows. No GUI was implemented. Replace Wails work with guided terminal usability, explicit automation approval and destination comparison. Relocate Rust without changing file contents; add version metadata, six-target packaging, native CI and a manual existing-tag draft release workflow. Actual release/tag publication remains a maintainer action. Security-sensitive workflow changes remain unmerged for user review.

Implementation is complete: version/--version and JSON metadata, stdlib six-target archive tooling, pinned native CI and separate draft-release publication permissions. All 28 relocated Rust files match their original Git blob IDs. The CLI release path packages only the executable, LICENSE, README and build metadata, plus a manifest/checksum pair outside each archive.

Local verification uses existing Go 1.26.0 linux/amd64 with GOTOOLCHAIN=local GOPROXY=off and scratch caches. The uncached full suite and full race suite passed; full go vet, owned Go formatting and whitespace checks passed. Behavioral RED/GREEN covered version output, real linker-stamped processes, archive/checksum contents, stale/dirty/ignored/assume-unchanged sources and no-overwrite failures. The Python release guards passed 10 tests after initial rejection tests failed. Installed PyYAML parsed both workflows and Bash checked all 12 shell blocks; this is not GitHub workflow-schema validation.

Independent review of the current files against canonical base passed. Adversarial workflow review and extra malformed-artifact probes passed. Packager review reproduced Git replacement objects bypassing source identity; a failing regression preceded disabling replacement objects on all verification commands. Independent and adversarial scoped re-reviews confirmed the fix. The post-fix full uncached Go suite and focused race/vet checks passed. Real packaging from clean commit 76bdecfdebc84577764d96d93afb0f5cbfd3de1a passed with test version v0.0.0-local.1. All six archive member sets, target executable headers (ELF/Mach-O/PE), embedded metadata, sizes, hashes and seven checksum entries were verified. The packaged Linux amd64 executable passed version/help/formats smoke checks. These local artifacts use Go 1.26.0 and are not published releases. Native hosted CI and PR publication evidence remain pending. No actual release or tag has been created.
