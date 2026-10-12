# Next session: finish pwmigrate 1.0.0

Prepared 2026-10-11, America/New_York. Workspace: `/home/akvartz/Dev/Bitwarden21Password`.

## Objective and working mode

**Build the finished, releasable 1.0.0 Go CLI described by the accepted product design.** The user explicitly wants a finished product, not another alpha, scaffold, packaging milestone or planning-only session. Green CI and downloadable binaries alone do not satisfy the objective.

Treat the next session as one sustained, autonomous development session. Verify the starting state, make a concrete implementation plan, then execute continuously through implementation, tests, review, fixes, documentation and release-candidate validation. Do not stop after the plan or each small milestone to ask whether to continue. Routine reversible decisions are delegated to the agent. Work in bounded slices while keeping one visible 1.0 acceptance checklist and its remaining gaps. Do not promise completion within one context window; continue across compaction and report any real external blocker honestly.

Use the native goal mechanism when continuing the user's requested goal-driven workflow. Keep the full 1.0 objective visible, with concrete milestone acceptance criteria and a durable progress ledger. Do not invent a token budget or mark the product complete because a smaller delivery goal was completed previously. Actual publication remains a separate user-controlled action.

## Read first

- [Project instructions](../../AGENTS.md) and the user's personal working agreement.
- [Accepted product design and roadmap](../superpowers/specs/2026-10-11-go-migration-design.md).
- [Execution loop](README.md) and [implementation evidence](go-migration-status.md).
- [Current CLI documentation](../../README.md), [release runbook](../releases.md), and [provider acceptance checklist](bitwarden-import-qualification.md).

The old M1/M2 contracts describe earlier slices. Do not mistake their deliberate limitations for the final 1.0 scope. The desktop/Wails direction is superseded: **CLI-only** is settled. Do not reopen that decision or rebuild the completed release infrastructure.

## Verified starting state

| Item | Evidence at handoff |
| --- | --- |
| GitHub main | `7777ae112f787b8d6e1ddbc00b24f0496733501b` |
| Delivery PR | [PR #4](https://github.com/akvartz/Bitwarden21Password/pull/4), merged after the user's explicit approval |
| Merged-main CI | [Run 38200897362](https://github.com/akvartz/Bitwarden21Password/actions/runs/38200897362), all five jobs passed |
| Local branch / HEAD | `chore/cli-delivery` / `4d02bf052715b51110e6ed4b3dc6bdb27d293c41` |
| Shared local/main tree | `ab349fe989b87884970ba44be0ceb16e23ecf890`; identical files, different commit histories |
| Published tags / releases | None; no release workflow dispatch has been run |
| Local working tree | Clean before writing this handoff. This handoff is the only intended new, uncommitted file; preserve it when establishing the next branch. |

PRs #2 and #3 are also merged. The Go implementation currently inspects Chrome CSV and unencrypted Bitwarden JSON, plans Chrome-to-Bitwarden conversion, and performs that experimental conversion on Linux with bound review/approval and protected no-clobber output. **It does not yet implement Bitwarden-to-1Password conversion.** macOS and Windows intentionally reject conversion; their passing tests validate supported read-only/rejection behavior.

Completed work to reuse: exact-field inventory and redacted reports; selected-record accounting and duplicate retention; one-shot approval and Linux private output; version metadata; six Linux/macOS/Windows amd64/arm64 archive builds; manifests/checksums; native three-OS CI, Linux race/root checks; a manually dispatched draft-release workflow. All 28 Rust files were relocated unchanged to `legacy/rust`; Rust is neither a correctness oracle nor a fallback.

Independent and adversarial reviews passed the delivered work, including fixes for Git replacement-object build identity and a Linux-only limit test that initially failed on macOS/Windows. Local tests/race/vet and real archive inspections passed. Current main has fresh hosted evidence. No actual provider import has been qualified; no signing, stable publication or encrypted-format interoperability claim exists.

**Stale notes:** `go-migration-status.md` and the ignored `.superpowers/sdd/2026-10-11-cli-delivery/progress.json` still say PR #4 is unmerged. The release runbook still instructs the reader to first merge the infrastructure PR. Correct these during the next implementation's documentation closeout. The verified merge above supersedes those statements; recheck live state before working.

## Observable 1.0 completion criteria

Use these as the completion checklist, based on the accepted scope. Do not silently narrow it to the existing Chrome route. Record any necessary scope decision explicitly.

- **Useful provider coverage:** direction-by-direction, versioned profiles for Bitwarden, 1Password and Proton Pass in both directions, plus the declared browser-source routes. Prioritize Bitwarden ↔ 1Password. Freeze the exact supported route/item-type matrix before adapter work; do not imply support for all 14 Rust adapters.
- **Actual conversion on Linux, macOS and Windows:** reviewed platform privacy controls, including Windows DACLs and macOS ACL/volume handling, plus native no-clobber, cancellation, failure and permission tests. Cross-compilation and read-only CI are not writer qualification.
- **Auditable preservation:** account for every selected field, preserve exact credentials, duplicates and unfamiliar payloads, and implement the accepted rich-item mappings. Explicitly handle identities, typed custom fields, vault/folder relationships, attachments and passkey metadata. Unrepresentable data must be disclosed, recoverable or blocked; never silently normalize or call recovery retention successful migration. Do not promise universal losslessness or working cross-provider passkeys.
- **Encrypted input and usable recovery:** supported provider formats use maintained implementations with independent vectors, authentication, KDF/resource bounds and tamper/truncation tests. Encrypted recovery includes both writer and reader, documented key handling and demonstrated interoperability. Do not invent crypto to avoid a missing dependency.
- **Finished CLI experience:** discoverable help, guided review, whole-export defaults and optional vault/folder/type/item selection, exact issue acknowledgment, stable safe JSON/exit codes, progress/cancellation and useful errors. Document quoted paths and terminal path drag-and-drop. No blanket --yes approval, GUI, runtime network or account-login integration.
- **Destination comparison and acceptance:** compare supplied re-exports with multiplicity, ambiguous matches and unobservable fields reported honestly. Qualify every claimed destination/profile using synthetic imports on recorded provider versions/platforms. Source review and self-roundtrips do not establish destination acceptance.
- **Complete documentation:** accurate capability matrix, installation and migration walkthroughs, limits, approval, recovery, troubleshooting and release instructions. Remove obsolete post-merge status. An ordinary user must be able to complete each supported journey from the docs.
- **Stable delivery candidate:** patched/pinned build tools, checked artifacts and native smoke evidence, an exercised release path, and resolved/documented signing and build-provenance work. The existing workflow always creates draft prereleases and sets latest=false; design the deliberate stable-1.0 promotion path. A draft prerelease is not a published 1.0.0.

Keep engineering readiness and actual publication separate. If all engineering/qualification gates pass but a user-owned release action remains, report a ready candidate and the exact remaining action; do not say 1.0.0 has been released.

## Parallel, agentic execution

The main agent owns the acceptance checklist, architecture/shared contracts, task decomposition, Git integration and final verification. Use available subagents proactively for independent work; give each a complete brief, exact files/modules, API contracts, constraints and expected proof. Tell every worker that others share the repository and their changes must be preserved.

Freeze shared inventory/profile/approval interfaces before parallel edits. Good parallel lanes are provider adapters, platform output implementations, CLI/comparison work, and independent fixture/qualification research. Assign disjoint ownership; a worker must not rewrite another worker's module or mutate Git. Use worktrees where the tools can target this repository correctly; otherwise use the verified feature checkout with explicit ownership. Serialize shared APIs, staging, commits, publication and integration.

Keep review separate from authorship: use a fresh independent reviewer, and an adversarial reviewer for parsing, crypto, credentials, output, approval and other security-sensitive changes. Reviewers own no source writes. Require behavioral RED before risky changes, fix concrete findings, and re-review material fixes. Do not count a role name, cached test, unsupported-platform skip or missing review as evidence of success.

Run the loop continuously: **brief -> failing behavioral test -> implement -> focused checks -> independent/adversarial review -> fixes/re-review -> integration -> record evidence -> next ready slice**. Scale parallelism to independent work and avoid duplicate research/review seats. Reassign agents to ready work when a lane needs user-provisioned dependencies or manual provider evidence. Do not end the session at the first blocked lane while meaningful independent work remains.

Keep concise commentary and a sanitized project ledger. On compaction, resume the ledger without restarting completed tasks. A real dependency/permission/provider-access blocker needs a precise description and the smallest user action; it must not produce a false completion claim or a bypass.

## Next work, in order

1. **Reconcile the checkout and current evidence.** Read this handoff, inspect status and live GitHub main/CI, preserve the uncommitted handoff and all historical branches, and establish the next feature branch from canonical main. Local `main` is stale at `46f0db7`; do not use it as the implementation base without reconciliation.
2. **Create the 1.0 acceptance matrix and executable work packets, then start implementation in the same session.** Map every criterion above to owned files, prerequisites, tests, native/provider evidence and a completion condition. Reuse existing plans; avoid another broad brainstorming phase.
3. **Prioritize useful conversions.** Complete the Bitwarden ↔ 1Password vertical slice, with bounded archive handling, rich inventory/mapping and independent fixtures as needed. Refresh current primary provider-format documentation before choosing import profiles. Extend to the agreed Proton Pass and browser routes. Never guess attachment ownership or provider behavior.
4. **Advance platform and qualification lanes in parallel.** Implement/review macOS and Windows writers while preparing the existing [Bitwarden import checklist](bitwarden-import-qualification.md) for user-run disposable-vault testing. The checklist is currently explicitly not run. Establish equivalent evidence for newly claimed profiles; keep account interaction user-controlled.
5. **Complete encryption/recovery, selection, automation and comparison**, then close user journeys, documentation and stable-release preparation. Request any indispensable dependency/tool provisioning precisely and continue other lanes. Maintain the 1.0 checklist through each integration; do not substitute an alpha release for unfinished requirements.
6. **Finish with a tested 1.0 candidate and an honest release gate.** Exact-head CI and independent/adversarial reviews must pass. Resolve required native/provider evidence. Prepare the explicit version, source commit, assets, notes and stable-promotion commands for the user's release action. No fabricated approval, provider qualification or publication.

First runnable inspection:

```sh
cd /home/akvartz/Dev/Bitwarden21Password
git status --short --branch
git rev-parse HEAD 'HEAD^{tree}'
cat AGENTS.md docs/agentic/README.md docs/agentic/handoff-1.0.0.md
```

Use existing tools for checks, for example:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE=/tmp/pwmigrate-go-build GOMODCACHE=/tmp/pwmigrate-go-mod go test -count=1 ./...
```

## Boundaries and environment hazards

- The user waived routine implementation approvals and requested autonomous, parallel work toward completion. **The later merge approval applied to PR #4.** It does not approve future risky merges, tags, public releases or production changes. Follow the current project gates and ask only for genuinely required authorization/provisioning.
- Local Go is 1.26.0; hosted CI pins 1.26.9. Do not install or upgrade tools, modules, packages, binaries, containers or models. Required maintained crypto dependencies need user provisioning; continue independent work while waiting. Current implementation uses only the standard library.
- Use synthetic data only. No secret files, real vault fixtures, account credentials, raw parser excerpts, sensitive labels/values or source-derived fingerprints in logs, artifacts, notes or commits. Do not change global configuration or other projects.
- Shell Git HTTPS previously failed DNS; SSH hit a system configuration permission error. The authenticated GitHub connector worked. Recheck ordinary transport once if useful; never change SSH settings or bypass sandbox/hooks. Connector publication created different commit identities with verified identical trees. Preserve both histories; no reset, force-push or history rewriting.
- Prior canonical-object recovery artifacts are under `.superpowers/sdd/2026-10-11-cli-delivery/`. They describe an earlier base and are evidence/examples, not a script to rerun blindly. Any recovery must validate exact object IDs, parents and existing tree contents before append-only import; use native permissions.
- The chat originally lived outside this repository. Use the selected repository path explicitly. Some native worktree/patch tools previously targeted the wrong chat workspace; honor scoped approvals rather than evading a denial with another mechanism.
- The user can test Linux, macOS and a Windows VM. Provider accounts, missing tools, native-only qualification and signing credentials may require their participation. Continue code/test/docs work that does not depend on them; enumerate the specific external gate when it becomes actionable.

Continuation prompt: **Read docs/agentic/handoff-1.0.0.md and drive this project to a finished, qualified 1.0.0 CLI in one sustained development session. Use a coordinating agent and parallel subagents, maintain the acceptance checklist, implement and review continuously, and respect the stated merge/release and provisioning gates.**
