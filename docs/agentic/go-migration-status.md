# Go migration status

Design: docs/superpowers/specs/2026-10-11-go-migration-design.md.
Plan: docs/superpowers/plans/2026-10-11-go-foundation.md.
Goal scope: reviewed design/plan plus M1 read-only Go CLI and feature PR. The full desktop converter is not complete.

## Delivered source

- Baseline: 46f0db74b73ac6b3294c935aacdad631a59ef6d4.
- Local branch: feat/go-migration-foundation.
- Source through 6bd6adf: strict Chrome CSV and unencrypted Bitwarden JSON inventory; Chrome-to-Bitwarden read-only field planning; whole-export default and optional record selection; duplicates retained and flagged; fixed redacted reports/errors.
- CLI commands: inspect, plan, formats, help. No vault-output writer, encryption, recovery artifact, desktop UI, telemetry, runtime HTTP client, or Rust fallback.
- Rust source, fixtures, and manifests remain unchanged. README distinguishes Go capabilities and legacy limitations.
- M2-M6 have not started. M1 remains experimental for synthetic evaluation.

## Verified evidence

Toolchain: installed Go 1.26.0 linux/amd64. Go commands used GOTOOLCHAIN=local GOPROXY=off, GOCACHE=/tmp/pwmigrate-go-build-cache and GOMODCACHE=/tmp/pwmigrate-go-mod-cache. No tools/dependencies installed.

- Behavioral RED preceded parsers/planner/CLI and both review fixes. Independent literal fixtures cover exact whitespace/newlines/Unicode, unknown data, malformed inputs, limits, selection, duplicate multiplicity, field accounting and report redaction.
- Current full go test -race ./... passed; CLI 3.459s, unchanged core reused its successful 6.527s race result. Unit/subprocess checks and go vet ./... passed. Gofmt listing and Git whitespace checks were clean.
- Actual binary tests cover seven normal/error cases and six closed-pipe cases. They verify exit codes, redaction, and unchanged synthetic source/sibling contents, size, mode, mtime and directory entries. Reading may update atime.
- Linux tests include deterministic regular-file-to-FIFO replacement, FIFO/device rejection without waiting for a writer, bounded actual reads, and injected stat/read/close/short-write failures. Injection results are distinct from native filesystem evidence.
- Bounded fuzzing: go test ./internal/migration -run '^$' -fuzz '^FuzzChromeParser$' -fuzztime=10s -parallel=2 passed with 43,000 executions. Bitwarden JSON passed 801,978 executions initially and 113,688 after the container fix, using the corresponding FuzzBitwardenParser target.
- CGO_ENABLED=0 go build -trimpath ./cmd/pwmigrate succeeded for linux/amd64, windows/amd64, darwin/amd64 and darwin/arm64. Scratch binaries are under /tmp/pwmigrate-go-m1-builds. These are build checks, not release artifacts or native Windows/macOS tests.

## Review and decisions

- Independent core and CLI task reviews passed spec compliance and code quality after fixes. Separate adversarial review reports both findings addressed, with no evidenced blocker in M1.
- JSON container amplification was demonstrated using a small bounded fixture. Every object/array is now checked before allocation against 250,000 containers, separately from leaf-field counts. This may safely reject unusually complex exports; it is not an absolute heap-size guarantee.
- Actual closed stdout/stderr pipes originally terminated with SIGPIPE. Minimal signal setup in main now enforces the documented I/O exit 1. Run remains reusable without changing process signal state. This deliberately changes conventional broken-pipe signal termination to the CLI's documented exit class.
- Fresh whole-branch review of 46f0db7..6bd6adf passed with no findings. It independently ran eight selected core tests, thirteen actual CLI cases, and two FIFO/replacement subprocess cases. The milestone is published as PR #2; it remains open and unmerged.
- User waived routine approval questions. Native permissions, no-install rules, risky merges and release actions remain gated. This security-sensitive PR must remain unmerged.

## Publication and continuation

PR: https://github.com/akvartz/Bitwarden21Password/pull/2, branch feat/go-migration-foundation. At publication GitHub returned no commit statuses, workflow runs or submitted reviews; this is not a CI pass or GitHub approval. Independent agent reviews are recorded above.

Shell Git transport is unavailable on this host: SSH configuration permissions fail and HTTPS/API names do not resolve. The authenticated GitHub connector works. The reviewed committed source tree was published through Git data tools, with remote tree SHA equal to the local tree, and the feature PR was created/attached. The final documentation-only closeout is published by the same equality check. API-generated commit identities differ from local history; preserve both histories and inspect the PR head before further publication. Do not assume a normal fast-forward push is available until those histories are reconciled deliberately. Do not change system SSH configuration, force-push, or rewrite local history.

Read this status, inspect Git, and resume from the scoped agent ledger before redispatching work. The initial native worktree tool could not target this repository from the chat workspace; work uses the initially clean checkout on a feature branch with explicit file ownership. Main owns Git/integration/status; workers own bounded source paths.

## Next ready milestone

M2: protected Chrome-to-Bitwarden execution. First write a bounded plan for source-bound review/approval, a no-clobber output job, complete field outcomes, failure/cancellation cleanup and output reparse/value checks. Start with failing safety tests; keep the same independent/adversarial review loop. Windows output requires reviewed DACL handling plus native VM tests before enabling it. Actual dummy-vault destination import is a separate acceptance gate; a self-roundtrip cannot satisfy it.

Provisioning for later milestones is user-owned: Wails and maintained crypto dependencies are not installed. Do not substitute custom crypto or download dependencies. Rust/Cargo is unavailable, so legacy tests were not run. Native macOS/Windows behavior, provider import acceptance, working passkeys, encryption interoperability, protected output, signing and release readiness remain unverified.
