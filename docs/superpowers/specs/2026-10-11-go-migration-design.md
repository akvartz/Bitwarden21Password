# pwmigrate Go migration design

Date: 2026-10-11. Status: accepted product direction; implementation proceeds in gated milestones.

## Purpose and accepted requirements

Help ordinary people move between password managers and understand exactly what survived. Account for every source field; never promise universal losslessness.

The user approved:

- A Go engine shared by supported CLI and desktop apps on Linux, macOS, and Windows. They can test Linux/macOS and a Windows VM.
- Bitwarden, 1Password, and Proton Pass in both directions; browser exports as sources.
- Export files only, with local processing. No account authentication or direct vault API access.
- Supported encrypted exports unlock locally without saving passwords.
- Whole exports by default; optional vault, folder, item-type, and individual selection.
- Keep all suspected duplicates and flag them; no automatic merging or deletion.
- Explain limitations and require explicit review before continuing with data loss.
- Optional encrypted recovery for unsupported data, labelled preserved but not migrated.
- Field-level accounting, generated-output checks, and optional destination re-export comparison.
- No telemetry, remote UI assets, or automatic source deletion.

Wails v2 with a small TypeScript UI is the selected desktop approach. Keep business rules in Go and desktop dependencies out of the CLI. Choose the frontend component framework in the desktop milestone based on accessibility and maintenance.

## Baseline and constraints

Reference revision: `46f0db74b73ac6b3294c935aacdad631a59ef6d4`. The Rust code has 14 adapters, 18 test functions, and five fixtures. Source review found password trimming, secret-bearing errors, incomplete identity mappings, ambiguous notes encoding, and unprotected output. Rust is reference material, not a correctness oracle. Preserve it during replacement.

Go 1.26.0, Node 22.22.1, npm, and gh are installed. Rust/Wails were unavailable. Do not acquire tools or new dependencies; the user handles provisioning. M1 uses only the Go standard library with `GOTOOLCHAIN=local GOPROXY=off`. Local synthetic testing is not release-security qualification: use a maintained patched toolchain before releasing.

## Architecture

`source -> strict parser -> complete inventory + typed projection -> selection -> plan -> review/approval -> protected output -> validation -> optional destination comparison`

Inventory retains every source field and unfamiliar provider payload; typed projections simplify known mappings. Missing projection support must never erase inventory. Begin with one `internal/migration` package split by responsibility, a thin `cmd/pwmigrate`, and testable `internal/cli`. Add archive, crypto, output, and desktop boundaries only when needed. No generic plugin framework or daemon.

### Fidelity and reporting

- Keep an immutable owned source snapshot in backend memory. Preserve unknown records and metadata as well as known fields. Do not serialize the document into public reports.
- Preserve exact values: whitespace, line endings, Unicode, absent versus empty, duplicate multiplicity, and provider-specific types. Unknown item types are not logins.
- Never interpret arbitrary user notes as converter metadata. Any future preservation envelope must be structured, versioned, and namespaced separately from user fields.
- Full scope includes complete identities, typed custom fields, URI matching policy, distinct username/email, archived/trash states, timestamps, vault relationships, SSH keys, attachments, and passkey metadata/provider payloads. M1 implements only the projections it needs.
- Each selected source field gets exactly one disposition: `native`, `relocated`, `transformed`, `unsupported`, or `omitted`. Recovery retention is a separate fact, not destination success. Excluded records are counted separately from loss.
- Reports use fixed codes, counts, and one-based record/field ordinals. Never include raw values, titles, URLs, usernames, arbitrary field names, paths, raw parser excerpts, or unkeyed secret/vault hashes. Render sensitive selection labels only in the active UI, escaped as text.
- Source export omissions must be visible as coverage caveats. An empty export does not prove an empty account.

Evidence levels remain distinct: `planned` means no output; `output_validated` means local output checks; `destination_compared` means comparison of a supplied re-export with its limitations; provider certification requires an actual synthetic import on a recorded app version/platform. Self-roundtrips never establish provider acceptance. Comparison must retain multiplicity, report ambiguous matches, and identify unobservable fields. It cannot prove passkey authentication works.

### Approval and execution, M2 onward

The backend owns `loaded -> planned -> approved -> writing -> completed`, plus failure/cancellation states. Approval binds to the immutable snapshot, selection, target/profile version, options, and exact loss/transformation set. Changes invalidate it. Approval is consumed once, including duplicate clicks/replays. The CLI uses the same gate: interactive review or explicit acceptance of specific issue IDs for automation, never implicit blanket acceptance. Public receipts contain no approval secrets or source-derived hashes. M1 has no write/commit operation.

### Input and output safety

- M1 limits: 32 MiB actual input bytes, 50,000 records, JSON nesting depth 64, 1,000,000 total source fields, 1,024 CSV columns, and 250,000 JSON containers. Fail the entire operation at limits; never silently return partial success.
- Count every JSON object/array before allocating it, including root and empty items containers. A separate container budget limits nesting amplification without changing public leaf-field accounting; excess returns container_limit.
- Reject invalid UTF-8, duplicate JSON keys, extra JSON documents, malformed CSV quoting, duplicate/empty normalized headers, uneven rows, and malformed Bitwarden items. Errors contain fixed codes and numeric locations only.
- Output must be no-clobber by construction: newly created private job directories and exclusively created files are preferred. Never overwrite sources through same paths, symlinks, or hard links. Do not use existence-check-then-write.
- Unix directories/files start at `0700`/`0600`. Windows needs a reviewed DACL implementation and native tests; `0600` alone is not a Windows privacy guarantee.
- Exclusive creation does not prove atomic completed-file publication. Test interrupted writes, close/sync errors, cancellation, concurrent commits, and cleanup ownership. No completion receipt after a failed write.
- Read archives without extraction when practical. Reject traversal, duplicate/conflicting names, links/devices, unsafe nesting, and actual decompression-limit violations. Bound compressed/expanded bytes, entries, depth, and KDF resource use.
- No guarantee of secure erasure on SSDs/snapshots or perfect zeroization in Go/WebView memory; minimize copies and lifetime.

### Encryption and recovery

Follow each provider's authenticated format with maintained implementations and independent vectors. Reject unsupported versions, KDFs, and account-bound envelopes that cannot be unlocked independently. Do not invent crypto to avoid a missing dependency. Authenticate the complete stream before success.

Evaluate age and its maintained Go implementation for recovery in a separate dependency/security gate. Encrypt payloads and manifest; deliver a reader and independent interoperability/tamper tests in the same milestone. Passwords/keys come from local prompts/UI, never argv/logs/preferences. Explain recovery-key responsibility and plaintext destination requirements before output. Never automatically delete originals after import.

### Desktop boundary

Expose a narrow facade for open/inspect/select/plan/approve/commit/compare/cancel. No arbitrary filesystem bindings or raw-vault getter. Use embedded local assets, restrictive CSP, escaped text, no remote navigation, no vault data in browser storage, and deliberate secret reveal. Require keyboard navigation, focus management, accessible labels, progress, and cancellation.

## Provider capability policy

Capabilities are directional and versioned; export support does not establish import support. Label routes experimental until independently validated.

- Prefer 1PUX over incomplete 1Password CSV for richer items/attachments. Current desktop exports omit passkeys; mobile Credential Exchange is a separate native workflow. Current 1PUX import documentation includes desktop and mobile, but a generated writer still needs acceptance tests.
- Bitwarden JSON includes SSH keys/passkeys; individual exports exclude organization data and do not include trash/Sends. Current custom JSON import documentation requires separate attachment uploads.
- Bitwarden ZIP source at the reviewed revision uses sanitized titles/filenames without an attachment-ID manifest. Ambiguous ownership requires review/recovery, never guessed assignment.
- 1Password's native Bitwarden importer calls for password-protected encrypted JSON, not plaintext/account-restricted JSON; it has passkey/shared-collection limitations.
- Bitwarden password-protected envelopes use provider KDF parameters (PBKDF2 or Argon2id), authenticated encryption, and validation/data fields. Do not hardcode a KDF iteration count. Account-restricted exports are out of scope.
- Proton ZIP contains `Proton Pass/data.json` or `Proton Pass/data.pgp`, with optional files. Its encrypted payload uses password-based OpenPGP; optional attachments can remain unencrypted. Aliases, owned/shared vaults, and unknown types need explicit policies.
- Keeping provider passkey blobs is recovery preservation, not proof of working cross-provider passkeys.
- Recommend native provider routes when they better preserve data. This does not require app account access or runtime network calls.

Primary references checked 2026-10-11:

- [1Password export](https://support.1password.com/export/), [1PUX](https://support.1password.com/1pux-format/), [import](https://support.1password.com/import/), [Bitwarden import](https://support.1password.com/import-bitwarden/).
- [Bitwarden export](https://bitwarden.com/help/export-your-data/), [encrypted export](https://bitwarden.com/help/encrypted-export/), [custom JSON import](https://bitwarden.com/help/condition-bitwarden-import/).
- [Proton export](https://proton.me/support/pass-export).
- [Bitwarden source snapshot](https://github.com/bitwarden/clients/tree/df9641824436b65207f393d35b8d07225129797b/libs/tools/export-vault-core/src/services), [Proton archive source](https://github.com/ProtonMail/WebClients/blob/c8393e366e69bfa89762c5d0a9c2fb39b99c1ba4/packages/pass/lib/export/archive.ts), [Proton export UI](https://github.com/ProtonMail/WebClients/blob/c8393e366e69bfa89762c5d0a9c2fb39b99c1ba4/packages/pass/components/Export/ExportForm.tsx).
- [Wails](https://wails.io/docs/introduction/), [v2/v3 status](https://v3.wails.io/faq/), [Go filesystem APIs](https://pkg.go.dev/os@go1.26.0), [age format](https://age-encryption.org/v1).

Source snapshots and docs are not live-provider test evidence.

## Milestone roadmap

| Milestone | Deliverable | Gate |
| --- | --- | --- |
| M1 | Read-only Go inspection/planning CLI | Exact parsing, inventory accounting, redaction, no vault-output capability, independent/adversarial review |
| M2 | First protected Chrome-to-Bitwarden execution | Bound approval, no-clobber/failure tests, Unix permissions, Windows DACL/native tests before Windows output, synthetic destination import |
| M3 | Rich Bitwarden/1PUX/Proton routes and selection | Direction-specific profiles/fixtures, archive limits, attachment ambiguity, provider evidence |
| M4 | Encrypted inputs and recovery writer/reader | Provisioned maintained dependencies, independent vectors, tamper/truncation/KDF limits, security review |
| M5 | Wails desktop and destination comparison | Same engine, keyboard/accessibility, duplicate-aware matching, native Linux/macOS/Windows checks |
| M6 | Release readiness | Patched/pinned tools, installable artifacts, supported-route matrix, user testing, signing/build provenance |

Split platform/provider work into independently gated slices when useful. Missing dependencies block their capability, not unrelated work. A milestone pass never means the full product is complete. Releases/tags remain user actions.

## M1 exact contract

M1 is a read-only tool for synthetic evaluation, not a production converter replacement. No `convert`, output-file flag, password prompt, recovery writer, desktop code, or network access.

Module `github.com/akvartz/Bitwarden21Password`; Go floor `1.26.0`; standard library only. Keep Rust unchanged. Build the Go binary as `pwmigrate-go` during coexistence.

```
pwmigrate-go inspect --input PATH [--from chrome-csv|bitwarden-json] [--json]
pwmigrate-go plan --input PATH [--from chrome-csv] --to bitwarden-json [--select 1,3] [--json]
pwmigrate-go formats [--json]
```

Formats are exact IDs. Empty source means auto-detection: Chrome requires `name,url,username,password` headers (optional `note`); Bitwarden requires boolean `encrypted:false` plus an `items` array. Encrypted-looking Bitwarden returns `unsupported_encrypted`; unfamiliar input returns `unknown_format`, without excerpts.

Chrome: normalize headers' surrounding whitespace/ASCII case for matching only. Preserve every cell, including unknown/empty cells. Unknown columns plan as concealed custom fields, publicly identified only by column ordinal. Reject duplicate normalized headers, empty headers, blank logical records, malformed quoting, and uneven rows. Accept CRLF record endings and preserve CR/LF inside quoted cells exactly; Go's CSV reader normally normalizes CRLF, so test this explicitly. Never interpret the old extras marker in notes.

Bitwarden: validate envelope and integer item types. Known types: 1 login, 2 secure note, 3 card, 4 identity, 5 SSH key; other integer types stay unknown and retained. Require string `name`. Known login username/password/totp fields, if present, must be string or null; login if present must be object or null. Count scalar leaves and empty arrays/objects as fields, distinguishing record fields from root metadata. Keep complete raw source data. No Bitwarden-source planning route in M1.

One-based record/field ordinals identify source locations. Inventory includes counts, kind counts, duplicate groups, and fixed export-coverage caveats. Chrome duplicate suspicion uses exact `(name,url,username)`, ignores password differences, and never merges. Bitwarden duplicate detection is deferred and reported as not evaluated.

Chrome-to-Bitwarden plan: every selected cell gets exactly one disposition. Known fields are `native`; unknown columns are `relocated`. Selection defaults to all; supplied ordinals must be positive, unique, in range; supplied empty selection is invalid. Reports distinguish total/selected/excluded. Unsupported routes fail. Plans state `planned`, `output_emitted:false`, `destination_import_verified:false`. JSON and human views share safe report types.

API in `internal/migration`:

```go
type Format string // ChromeCSV and BitwardenJSON constants
func Parse(data []byte, source Format) (*Document, error) // empty source means detect
func (d *Document) Inspect() Inventory
func (d *Document) Plan(target Format, selection []int) (Plan, error) // nil means all
```

Document fields are unexported and own the snapshot/records. Reports contain only safe fields/fixed strings. SafeError exposes fixed code and optional numeric record/column. Never interpolate unknown format/target strings, paths, or parser errors. Limits: 32 MiB bytes, 50,000 records, JSON depth 64, 1,000,000 total source fields, 1,024 CSV columns, and 250,000 JSON containers.

CLI: `func Run(args []string, stdout, stderr io.Writer) int`; main performs minimal process signal setup and exits with its result. Handle Unix SIGPIPE at the executable boundary so closed stdout/stderr pipes return the documented I/O failure instead of signal termination. Exit 0 success/help; 2 invalid arguments; 3 invalid/unsupported/over-limit input or route; 1 I/O failure. Errors never echo user flag values/paths. Read only regular files, bound actual bytes, and report to stdout with sanitized stderr. Never invoke Rust as fallback.

Checks: focused red-green tests; `go test ./...`; `go test -race ./...`; `go vet ./...`; bounded parser fuzzing; cross-compile CLI for Linux amd64, Windows amd64, macOS amd64/arm64. Cross-compilation is build evidence only. Actual CLI subprocess tests use synthetic files and verify exit codes/redaction/selection/no file writes.

## Authorization

The user waived routine approval gates and delegated execution. Native permissions, secret denials, no-install rules, destructive-action boundaries, and release/merge gates remain. Risky migration PRs remain unmerged. Follow `docs/agentic/README.md`; unavailable checks are not passes.
