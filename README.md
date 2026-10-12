# pwmigrate

pwmigrate is a local, CLI-only password-export migration tool. This Go candidate
inspects exports, plans field mappings, converts after explicit review, preserves
an optional encrypted recovery copy, and compares a supplied destination
re-export. Runtime processing needs no network, telemetry or provider login.

**The candidate is experimental. Actual provider-import qualification is not
run, and macOS/Windows public output commands remain disabled pending native
qualification. It is not yet a qualified or published 1.0.0 release.** Use
synthetic data to evaluate it. The [acceptance ledger](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/release-1.0-progress.md)
records the remaining 1.0 gates; the [release runbook](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/releases.md) separates
candidate validation from publication.

## Install or build

When published, download an archive for your operating system and architecture
from [GitHub Releases](https://github.com/akvartz/Bitwarden21Password/releases).
Verify its archive checksum against `SHA256SUMS` before extraction: use
`sha256sum --check SHA256SUMS` on Linux, `shasum -a 256 -c SHA256SUMS` on macOS,
or compare `Get-FileHash -Algorithm SHA256` results on Windows. Check the
manifest's source commit against the intended release. Checksums establish byte
integrity; unsigned checksums do not establish publisher authenticity.

Extract the archive, open a terminal in that directory, and run:

```sh
./pwmigrate-go version --json
./pwmigrate-go help
./pwmigrate-go formats --json
```

In Windows PowerShell use `.\pwmigrate-go.exe`. Archives also contain this
README, the MIT license and `BUILD-INFO.json`. Version output identifies the
source commit, Go version, operating system and architecture; unstamped builds
report `dev` and `unknown`. No installer, GUI or file-drop launcher is included.
Repository documentation links follow the `feat/1.0-release` candidate branch;
the archive includes the README, project license and dependency notices alongside its binary/metadata.
Most terminals insert a path when you drag a file into the command line. Check
the inserted quoting, and quote paths containing spaces.

Source builds require an existing Go 1.26.0 or newer toolchain; distributed
builds pin maintained Go 1.26.9. The module graph is pinned in `go.mod` and
`go.sum`, including x/crypto v0.58.0, gopenpgp/v3 v3.5.2 and age v1.3.2. With
those dependencies already provisioned in your module cache:

```sh
GOTOOLCHAIN=local GOPROXY=off go build -o pwmigrate-go ./cmd/pwmigrate
```

The build does not download a toolchain or dependencies with these settings.
An incomplete offline module cache fails the build. The Go binary is
`pwmigrate-go` (`pwmigrate-go.exe` on Windows); the archived Rust binary was
named `pwmigrate`.

## Formats and routes

Use these exact, case-sensitive IDs; aliases and file extensions do not select
a profile. Omit `--from` for content detection, or provide it explicitly.

| Source format | Accepted input profile | Plan, convert and compare targets |
| --- | --- | --- |
| `chrome-csv` | Chrome/Chromium-compatible CSV with `name,url,username,password` headers | All three provider formats below |
| `firefox-csv` | Firefox CSV with `url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged` headers | All three provider formats below |
| `safari-csv` | Safari/Apple Passwords CSV with `Title,URL,Username,Password,Notes,OTPAuth` headers | All three provider formats below |
| `bitwarden-json` | Unencrypted JSON; supported password-protected encrypted JSON | `onepassword-1pux`, `proton-pass-zip` |
| `onepassword-1pux` | Unencrypted 1PUX v3 ZIP | `bitwarden-json`, `proton-pass-zip` |
| `proton-pass-zip` | Versioned Proton ZIP with `Proton Pass/data.json`, or supported encrypted `data.pgp` | `bitwarden-json`, `onepassword-1pux` |

Browser formats are input-only. Provider-to-same-provider conversion is not a
route. All six directional provider profiles and all browser-to-provider
profiles remain experimental. `formats --json` lists the binary's capabilities;
the completed review names the exact versioned route profile. 1Password ↔ Proton
uses two mapping steps through the Bitwarden model and discloses intermediary
losses.

Firefox has no native title column: a generated destination title comes from
the exact source URL and requires acknowledgment. Its noncredential columns
remain disclosed custom fields. Safari's `OTPAuth` maps the exact OTP URI to
the destination TOTP field with profile acknowledgment; working OTP behavior
still requires destination qualification. Unfamiliar browser columns do not
acquire native semantics merely because their label resembles another format.

Supported rich item mappings cover logins, secure notes, cards and identities.
Experimental SSH mappings support Ed25519 between Bitwarden and 1PUX in both
directions, and RSA 2048/3072/4096-bit keys from 1PUX to Bitwarden. Bitwarden
RSA → 1PUX remains blocked because the destination's `metadata.keyType` literal
has not been independently verified. These mappings validate key material,
public keys and fingerprints and disclose private-key representation changes;
no native SSH import or authentication has been qualified.

SSH routes involving Proton, Proton aliases and unknown item types remain
unsupported. Selecting an unsupported record blocks conversion. Exclude it
deliberately or use `recovery-save` to retain the whole original for another
migration path. The converter never changes an unknown type into a login or
merges duplicate records.

Each selected field receives a disposition: `native`, `relocated`,
`transformed`, `unsupported` or `omitted`. Custom field types, timestamps,
favorites, URL matching, container relationships, archive files and unfamiliar
metadata can require relocation, transformation or explicit loss review.
Vaults/folders/collections are available as selection criteria where represented
by the source; original provider relationships are not reconstructed universally
in destination exports. Attachments and passkey payloads do not acquire working
destination behavior merely by being retained in recovery. No cross-provider
passkey or SSH authentication claim is made.

## Inspect, select, review and convert

Export from your source application using a supported profile. Keep that
original file until you have independently checked the destination. These
examples use synthetic files and an existing private Linux output parent:

```sh
./pwmigrate-go inspect --input "synthetic bitwarden.json" --from bitwarden-json
./pwmigrate-go plan --input "synthetic bitwarden.json" --to onepassword-1pux
./pwmigrate-go plan --input "synthetic bitwarden.json" --to onepassword-1pux --select 1,3 --folder 1 --kind login,card --json

mkdir -m 700 "synthetic output"
./pwmigrate-go convert --input "synthetic bitwarden.json" --to onepassword-1pux --output-dir "synthetic output"
```

Inspection reports record/item-kind counts and source coverage caveats without
printing names or secrets. Record, vault and folder identifiers in selection
are positive, unique, one-based **ordinals**, not labels or provider IDs. An
omitted criterion selects the whole export in that dimension. Combine
`--select 1,3`, `--vault 1,2`, `--folder 1` and
`--kind login,secure_note,card,identity,ssh_key` as needed: criteria intersect and
results retain source order. Malformed, repeated, out-of-range or supplied
empty criteria, and filters that select no records, fail. A format without
vaults/folders cannot satisfy a corresponding container filter.

Read the plan and conversion review, including every affected record/field
ordinal and source-metadata issue. Reports omit labels to keep them safe; use
your local source application or synthetic fixture to identify those locations.
`unsupported` or `omitted` fields are absent from the destination file.
Acknowledging loss permits that omission; it does not preserve the field there.
Keep the original or choose encrypted recovery before continuing.

`convert` prints the exact approval line to enter:
`approve REVIEW_ID ISSUE_ID ...`. Enter that current line only after reviewing
all its issues. Each job has a fresh random review ID. Missing, extra, repeated
or incorrect issue IDs fail, as does an approval from another job. Every
experimental profile requires the experimental-import acknowledgment. There
is no `--yes`, `--force`, reusable approval token or automatic retry.

Wait for exit code **0** and a successful completion receipt before importing.
The receipt gives a generated job-directory basename and fixed export filename
relative to your output parent. Use that exact successful artifact in the
destination's documented import flow: Bitwarden JSON, 1Password 1PUX, or Proton
Pass export ZIP. These files are **plaintext**. Local generated-output validation
does not establish that the destination accepted or retained their values.

The review reports applicable known importer hazards. Bitwarden can replace
blank names, turn blank notes and empty credentials into null/absent values,
remove empty URIs, and reject some blank-name/password batches. Count and
encrypted-field limits depend on the application/server version. Proton's
reviewed importer does not reconstruct favorites from `pinned`; generated
favorite bytes do not prove favorite migration. See
[provider evidence](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/provider-format-evidence.md) and the
[destination qualification procedure](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/provider-qualification.md).

## Encrypted input passwords

Supported encrypted input is unlocked locally. With an interactive terminal,
the CLI requests the export password with terminal echo disabled. Passwords
are never accepted as command-line argument values and are not included in
reports. No trimming or Unicode normalization is applied.

For controlled stdin use `--password-stdin`; it reads one LF/CRLF-terminated
password line before the conversion approval line. The line terminator is
framing, so use `--password-stdin --password-json` for a password containing
literal CR, LF or a final CR. Supply exactly one JSON string on that line, using
JSON escapes such as `\r` and `\n`; the decoded password remains exact. Keep
passwords out of shell history, scripts, argv and logs. Do not pipe a hard-coded
password as a command example. Stdin framing is bounded below 16 KiB.

```sh
./pwmigrate-go inspect --input "synthetic encrypted.json" --from bitwarden-json --password-stdin --password-json --json
```

Bitwarden accepts only password-protected exports with PBKDF2-SHA256 or
Argon2id and authenticated type-2 AES-CBC/HMAC records. Account-restricted,
unauthenticated or unfamiliar cipher envelopes are rejected. PBKDF2 permits
5,000–2,000,000 iterations. Argon2id permits 2–10 iterations, 16–256 MiB,
parallelism 1–16 and at most 768 MiB-passes. Valid provider exports outside
these resource bounds are rejected; do not change an account's KDF just to pass
this tool. [Crypto profile and evidence](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/internal/providercrypto/README.md)
describe the limits and independent vectors.

Proton accepts a strict password-based OpenPGP profile: one v4 AES session-key
packet with iterated salted SHA-256/384/512 S2K, followed by one v1 MDC-protected
encrypted packet. Whole-stream authentication precedes plaintext release;
Argon2, AEAD, signed messages and unauthenticated encryption are unsupported.
Proton's encrypted ZIP protects `data.pgp`, **not optional attachment members**.
1PUX input is unencrypted; 1Password account passwords are not used by this CLI.

## Keep and recover an encrypted original

Recovery is optional and separate from destination migration. It encrypts the
**whole original source file**, including excluded records, unsupported fields,
archive attachments and metadata, in a binary age v1 file. If the original was
already an encrypted provider export, recovery retains those encrypted bytes;
its original export password is still needed after restoration.

Create a recovery key in a private existing Linux directory, then use the
generated `recovery-key.txt` path shown by its receipt:

```sh
mkdir -m 700 "synthetic keys"
./pwmigrate-go recovery-key --output-dir "synthetic keys"
./pwmigrate-go convert --input "synthetic bitwarden.json" --to onepassword-1pux --output-dir "synthetic output" --recovery-key-file "synthetic keys/JOB_DIRECTORY/recovery-key.txt" --json
```

Replace `JOB_DIRECTORY` with the generated basename. The key is a secret age
X25519 identity written through protected output, never printed in the receipt.
Protect a supplied key file yourself; store the key separately from the
encrypted recovery and back it up securely. A lost key makes recovery
unreadable. Sharing the key permits decryption. This profile accepts one native
X25519 key, not age passwords, plugins, SSH keys or multiple recipients.

If unsupported records block conversion, save recovery independently without
claiming that any record migrated. This also permits retaining an attachment-only
original. Specify the original's format explicitly:

```sh
./pwmigrate-go recovery-save --input "synthetic original.1pux" --from onepassword-1pux --key-file "synthetic keys/JOB_DIRECTORY/recovery-key.txt" --output-dir "synthetic output"
```

`recovery-save` encrypts exact original bytes with the declared format; it does
not unlock or validate the provider export or create a destination export.
This explicit save command needs no conversion approval. Its receipt states
`whole_source_not_migrated`; it does not report destination migration. Recovery
is limited to a 32 MiB original and 48 MiB ciphertext.

Approve the additional whole-source retention issue. The successful conversion
receipt identifies both the destination artifact and the separate `recovery.age`
artifact. Restore into a new private output parent:

```sh
mkdir -m 700 "synthetic restored"
./pwmigrate-go recover --input "synthetic output/RECOVERY_JOB_DIRECTORY/recovery.age" --key-file "synthetic keys/JOB_DIRECTORY/recovery-key.txt" --output-dir "synthetic restored"
```

`recover` authenticates the complete ciphertext before publishing a source
file. The receipt identifies its new directory and `source.csv`, `source.json`,
`source.1pux` or `source.zip`. Restoration reproduces original bytes, not an
importable destination conversion. The restored original may itself contain
plaintext. [Recovery framing and evidence](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/internal/recovery/README.md) record
the package limits and maintained age interoperability separately from native
age CLI qualification.

## Compare a destination re-export

After a successful manual import into a disposable synthetic vault, export the
destination using its supported native profile. Compare it against the original
source with the same target and filters used for conversion:

```sh
./pwmigrate-go compare --input "synthetic bitwarden.json" --to onepassword-1pux --destination "synthetic reexport.1pux" --select 1,3 --json
```

The report distinguishes matched, missing and unexpected records, duplicate
multiplicity, ambiguous matches and unobservable fields. Metadata and omitted
fields cannot be inferred from a match. A supplied re-export observation retains
`destination_import_verified:false`: the CLI has no evidence of how that file
was produced and cannot certify account contents or working credentials.
Encrypted source/destination inputs prompt in that order; stdin mode needs a
separate password line for each encrypted input. Check exact case/field
expectations independently using the
[qualification checklist](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/provider-qualification.md).

## Progress, failures and output protection

Conversion announces fixed stages on stderr and reports its review/completion
state. Stage announcements do not prove that a stage has finished; the CLI
does not display source values or estimate a completion percentage. Ctrl+C
or SIGTERM requests cancellation of output commands. Expensive KDF/library work
can finish before cancellation is observed. Read-only commands use normal
operating-system signal termination.

On Linux, the existing output parent must be owned by the effective user and
not writable by group or others. Each artifact gets a new private `0700` job
directory and an exclusively created `0600` partial file. Publication is
no-clobber; existing files are never replaced. Writes, readback, sync and close
are checked. Use a suitable local filesystem; the writer needs hard-link and
sync support. Public macOS/Windows writers fail closed with `output_platform`
until native ACL/DACL and volume checks qualify them. Authored platform code
and cross-compilation do not constitute that qualification.

A job containing an export and recovery is not one atomic filesystem
transaction. Failure or interruption can leave private partial artifacts or a
completed export before recovery/report failure. A broken final output stream
can return failure after file publication. Require both a successful receipt
and exit 0; inspect a failed job locally before deciding to retry. A retry starts
a fresh job and requires fresh approval. No recursive cleanup, automatic retry
or source deletion occurs.

| Exit code | Normal-return meaning |
| --- | --- |
| `0` | Successful report/output command or help |
| `2` | Invalid arguments or missing flags |
| `3` | Rejected input, selection, route, limits, approval, state or platform |
| `1` | I/O, local validation or cancellation failure |

Errors use fixed safe codes. For `output_parent`, check the existing directory's
ownership/permissions; for `output_platform`, use supported Linux output; for
`password_required`, use a terminal or explicit stdin framing; for
`authentication_failed`, check the local password and original export without
posting them. Unsupported formats, encryption profiles or records require a
supported source/profile/selection. Never work around a rejected archive by
silently extracting or dropping unknown members.

Input and generated export output are bounded at 32 MiB; ZIPs also enforce
actual expanded-byte/member/path/type/CRC limits. JSON and CSV have field,
record, container and depth budgets. A valid input can expand past output
limits and fail before export creation. Recovery ciphertext is bounded at
48 MiB. The loader checks opened regular-file handles and actual bytes;
Windows native input-device/pipe replacement behavior remains unqualified.

Reports contain fixed codes, counts and ordinals, never credentials, titles,
URLs, custom labels, source/parent paths or source-derived fingerprints.
`inspect`, `plan`, `compare`, `formats`, `version`, `recovery-key`,
`recovery-save` and `recover` emit one JSON report with `--json`.
`convert --json` emits newline-separated
event objects, with approval instructions on stderr and the response on stdin;
it is not a single JSON document. A plan emits no vault file.

Private filesystem permissions do not isolate root or another process using
your account. Plaintext exports and restored sources require your own handling
and cleanup. Go cannot guarantee clearing every memory copy, and SSDs, backups
and snapshots prevent reliable secure-erasure guarantees. An empty export does
not prove an empty account.

## Development and qualification

With the provisioned dependency cache and existing patched toolchain:

```sh
GOTOOLCHAIN=local GOPROXY=off go test -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off go test -race -count=1 ./...
GOTOOLCHAIN=local GOPROXY=off go vet ./...
```

Tests use synthetic data only. The migration engine is in `internal/migration`,
bounded ZIP handling in `internal/safearchive`, crypto in
`internal/providercrypto` and `internal/recovery`, protected writes in
`internal/protectedoutput`, and commands in `internal/cli`. See the
[design](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/superpowers/specs/2026-10-11-go-migration-design.md),
[acceptance ledger](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/release-1.0-progress.md),
[all-destination qualification checklist](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/provider-qualification.md)
and earlier [Chrome-to-Bitwarden checklist](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/docs/agentic/bitwarden-import-qualification.md).
The earlier checklist describes the baseline evidence; use the current
`compare` command for supplied re-exports.

| Platform | Inspect, plan, compare, formats, version | Public convert/recovery output |
| --- | --- | --- |
| Linux amd64/arm64 | Built for both architectures | Experimental; record native runtime evidence by architecture |
| macOS amd64/arm64 | Built for both architectures | Disabled pending native ACL/volume qualification |
| Windows amd64/arm64 | Built for both architectures | Disabled pending native DACL/volume qualification |

Local tests, native CI, six-architecture packaging and provider imports are
separate evidence. Cross-compilation proves a build, not native behavior;
self-roundtrips prove neither provider acceptance nor authentication.

## Legacy and license

The archived [Rust implementation](https://github.com/akvartz/Bitwarden21Password/blob/feat/1.0-release/legacy/rust/README.md) retains its historical
adapters and fixtures. Their format list does not describe Go support. Known
legacy concerns include trimming credentials, secret-bearing errors, incomplete
mappings, ambiguous notes markers and unprotected output. Rust is neither a
correctness oracle nor a fallback; the Go CLI never invokes it silently.

MIT — see [LICENSE](LICENSE). Dependency licenses appear in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md); both files are packaged.
