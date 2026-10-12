# pwmigrate

The Go implementation currently provides **M1 read-only inspection and planning
for synthetic evaluation**. It is not a production password-manager converter.
The legacy Rust implementation remains in the repository while Go milestones
are validated.

## Go M1

Requires the installed Go 1.26.0 toolchain. M1 uses only the standard library.
Build from the repository root without downloading a toolchain or dependencies:

```sh
GOTOOLCHAIN=local GOPROXY=off go build -o pwmigrate-go ./cmd/pwmigrate
```

On Windows, name the binary `pwmigrate-go.exe`. During coexistence, the legacy
Rust binary remains named `pwmigrate`.

```sh
./pwmigrate-go inspect --input synthetic-chrome.csv
./pwmigrate-go inspect --input synthetic-bitwarden.json --from bitwarden-json --json
./pwmigrate-go plan --input synthetic-chrome.csv --to bitwarden-json --json
./pwmigrate-go plan --input synthetic-chrome.csv --to bitwarden-json --select 1,3
./pwmigrate-go formats --json
./pwmigrate-go help
```

| Exact format ID | Inspect | Plan target |
| --- | --- | --- |
| `chrome-csv` | Yes | `bitwarden-json` |
| `bitwarden-json` | Unencrypted JSON only | None in M1 |

Omitting `--from` enables detection. Chrome requires `name`, `url`, `username`,
and `password` headers; `note` and unfamiliar columns are retained. Bitwarden
requires `encrypted:false` and an `items` array. Format aliases are not supported.

Inspection reports counts, fixed item-kind labels, duplicate record ordinals,
and export-coverage caveats. Plans report a disposition for every selected
field, with unfamiliar columns identified by ordinal and planned as concealed
custom fields. Duplicates remain separate records. Selection defaults to all;
`--select` accepts positive, unique one-based record ordinals. Supplied empty,
repeated, malformed, or out-of-range selections fail.

Both human and JSON reports exclude credential values, item titles, URLs,
usernames, unfamiliar field names, input paths, and source-derived fingerprints.
Plans explicitly state `planned`, `output_emitted:false`, and
`destination_import_verified:false`. An empty export does not prove an empty
account, and a plan does not establish destination-provider acceptance or
working passkeys.

M1 has **no conversion, vault-output files, encryption, recovery writer,
password prompt, or desktop UI**. Runtime processing is local with no network,
telemetry, or Rust fallback. Reports go to stdout, and sanitized errors go to
stderr. Shell redirection can save a report; the CLI itself creates no output
files and never deletes originals.

| Exit code | Meaning |
| --- | --- |
| `0` | Successful report or help |
| `2` | Invalid arguments or missing required flags |
| `3` | Invalid, unsupported, nonregular, or over-limit input/selection/route |
| `1` | Input or report I/O failure, including close and short-write failures |

The loader checks the opened file handle and reads at most the 32 MiB input
limit plus one byte. Unix opens use nonblocking mode so a FIFO or a path replaced
by a FIFO is rejected without waiting for a writer. Other parser resource limits
and the shared report contract are documented in the
[foundation plan](docs/superpowers/plans/2026-10-11-go-foundation.md).
Windows native device/pipe and file-replacement behavior still needs native
validation; cross-compilation alone does not qualify it.

Plaintext exports contain credentials. M1 is intended for synthetic fixtures;
keep any source export local and protected by your storage controls. The tool
does not protect or automatically remove existing source files. Secure erasure
on SSDs/snapshots and perfect memory zeroization are not guaranteed.

See the [design](docs/superpowers/specs/2026-10-11-go-migration-design.md),
[implementation plan](docs/superpowers/plans/2026-10-11-go-foundation.md), and
[milestone status](docs/agentic/go-migration-status.md) for the accepted product
scope, evidence, and next gates. Provider imports and native platform checks
remain separate from local synthetic tests.

## Development

```sh
GOTOOLCHAIN=local GOPROXY=off go test ./...
GOTOOLCHAIN=local GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOPROXY=off go vet ./...
```

The shared engine lives in `internal/migration`, the read-only CLI in
`internal/cli`, and the entry point in `cmd/pwmigrate`. Tests use temporary
synthetic exports; subprocess tests build an actual CLI and check exit codes,
redaction, selection, and unchanged source/sibling files.

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
