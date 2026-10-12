# Prepare the synthetic qualification kit

The kit makes the remaining native-import gate executable. It prepares
**synthetic data only** and locally checks all fifteen declared conversion
directions: six provider directions and nine browser-to-provider directions.
Its source fixtures are authored from the documented schemas; they are not
exports produced by native applications. Neither local success nor kit
preparation changes provider qualification from **NOT RUN**.

## Build and prepare

Use an existing Python 3 installation (standard library only) and the trusted,
reviewed Linux candidate. The script installs nothing, builds nothing, uses no
network and accesses no provider account. This helper's preparation is
Linux-only. The candidate enables macOS output after native privacy checks,
with fresh public CLI journey checks still pending; the helper does not provide
that evidence. A successful synthetic artifact can be imported manually in a
destination application on another platform without qualifying that platform's
writer. See the [native output journey](native-output-journey.md) for ordinary
private-directory preparation.

Build with the existing provisioned toolchain/module cache, or use the intended
packaged binary. From the repository root:

```sh
GOTOOLCHAIN=local GOPROXY=off go build -o /tmp/pwmigrate-go-qualification ./cmd/pwmigrate
mkdir -m 700 "synthetic qualification parent"
python3 scripts/qualification/prepare.py \
  --binary /tmp/pwmigrate-go-qualification \
  --output "synthetic qualification parent/kit-01"
```

The output directory must be new. Its parent must already exist, be owned by
the effective user and have no group/other write permission; symlink ancestors
are rejected. Generated directories have mode `0700`; fixture, expectation,
index and manifest files have mode `0600`. The script refuses an existing
output directory and never deletes or replaces a prior kit. Failure can retain
a private partial kit; inspect it locally and choose a fresh directory for
retry. A successful final manifest exists only after all fifteen local checks
pass.

Invoking this script authorizes conversion of **only the fixtures it creates**.
For each route, it runs `inspect`, `plan` and `convert --json`, checks the current
source/target/count/profile, reads the current review and acknowledges its exact
issue IDs in the same process. Only a fixed reviewed set of known synthetic
issue codes is permitted; duplicate JSON keys, an unknown issue or a protocol/profile change fail
closed. Approval is not cached, reused or sent through `--yes`. This bounded
test helper is not an unattended migration tool: it accepts no user vault as
input and must not be adapted to autoapprove real data.

Success prints only a fixed status line. Failures print fixed codes, not source
values, parser excerpts or paths. Command stdout/stderr are captured privately;
the helper does not publish raw reports or approval IDs.
Ctrl+C returns a fixed `cancelled` diagnostic and exit code 130. Library/decoder
failures return a fixed failure code; no traceback is published.

Maintainers can run the retained standard-library helper regressions on Linux:

```sh
python3 -B scripts/qualification/test_prepare.py
```

The tests build the candidate with the existing Go environment and use synthetic
temporary directories. Set `PWMIGRATE_QUALIFICATION_BINARY` to an already built
trusted Linux binary to reuse it instead. Tests cover malformed protocol types,
no approval for malformed/unknown issues, corrupt completed archives, private
modes, no-clobber/parent rejection, safe manifests and credential mutation.

## Optional synthetic SSH companion

The default kit remains fifteen routes with 591 local field checks and contains
no SSH records. A separate companion prepares the six directed provider routes
for Ed25519 SSH items, using the published
[RFC 8032 test vector 1](https://www.rfc-editor.org/rfc/rfc8032#section-7.1).
These published key bytes are synthetic test material; use them only in a
disposable qualification environment.

Run this companion on Linux with the same trusted candidate and an existing
private parent. It accepts no input vault, installs nothing and uses no network:

```sh
python3 -B scripts/qualification/prepare_ssh.py \
  --binary /tmp/pwmigrate-go-qualification \
  --output "synthetic qualification parent/ssh-kit-01"

python3 -B scripts/qualification/test_prepare_ssh.py
```

`PWMIGRATE_QUALIFICATION_BINARY` also lets these regressions reuse an already
built trusted Linux binary. The companion's private-directory preparation is
Linux-only. Its generated Bitwarden JSON, 1PUX and Proton ZIP artifacts can be
imported manually in a destination client on another platform; that does not
qualify that platform's writer or SSH integration.

The companion saves three independently authored native-schema sources and all
six route expectations before invoking any candidate command. Every source has
three SSH records in order: `ssh-ed25519-basic`, `ssh-ed25519-whitespace`,
`ssh-ed25519-duplicate`. They exercise leading/trailing key-text whitespace,
public comments, exact CR/LF notes, repeated items and ordered duplicate
text/hidden custom fields. Bitwarden and Proton sources contain unencrypted
OpenSSH keys; the 1PUX source contains PKCS#8 keys and matching duplicated private
representations, public metadata, fingerprint and `ed25519` type.

It uses the same exact live review/issue/profile/count/completion contract as the
default kit. Stdout and stderr are drained with fixed byte limits and timeouts;
child diagnostics remain private. Unknown issues, duplicate JSON or ZIP names,
unlisted archive members, changed completed plans, unsafe receipt paths and
key mismatches fail closed. Existing directories are never replaced. Modes,
partial-failure handling and private-file handling match the default kit.
Archive validation admits regular or unspecified file types with private or
unspecified entry modes, stored/deflated payloads and Go's framed UTC timestamp
extension. It checks local and central names/flags/methods/sizes, complete
compression and signed data descriptors. ZIP64, special-file modes, unknown or
malformed extensions, overlapping/gapped member spans and contradictory
headers are rejected before archive objects are allocated.

The standard-library decoder verifies only this fixed test vector. It checks
PKCS#8 DER against the known seed and checks unencrypted OpenSSH framing,
matching check integers, wrapper/embedded public bytes, seed, comment and
padding. Public text and SHA256 fingerprints must match the independent literal
expectations. It also checks native SSH kind, record order/count, notes, exact
custom-field order/multiplicity/concealment, 1PUX metadata agreement and hidden
Proton fingerprint relocation. Routes that retain OpenSSH text must preserve
its exact bytes. Representation changes are checked against the known stored
key material, with explicit private expectations for canonical PKCS#8 or
generated OpenSSH check integers/comments.

On success, `private-index.json` identifies the three sources and six successful
artifacts, and `private-expectations.json` contains the exact local values.
Keep both private. Only `result-manifest.json` contains shareable fixed case and
route IDs, public binary metadata and counts. Its `source_app_export`,
`provider_import` and `ssh_authentication` outcomes all remain `not_run`.
The success line reports `local_key_material=passed`; it does not establish
native import, signing behavior or SSH authentication. The decoder is not a
general cryptographic implementation, and the companion does not cover RSA,
encrypted individual keys or all optional SSH metadata.

For each successful route, import its indexed artifact into a fresh disposable
destination vault, require three native SSH records and compare the private
expectations locally. Check duplicate multiplicity, exact retained strings,
documented representation changes and custom concealment. Record application
versions and sanitized case/ordinal outcomes. A native destination re-export
and any authentication against a disposable server you own remain separate
manual gates. Never publish key text, public-key text or fingerprints as
evidence. Real native source export behavior still requires the checklist below.

## Generated files and evidence

| File or directory | Purpose and handling |
| --- | --- |
| `sources/` | Six independently authored plaintext synthetic exports: Chrome, Firefox, Safari CSV; Bitwarden JSON; 1PUX v3; Proton ZIP profile 1.42.0 |
| `private-expectations.json` | Exact synthetic field values, fixed case IDs and one-based ordinals, saved before candidate inspection/conversion; includes independently declared per-route representation expectations |
| `artifacts/` | Fifteen private route parents; each successful converter receipt identifies a new private job directory and destination file |
| `private-index.json` | Relative source/artifact locations for finding each successful file; keep private and use locally |
| `result-manifest.json` | Safe local result: fixed route/case IDs, counts, profile, binary version/public commit and local-check outcomes; every source-app export and provider import remains `not_run` |

The kit intentionally contains synthesized plaintext. Preserve it privately
while testing, and never add its output directory, expectations, index or
artifacts to a commit or public report. Only the sanitized result manifest is
suitable for sharing. An unstamped binary records `dev`/`unknown`; regenerate
with the final reviewed candidate if exact release provenance is required.
No source-derived hash is published.

Provider fixtures have seven records in this order: `login-basic`, `note-basic`,
`card-basic`, `identity-basic`, `credential-whitespace`, `duplicate-identical`,
`duplicate-password`. Browser fixtures have four login records in this order:
`login-basic`, `credential-whitespace`, `duplicate-identical`,
`duplicate-password`. The duplicate cases retain identical title/URL/username
with both an exact repeated password and a separate password variant. Tests
also include hidden/text custom values, quoted CSV content, leading/trailing
credential whitespace, CR/LF/CRLF and distinct Unicode spellings.

The helper independently decodes the documented output subset and compares
record count/order, item kind, names, notes where supplied, exact login
credentials/URLs, representative card and identity fields, custom values and
concealment, and Safari's exact OTP URI. It does not use a converter-produced
file as an expected source. Numeric 1PUX `YYYYMM` does not carry a lexical
leading-zero month: the private expectation explicitly distinguishes its
Bitwarden decimal month from the zero-padded Proton representation.

This is **local mapping evidence**. The script does not certify native import,
all optional metadata, folder/vault reconstruction, importer limits, attachment
behavior, passkey/SSH authentication, encrypted-source interoperability or
complete account coverage. Disclosed unsupported metadata remains omitted from
destination output. The broader cases in the
[provider qualification checklist](provider-qualification.md) are still
required.

## Import and compare each route manually

1. Open `private-index.json` locally and choose a route. Use its exact successful
   `artifact_file`; require a successful script exit and completed manifest.
   Do not import files from a failed/partial kit.
2. Create a disposable empty destination vault/account containing no real
   credentials. Start fresh for each route. Import with **Bitwarden JSON**, native
   **1PUX**, or **Proton Pass ZIP**, matching the artifact target. Record the
   application/version, server where applicable, platform, import option, date,
   converter version/commit and route profile.
3. Check the expected count (seven provider records or four browser records),
   types and duplicate multiplicity. Compare exact values locally to
   `private-expectations.json` for that route, preserving whitespace,
   absent/null/empty distinctions, custom concealment and representation changes.
   Record only fixed case IDs, ordinals, safe counts and discrepancy codes.
4. If import is rejected, record `rejected` and its sanitized outcome. Do not
   hand-repair the file and attribute acceptance to the original converter.
   Acknowledged field loss and provider importer changes are still losses.
5. Manually re-export that synthetic destination in its admitted native format.
   Run the candidate's `compare` command using the original source and exact
   route target. For example, for Bitwarden → 1Password:

   ```sh
   /tmp/pwmigrate-go-qualification compare \
     --input "synthetic qualification parent/kit-01/sources/bitwarden-json.json" \
     --from bitwarden-json --to onepassword-1pux \
     --destination "synthetic destination reexport.1pux" --json
   ```

   Read matched/missing/unexpected counts, ambiguous duplicate groups and
   unobservable fields alongside independent local expectations. Comparison
   remains `destination_import_verified:false`: it observes a supplied file,
   not the account/import event. It does not certify working credentials.
6. Fill the safe result template in
   [provider-qualification.md](provider-qualification.md) for that exact
   route/profile/environment. Keep the kit's local manifest unchanged: actual
   manual acceptance belongs in a separately recorded native result, not an
   invented automatic pass.

The agent and converter receive no account credentials or account access.
Cleanup of the disposable vault and synthesized plaintext is a user action.
Private permissions do not isolate root/same-user processes, and SSD/snapshot
secure erasure is not guaranteed.

## Additional native-source and behavior cases

The kit is a repeatable starting set, not the complete 1.0 gate. Create synthetic
records in actual source applications and export them to establish exporter
compatibility separately from these authored fixtures. Retest every supported
source/profile against each claimed destination.

- **Encrypted sources:** create native synthetic Bitwarden password-protected
  PBKDF2 and Argon2id exports within the published bounds, and a native Proton
  encrypted export in the admitted OpenPGP profile. Inspect/convert with local
  echo-disabled password prompts. For stdin, use `--password-stdin`; add
  `--password-json` to preserve literal CR/LF. Never put a password in argv,
  shell history or evidence. Wrong password/tampered input must not produce a
  successful artifact. Record native exporter versions and interoperability
  separately; Proton attachment members remain plaintext in its encrypted ZIP.
- **SSH:** the default fifteen-route kit has no SSH records; the optional
  companion above prepares independently authored Ed25519 fixtures for six
  provider directions. Also create Ed25519 keys in a disposable native source
  and test its exports across all provider directions. Test RSA
  2048/3072/4096-bit Bitwarden ↔ Proton and 1PUX → Bitwarden/Proton. Reverse RSA
  into 1PUX remains blocked on its unverified writer `metadata.keyType` literal.
  Check exact retained strings, disclosed PKCS#8/PKCS#1 → OpenSSH transformations
  and private/public/fingerprint consistency locally. Check exact hidden Proton
  fingerprint relocation, text/hidden section-field relocation and grouping or
  unsupported section-type loss without interpreting arbitrary labels as native
  fingerprint metadata. Native SSH authentication must run separately against
  a disposable server you own with its native client/integration. Do not share
  private/public key text or source-derived fingerprints in evidence. Recovery
  of the whole source preserves omitted sections/representations; it does not
  migrate them or qualify authentication.
- **Coverage and loss:** add absent/null/empty values, favorites/status/times,
  container selection, unknown fields/types, large fields/batches, attachments,
  icons and passkey payloads from the full checklist. Unsupported selected
  records must block conversion; deliberately exclude them or use
  `recovery-save` to preserve the exact whole original without claiming migration.
- **Recovery:** generate a private age key, convert with `--recovery-key-file`,
  acknowledge whole-source retention and restore with `recover --key-file`.
  Verify exact original bytes locally, including excluded records and archive
  members. Test wrong-key/truncation/tamper rejection on synthetic data. Keep
  the secret key separate; losing it makes recovery unreadable. Maintained age
  interoperability, native age CLI interoperability and provider import are
  separate recorded outcomes.

No native imports, native-source encrypted interoperability, native SSH
authentication or stable publication are executed by kit preparation.
