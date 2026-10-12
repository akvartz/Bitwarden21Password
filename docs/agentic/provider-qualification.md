# Synthetic destination qualification

Status, 2026-10-12 (America/New_York): **NOT RUN for every current destination
and route profile**. Source research, independent fixtures, generated-output
validation and self-roundtrips do not establish native provider acceptance.
This is a concrete user-run procedure using disposable synthetic vaults.
Neither the agent nor the converter logs in, acquires an account, calls provider
APIs or receives real vault/password/key files.

The earlier [Chrome-to-Bitwarden checklist](bitwarden-import-qualification.md)
remains the baseline case inventory. The current CLI automates comparison of a
supplied re-export with `compare`; comparison does not observe the import event
or set `destination_import_verified:true`. Use the current
[README journeys](../../README.md) and [public format evidence](provider-format-evidence.md)
with this checklist.

Start with the [synthetic qualification kit](qualification-kit.md) to generate
private fixtures and locally checked artifacts for all fifteen routes using
the reviewed candidate. Its independently authored sources are not native-app
exports, and its safe manifest leaves every provider import `not_run`. Continue
the manual procedure below to establish the missing native evidence.

## Record a reproducible environment

Record a separate result for each direction, versioned profile, destination
import route and environment. Include:

- Converter source commit, binary version, Go version, OS and architecture.
- The exact `profile` from conversion review/completion and source format
  version/encryption profile where applicable.
- Source application version/platform/export option; destination application
  version/platform/import option; server/self-hosted version if known.
- Test date, fixed synthetic case IDs, attempted/accepted/rejected record counts,
  duplicate multiplicity and observed field outcomes by case/field ordinal.
- Local checks, actual native destination import, supplied re-export comparison,
  native output permissions and authentication checks as separate evidence.

Keep real source paths, vault labels, credentials, custom labels/values and
source-derived hashes out of evidence records. Store any synthetic fixtures and
exact-value expectations locally; publish only fixed case IDs, safe counts,
ordinals and discrepancy codes. Public converter/provider Git revisions are
appropriate provenance. Do not export or post a user's existing account.

Create a disposable **empty** destination vault/account containing no real
credentials. Use a new empty vault for each import, or explicitly reset it
between cases: importing twice into the same vault can create duplicates and
invalidate multiplicity observations. Keep the original fixture and successful
conversion artifact available locally until the result is assessed.

## Route coverage

Qualify each profile independently. A successful Bitwarden destination does
not qualify 1Password, Proton or the reverse direction.

| Direction | Versioned provider profile | Native destination import option |
| --- | --- | --- |
| Bitwarden → 1Password | `bitwarden-to-onepassword-1pux-v1` | 1Password unencrypted export (`.1pux`) |
| 1Password → Bitwarden | `onepassword-1pux-to-bitwarden-json-v1` | Bitwarden JSON |
| Bitwarden → Proton | `bitwarden-to-proton-pass-zip-v1` | Proton Pass export ZIP |
| Proton → Bitwarden | `proton-pass-zip-to-bitwarden-json-v1` | Bitwarden JSON |
| 1Password → Proton | `onepassword-1pux-to-proton-pass-zip-v1` | Proton Pass export ZIP |
| Proton → 1Password | `proton-pass-zip-to-onepassword-1pux-v1` | 1Password unencrypted export (`.1pux`) |

Also run **each** declared browser format (`chrome-csv`, `firefox-csv`,
`safari-csv`) into **each** destination (`bitwarden-json`, `onepassword-1pux`,
`proton-pass-zip`): nine browser directions. Copy the actual versioned browser
profile from its review instead of inferring a name. Explicitly record any
browser-generated title or OTP representation acknowledgment.

The source must use the admitted profile: unencrypted Bitwarden JSON or its
supported password-protected PBKDF2/Argon2id profile; unencrypted 1PUX v3;
versioned Proton ZIP with supported plaintext or encrypted data; or the exact
browser CSV schema. Provider-native encrypted exports need their own source
unlock evidence, even when the same destination mapping was qualified from
plaintext. Bitwarden account-restricted exports and unknown cipher/KDF variants
are rejected. An encrypted Proton data entry does not encrypt its attachments.

## Independent synthetic expectations

Author expected values before running conversion. Prefer source-app-created
synthetic exports to establish real exporter shape, supplemented by hand-authored
edge fixtures with fixed documented schemas. Do not generate an expected file
using the adapter under test. Check decoded values exactly, including whitespace,
CR/LF, Unicode, absent/null/empty distinctions and duplicate counts.

For login, note, card and identity cases, list each native, relocated,
transformed, unsupported or omitted field from `plan`. A supported item kind
does not guarantee that all its optional fields migrate. Validate every
representation change independently; do not normalize observations just to
make them match. Compare loss review to the actual loss, and keep recovery
retention separate from destination outcomes.

| Fixed case | Independent expectation and destination observation |
| --- | --- |
| `login-basic` | One login with exact username/password, notes and URLs; distinguish multiple URLs and their matching policies |
| `note-basic` | Secure-note item type and exact multiline notes; no conversion into a login |
| `card-basic` | Cardholder, number, verification code and independently decoded brand/expiry; leading zero and lexical expiry cases must be disclosed if transformed |
| `identity-basic` | Exact separately named identity fields; no splitting arbitrary full names or silently concatenating address lines |
| `credential-whitespace` | Leading/trailing spaces, tabs, CR, LF, CRLF and non-normalized Unicode remain exact in supported credential values |
| `empty-missing-null` | Check each independently; record destination null/absence/placeholder conversion instead of treating it as equality |
| `duplicate-records` | Two identical items and two lookalikes differing only in password remain distinct; re-export multiplicity and ambiguous matching are visible |
| `typed-custom-fields` | Text, hidden/concealed, boolean, linked, TOTP, timestamp and unfamiliar types; record exact value, destination type/concealment and disclosed transformation/loss |
| `favorites-status-times` | Favorite, archive/trash state, creation/revision times and lexical/time-unit changes; distinguish absent destination behavior from carried bytes |
| `containers-selection` | Two vaults/folders with overlapping local item IDs; test whole-export default and intersecting item/vault/folder/kind filters in source order; observe disclosed relationship loss |
| `unknown-fields-metadata` | Unfamiliar scalar/empty-object/empty-array fields and root metadata all receive dispositions and exact review locations; omission is never counted as native migration |
| `files-passkeys` | Synthetic attachment/icon members and passkey payloads receive explicit loss review; recovery preserves the whole original, with no claim that destination attachments/passkeys function |
| `ssh-key-profile` | Ed25519 across all provider directions; RSA 2048/3072/4096-bit Bitwarden ↔ Proton and 1PUX → Bitwarden/Proton; check private/public/fingerprint consistency, exact retained strings or disclosed representation changes; native acceptance/authentication remain separate |
| `ssh-sections-fingerprint` | Bitwarden fingerprint relocates to a hidden Proton section; Proton → Bitwarden derives its required native fingerprint without interpreting arbitrary labels; text/hidden sections relocate exactly while grouping/TOTP/timestamp/unknown fields require loss review |
| `unsupported-record` | Unsupported SSH profile/route, alias, unknown type or attachment-only unsupported item blocks selected conversion; deliberate exclusion is visible and independent `recovery-save` retains the original |
| `bounded-large-fields` | Long synthetic fields and realistic item counts; converter/provider rejection or truncation recorded separately; no universal plaintext limit inferred |
| `browser-schema` | Native Chrome/Firefox/Safari column sets, quoted commas/quotes and embedded CRLF, optional unfamiliar columns, generated title or OTP field issues as applicable |
| `password-protected-input` | Native synthetic Bitwarden PBKDF2/Argon2id or admitted Proton encrypted export unlocks with exact password; wrong-password/tampered inputs produce no successful conversion |
| `recovery-original` | Whole original bytes, including excluded records and archive members, recover with the saved key; wrong key/truncation/tampering produces no successful restored artifact |

For provider duplicate candidates, confirm `exact_provider_content_v1` flags
equal complete native item content within the same vault/folder, ignoring only
well-typed native item identity and creation/update fields documented in the
README. A password-only change must remain distinct; unknown fields, array
order, concealment, relationships and absent/null/empty distinctions must
participate. The fixed `provider_duplicate_candidates_exact_content_only`
caveat discloses the conservative scope; unflagged items are not proven unique.
For browser fixtures, exact title/URL/username (Chrome/Safari) or URL/username
(Firefox) candidates can include different passwords. In every case all source
records and selected multiplicity must survive conversion without merging.

## Run each destination test

1. Build or extract the exact reviewed candidate. Record `version --json` and
   `formats --json`. Public output is enabled for Linux, macOS and Windows in
   the candidate. Native macOS/Windows privacy and public CLI journeys passed
   on both architectures; the documented Windows PowerShell setup passed on
   both architectures under the CI runner account. Record the exact build's
   evidence separately from provider import acceptance.
   Prepare a suitable private parent using the
   [native output journey](native-output-journey.md). You can manually
   transfer a synthetic successful artifact to a native destination app on
   another platform; that tests its importer, not that platform's writer.
2. Create the original synthetic source and independent local expectation
   table. If using encrypted input, preserve the original and password locally.
   Inspect it, then plan the route with the intended filters.
3. Create a private existing output parent. Optionally create a separate recovery
   key with `recovery-key` and use `--recovery-key-file` on conversion. Read the
   exact field/metadata loss review and current approval instruction. Enter the
   required review/issue IDs in the same process.
4. Require exit 0 and a successful completion receipt. Read back the successful
   artifact and check its independent local expectations. A failed job's partial
   or final file is not an import-qualified artifact.
5. Manually import that artifact using the destination's native option in the
   route table. Record accepted/rejected counts and only a sanitized provider
   outcome. If the app rejects the generated file, stop that case and record
   `rejected`; do not silently rewrite or hand-repair the file and qualify the
   original converter output from the repaired result.
6. Inspect types, exact supported values, duplicate counts, concealment and
   behavior in the destination application. Record every change from the
   independent expectations and whether preflight warned accurately.
7. Manually re-export the synthetic destination into its admitted native source
   format. Run `compare` with the original, target, supplied re-export and the
   same filters used for conversion. Example paths below are synthetic:

   ```sh
   ./pwmigrate-go compare --input "synthetic original.json" --from bitwarden-json --to onepassword-1pux --destination "synthetic destination.1pux" --select 1,3 --json
   ```

   Supply export passwords locally when requested. With `--password-stdin`,
   provide one line per encrypted input in source-then-destination order; add
   `--password-json` for literal password CR/LF. Never place passwords or age
   secret keys in argv, logs or the evidence report.
8. Assess matched/missing/unexpected counts, duplicate multiplicity, ambiguous
   groups and unobservable fields alongside the independent local checks.
   `destination_import_verified:false` is expected: compare only observes the
   supplied file. A semantic match does not prove an import occurred, that an
   excluded item was absent, or that a credential/passkey works.
9. If recovery was selected, use `recover --key-file` into a new private parent
   and compare its original bytes locally. Record equality only as a safe
   outcome; do not publish source-derived hashes. Test a wrong key and a
   mutated/truncated ciphertext on synthetic data. A bad recovery must produce
   no successful restoration receipt. Keep exact-byte recovery separate from
   importer acceptance.
10. Record a verdict for this route/profile/environment and the cases actually
    tested. Cleanup of the disposable vault and local plaintext is a user
    action. Failed jobs can retain private artifacts; SSD/snapshot secure
    erasure and perfect memory clearing are not guaranteed.

## Destination-specific observations

**Bitwarden:** choose **Bitwarden JSON**, not the foreign-provider importer for
the original source. Check blank-name replacement, blank-note/empty-credential
null or absence, removed empty URIs, duplicate retention and the sampled
blank-name/password batch rejection. Check custom type/concealment, item counts
and field/batch limits on the actual client/server route. Source research found
conflicting 7,000/40,000 count limits across versions; do not infer acceptance
from the public maximum alone.

**1Password:** choose the native **1PUX** import route for converter output.
Record created vaults, account permission limits, categories, fields, notes,
favorites and duplicate retention. Generated common account/vault placeholders
are structural destination data, not preserved source identity. The native
Bitwarden import option has different requirements (password-protected JSON,
documented Argon2 restriction); it is not the converter's 1PUX qualification
route. 1PUX desktop export omits passkeys, so no post-import passkey conclusion
follows from absent re-export data.

**Proton:** choose its own **Proton Pass ZIP** import route for converter output.
Check separate email/username values, TOTP text, URI matching and both legacy
URLs/autofillUrls. Record favorite loss even when `pinned` appears in generated
JSON, since the researched importer does not reconstruct it. Check folder and
vault metadata loss, new UUIDs/vaults, trash/timestamps, typed extras and actual
card-expiry interpretation. Unsupported alias ownership and passkey behavior
remain separate from accepting logins/notes/cards/identities/SSH keys.

For SSH, create independent synthetic keys in native applications and test each
admitted direction and key size. Bitwarden ↔ Proton permits Ed25519 and RSA
2048/3072/4096-bit pairs; Ed25519 also permits Proton ↔ 1PUX through Bitwarden;
RSA 1PUX → Proton is admitted while Bitwarden/Proton RSA → 1PUX stays blocked.
Verify exact OpenSSH/private/public strings where promised, and mathematical
key consistency separately when PKCS#8/PKCS#1 becomes OpenSSH. Compare the exact
source fingerprint's disclosed hidden-field relocation and supported custom
section values without interpreting arbitrary labels as native metadata.
Record grouping and unsupported section-type loss, and original representations
that the re-export cannot observe. Then use a native client/integration against
a disposable SSH server you own if qualifying authentication; accepting a key
item or matching a supplied re-export does not prove a working SSH login. Never
publish private keys, public-key text or source-derived fingerprints.

## Safe result template

```text
date:
converter version / public source commit / OS / architecture:
source app/version/platform / declared format / encryption profile:
destination app/version/platform/server / native import option:
versioned route profile:
fixed cases attempted:
local artifact validation outcome:
native import accepted / rejected counts:
observed discrepancies by fixed case and field ordinal:
duplicate multiplicity / ambiguous comparisons / unobservable fields:
preflight disclosure coverage:
whole-original recovery outcome, separately:
native writer evidence, separately:
remaining gaps:
verdict: unverified | rejected | qualified for recorded cases and environment
```

No actual result is filled in here. Qualification claims must link a completed
sanitized result for the exact claimed profile/environment. Unexpected
changes require a fix or explicit reviewed limitation and requalification;
acknowledgment is not proof of preservation. Provider qualification alone does
not authorize production migration, release/tag creation or stable promotion.
