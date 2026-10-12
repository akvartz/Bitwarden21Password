# Synthetic Bitwarden import qualification

Status: **not run**. Local output validation and source-code research do not establish provider acceptance. This checklist is a later user-run acceptance gate, not authorization for account access by the converter or agent.

## Record the environment

Record converter source revision, profile (`chrome-to-bitwarden-json-v1`), Bitwarden client/version, server/self-hosted version where known, operating system, import route, and date. Record native Linux/macOS/Windows checks separately. No real vault contents, credentials, source paths or source-derived hashes belong in the evidence record.

Use a disposable, empty test vault containing no real credentials. Keep the original synthetic CSV and generated JSON available locally. The converter must never log in to the vault or call a provider API.

## Fixture matrix

Create synthetic Chrome CSV inputs with the required name,url,username,password headers. Add note and an unfamiliar custom column for the applicable cases. Quote embedded commas, quotation marks and newlines correctly.

| Case | Local JSON expectation | Destination observation to record |
|---|---|---|
| Ordinary login | Exact known cells, one URI | Item count/type and each field |
| Duplicate rows, different passwords | Two separate items | Multiplicity; never accept one merged item |
| Leading/trailing credential whitespace | Exact bytes including spaces | Compare username/password without trimming |
| CRLF, LF and Unicode in quoted cells | Exact decoded strings | Record normalization or retained values |
| Empty username/password/URL | Empty strings retained in JSON | Null/absent values and removed URI are known source-code risks |
| Blank/whitespace/BOM-only name | Original value retained | Placeholder name or import rejection |
| Missing note vs empty/blank note | Missing property vs exact string | Empty note may become null |
| Original unfamiliar label with spaces/case | Exact label and value, hidden custom field type1 | Label, type and value retained |
| Empty unfamiliar value | Explicit empty string | Empty vs null/absent |
| Legacy converter marker in ordinary notes | Literal notes preserved | No metadata decoding |
| Optional selection | Selected records in source order | Only selected items, correct multiplicity |
| Long synthetic fields / large item batch | No converter truncation; bounds may reject before output | Provider-specific rejection, limits or truncation; never infer a universal plaintext cap |

Bitwarden source research found downstream changes even when generated JSON is exact. Required issue acknowledgments describe those risks; they are not proof of acceptance. Do not count native and relocated fields as successfully imported until the destination observation supports it.

## Procedure

1. Build the reviewed converter with the existing pinned toolchain. Keep the test output parent owned by the current user and not writable by others.
2. Inspect and plan the synthetic fixture. Check total/selected/excluded counts and duplicates.
3. Run convert, read the review, and enter exactly the requested issue acknowledgments. A nonzero exit or missing completion receipt means the job is not qualified; do not import a leftover partial or final artifact from that job.
4. Check the successful JSON locally against the independent fixture expectations. This is local evidence only.
5. Manually import the successful file using Bitwarden's documented Bitwarden JSON import route into the empty disposable vault.
6. Record acceptance or the provider's non-sensitive error. Inspect item counts, hidden field types, exact values and duplicate multiplicity. Do not trim/canonicalize values to make comparisons pass.
7. Manually re-export the synthetic destination if supported and compare semantic values plus multiplicity, distinguishing absent/null/empty and unavailable fields. Current converter does not yet automate destination comparison.
8. Record each discrepancy and whether the preflight issue correctly warned about it. Fix/qualify the specific route/profile; never label all password-manager formats qualified from this test.

No automatic source deletion, live-account migration, release, or claim of working passkey transfer is part of this procedure. Cleanup of the disposable vault and local plaintext fixtures is a user action. Failed converter jobs can retain private artifacts; secure erasure is not guaranteed.

## Current evidence sources

- [Bitwarden custom import documentation](https://bitwarden.com/help/condition-bitwarden-import/).
- [Bitwarden clients source snapshot](https://github.com/bitwarden/clients/tree/df9641824436b65207f393d35b8d07225129797b), checked 2026-10-11. Source behavior is not an end-to-end import test.
- [Importer cleanup](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/base-importer.ts#L312), [credential and URI handling](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/vault/models/view/login.view.ts#L125), and [sampled rejection guard](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/services/import.service.ts#L193).
- [Cloud individual-import count gate](https://github.com/bitwarden/server/blob/5e68c1e65dd5ea476c3a00283b2a2ba575574c1d/src/Api/Tools/Controllers/ImportCiphersController.cs#L49): inspected source rejects over 7,000 items, while [help](https://bitwarden.com/help/import-data/#file-limits) currently states 40,000. Record actual version/route behavior. Encrypted field limits are version-dependent and are not plaintext-size guarantees.
- [M2 implementation design](../superpowers/specs/2026-10-11-protected-export.md).

Result template: environment; fixture cases attempted; exact accepted/rejected counts; observed changes by fixed case/field ordinal; preflight issue coverage; remaining gaps; verdict (`unverified`, `rejected`, or `qualified for the recorded cases and environment`).
