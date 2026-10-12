# First provider pilot: 1Password 1PUX → Bitwarden

Status: **native import and re-export NOT RUN**. This pilot uses seven already
prepared synthetic records from the `v1.0.0-rc.2` default qualification kit.
The original 1PUX was independently authored from the documented schema; it
was not exported by the 1Password application. The pilot tests Bitwarden's
importer for `onepassword-1pux-to-bitwarden-json-v1` and the cases below.

The prepared candidate is `v1.0.0-rc.2`, commit
`4c1d4edef052a39bf8d4954cf10b6322706f09bd`. Its existing manifest records seven
items and 55 passing local field checks for this route. That is local mapping
evidence; the Bitwarden account steps belong to the user.

1. **Find the prepared files and keep them private.** The session workspace
   already contains these files; no regeneration or conversion is needed:

   - Import file:
     `/workspace/artifacts/pwmigrate/qualification-1.0.0-rc.2/default/artifacts/onepassword-1pux-to-bitwarden-json/job-48687cfb9cfbfc4ae06ceef586c4ae72/bitwarden.json`
   - Original source for comparison:
     `/workspace/artifacts/pwmigrate/qualification-1.0.0-rc.2/default/sources/onepassword-1pux.1pux`
   - Local exact expectations:
     `/workspace/artifacts/pwmigrate/qualification-1.0.0-rc.2/default/private-expectations.json`,
     under `routes` → `onepassword-1pux-to-bitwarden-json`.

   The kit directories are `0700` and these files are `0600`. If Bitwarden runs
   on another computer, transfer the synthetic files into a new private local
   folder with the equivalent permissions for that platform. Keep exact values
   and re-exports local. Use the
   [native directory instructions](native-output-journey.md) where needed.

2. **Read the loss caveats before importing.** The converter discloses omitted
   provider/account/vault metadata and field representation changes; this
   small pilot does not cover every 1PUX field. The Bitwarden
   [primary-source importer review](provider-format-evidence.md#bitwarden-custom-json)
   also identifies downstream behavior: native IDs and relationships are
   rebuilt, blank names and whitespace-only notes can change, empty credentials
   can become null/absent, empty URIs can be removed, and password history can be
   truncated. These are known loss caveats, not observed results from this
   pilot. An acknowledged caveat still needs assessment when it occurs.

3. **Import once into a disposable, empty Bitwarden account/vault.** Record the
   Bitwarden app or web-vault version, server/self-hosted version if known,
   operating system and date. Use its native **Bitwarden JSON** import option
   and select the prepared `bitwarden.json` from step 1. A personal test account
   containing no real items makes the count unambiguous. Start with zero items;
   do not repeat the import in the same vault. If the file is rejected, record
   `rejected` and a sanitized outcome, then stop. Preserve the original file;
   hand-editing it would test a different artifact.

4. **Require seven imported items and check them locally.** Expect four logins,
   one secure note, one card and one identity. Open the route's private
   expectations alongside the app. These fixed case IDs refer to source
   ordinals, not labels that Bitwarden must display:

   | Source ordinal | Fixed case ID | Local observation |
   | --- | --- | --- |
   | 1 | `login-basic` | Exact username, password, URLs, notes and custom fields |
   | 2 | `note-basic` | Secure-note type, exact multiline notes and custom fields |
   | 3 | `card-basic` | Card type; exact cardholder, number, verification code and route-specific month/year representation |
   | 4 | `identity-basic` | Identity type; separately named identity values remain exact |
   | 5 | `credential-whitespace` | Leading/trailing spaces, tabs, CR/LF/CRLF and Unicode spelling remain exact in the expected fields |
   | 6 | `duplicate-identical` | A second copy of ordinal 1 survives as a separate item |
   | 7 | `duplicate-password` | A third lookalike login survives with its distinct expected password |

   Check custom-field values, order/multiplicity and text versus concealed
   types against the route expectations. A hidden value must retain its hidden
   type. Do not trim strings or normalize Unicode to make a check pass. The
   app's visual display may hide whitespace; check the decoded re-export in
   step 6 before recording equality. Identical cases 1 and 6 need multiplicity
   evidence; they cannot be distinguished by their equal contents. Bitwarden
   may reorder the export, so source ordinals are reference IDs, not a required
   destination order.

5. **Re-export only the synthetic destination as unencrypted JSON.** In
   Bitwarden's native export flow, choose **JSON** rather than CSV or a
   password-protected/account-restricted JSON option. Save the export into a
   new private local folder as `bitwarden-re-export.json`, and confirm it came
   from the seven-item test account/vault. The file is plaintext; keep the
   folder private and exclude it from Git and shared/cloud folders.

6. **Compare with the same candidate and assess the result.** On the session's
   Linux workspace, replace the destination placeholder with the local
   re-export path and run:

   ```sh
   /workspace/artifacts/pwmigrate/qualification-1.0.0-rc.2/pwmigrate-go compare \
     --input "/workspace/artifacts/pwmigrate/qualification-1.0.0-rc.2/default/sources/onepassword-1pux.1pux" \
     --from onepassword-1pux --to bitwarden-json \
     --destination "/path/to/private/pilot/bitwarden-re-export.json" --json
   ```

   On another computer, use that platform's `v1.0.0-rc.2` candidate from the
   same commit and the transferred original 1PUX path. The prepared workspace
   executable is Linux/amd64. This route used all seven records with no
   selection filters. Assess matched, missing and unexpected counts, duplicate
   multiplicity, ambiguous groups and unobservable fields alongside the local
   expectations. Confirm exact whitespace and the password variant from the
   decoded synthetic export without publishing their values. A successful
   command or matching count alone does not resolve an unknown or unobservable
   outcome. `destination_import_verified:false` is expected: the CLI compares
   supplied files and does not observe the account import or certify provider
   acceptance.

7. **Return a safe observation record.** Record the route/profile, candidate
   version/commit, app/server version, platform, date, native import outcome,
   attempted/accepted/rejected counts and observed item kinds. For the seven
   fixed case IDs, report `passed`, `changed`, `missing` or `unobservable` and
   any affected source record/field ordinal from the comparison. Include the
   identical-pair multiplicity, password-variant outcome, comparison counts,
   unresolved ambiguity and whether the loss caveats matched the observations.
   Share no passwords, custom labels/values, raw exports, screenshots containing
   values, real vault files or source-derived hashes. Keep a result
   `unverified` until the observations are assessed; any qualification applies
   only to these cases and this recorded Bitwarden environment. Native
   1Password source export behavior, other destinations and the broader
   [qualification checklist](provider-qualification.md) remain separate gates.
   Cleanup of the disposable account and private plaintext is the user's
   choice after assessment.
