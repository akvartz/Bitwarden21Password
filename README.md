# pwmigrate — universal password manager migration

`pwmigrate` is a command-line tool that migrates your vault between password
managers: it converts export files between the popular formats, verifies that
a file is well-formed before you import it, and tells you exactly which data
could — and could not — be carried over. It grew out of a simple
Bitwarden ↔ 1Password CSV converter and now aims at 100% migration of
everything a password manager holds: logins, secure notes, credit cards,
identities, TOTP seeds, custom fields, folders/tags — and passkeys where the
formats allow it.

Everything runs **locally and offline**. Your secrets are never sent
anywhere, and all field mapping is deterministic code — vault contents are
never fed to an LLM or any external service.

## Supported formats

| Format id         | Password manager                          | Import | Export | Passkeys |
|-------------------|-------------------------------------------|:------:|:------:|:--------:|
| `bitwarden-json`  | Bitwarden (unencrypted `.json` export)     | ✅ | ✅ | ✅ |
| `bitwarden-csv`   | Bitwarden CSV                              | ✅ | ✅ | — |
| `1password-csv`   | 1Password 8 CSV                            | ✅ | ✅ | — |
| `protonpass-json` | Proton Pass (`data.json` from export zip)  | ✅ | ✅ | ✅* |
| `protonpass-csv`  | Proton Pass CSV                            | ✅ | ✅ | — |
| `lastpass-csv`    | LastPass CSV                               | ✅ | ✅ | — |
| `chrome-csv`      | Chrome / Edge / Brave / Opera (Google PM)  | ✅ | ✅ | — |
| `firefox-csv`     | Firefox                                    | ✅ | ✅ | — |
| `apple-csv`       | Apple Passwords / Safari / iCloud Keychain | ✅ | ✅ | — |
| `keepassxc-csv`   | KeePassXC                                  | ✅ | ✅ | — |
| `dashlane-csv`    | Dashlane credentials CSV                   | ✅ | ✅ | — |
| `nordpass-csv`    | NordPass CSV                               | ✅ | ✅ | — |
| `keeper-csv`      | Keeper CSV (no header row)                 | ✅ | ✅ | — |
| `pwmigrate-json`  | pwmigrate canonical JSON (lossless)        | ✅ | ✅ | ✅ |

\* Proton Pass passkeys round-trip losslessly Proton → Proton; see
[Passkeys](#passkeys) for the cross-provider story.

Friendly aliases work too: `--from bitwarden`, `--to proton`, `--from edge`,
`--from safari`, `--from keepass`, …

## Installation

Requires Rust (stable). From the repository root:

```sh
cargo build --release
# binary at ./target/release/pwmigrate
```

## Usage

### Convert

```sh
# Source format is auto-detected; only the target is required.
pwmigrate convert -i bitwarden-export.json -o proton.json --to protonpass-json

# Explicit source format (required for Keeper, which has no CSV header):
pwmigrate convert -i keeper.csv --from keeper-csv -o out.csv --to 1password-csv

# Convert and run content validation in one go:
pwmigrate convert -i export.csv --to bitwarden-csv -o out.csv --verify
```

Every conversion prints a **migration report**: which fields were relocated
(e.g. custom fields folded into notes), which were dropped, and which
passkeys need re-registering. Nothing is dropped silently.

### Verify

Checks that a file parses as its format, that required columns/structure are
present, and sanity-checks the contents (logins without passwords, malformed
URLs, invalid TOTP secrets, duplicate entries, card numbers failing the Luhn
checksum, passkeys missing key material):

```sh
pwmigrate verify -i export.csv
```

Exit code 0 = OK (warnings possible), 2 = the file is not a valid export.

### Inspect

Summarizes what an export contains without printing any secrets:

```sh
pwmigrate inspect -i data.json
```

### List formats

```sh
pwmigrate formats
```

## How data is preserved

All conversions go through a canonical internal model (logins, secure notes,
cards, identities, custom fields, tags, folders, timestamps, passkeys). When
the **target format can't hold a piece of data**, pwmigrate:

1. keeps it as a proper custom field if the target supports custom fields;
2. otherwise appends it to the item's notes in a delimited block:

   ```
   ---- pwmigrate extras ----
   folder: Work
   totp: JBSWY3DPEHPK3PXP
   employee id: 4711
   ```

3. and reports what it did.

When pwmigrate later imports a file containing such a block, it parses it
back into structured data — so migrating Bitwarden → Chrome → Bitwarden
restores folders, TOTP seeds and custom fields instead of leaving them as
note text. Custom fields with secret-looking names (PIN, CVV, recovery code,
API key, …) are automatically marked as concealed/hidden in formats that
support it.

For a lossless intermediate or backup, use `--to pwmigrate-json`: it dumps
the full canonical model, including passkey provider blobs.

## Passkeys

Passkey support in export formats is still young, and the industry-wide
[FIDO Credential Exchange Format](https://fidoalliance.org/specifications-credential-exchange-specifications/)
is not broadly deployed yet. What pwmigrate does today:

- **Bitwarden JSON** stores passkeys with a portable PKCS#8 private key
  (`fido2Credentials`). pwmigrate imports and exports these fully —
  Bitwarden → Bitwarden migrations keep passkeys working.
- **Proton Pass JSON** stores passkeys with the private key wrapped in
  Proton's internal encoding. pwmigrate preserves the record verbatim, so
  Proton → Proton round-trips are lossless.
- **Cross-provider** (e.g. Proton → Bitwarden): the private key encodings are
  not interoperable, so the passkey cannot be transplanted. pwmigrate carries
  the metadata, warns you per passkey, and lists the sites where you need to
  re-register after migrating. It will never silently pretend a passkey was
  migrated.
- CSV formats cannot hold passkeys at all; you get a warning per affected
  item.

`pwmigrate inspect` shows how many passkeys an export contains before you
migrate.

## Security notes

- Export files contain **all your secrets in plain text**. Create them on an
  encrypted disk, keep them off cloud-synced folders, and delete them
  (ideally with secure deletion) as soon as the migration is done.
- pwmigrate makes no network connections and stores nothing outside the
  output file you specify.
- Proton Pass exports arrive as a zip — extract it and pass the contained
  `data.json` to pwmigrate. For importing back into Proton Pass, zip the
  generated `data.json` or use the Bitwarden JSON output (Proton Pass can
  import Bitwarden JSON directly).

## Development

```sh
cargo test      # unit + round-trip integration tests
cargo clippy    # lints (kept warning-free)
```

The code is organized as a library (`src/lib.rs`) plus a thin CLI
(`src/main.rs`):

- `src/model.rs` — canonical vault model
- `src/formats/` — one importer/exporter module per format, plus detection
- `src/extras.rs` — misc-field folding/unfolding for lossy targets
- `src/verify.rs` — content validation
- `src/report.rs` — migration report plumbing

Adding a format means implementing `import(&str, &mut Report) -> Vault` and
`export(&Vault, &mut Report) -> String` in a new module and registering it in
`src/formats/mod.rs`.

## Roadmap

- 1Password 1PUX and Enpass/RoboForm JSON import
- KeePass 2 XML
- Reading Proton Pass export zips directly
- FIDO Credential Exchange Format (CXF) once providers ship it

## License

MIT — see [LICENSE](LICENSE).
