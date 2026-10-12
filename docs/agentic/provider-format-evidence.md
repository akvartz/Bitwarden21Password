# Provider format evidence

Checked 2026-10-12, America/New_York. This packet contains public format literals and independently reviewed provider behavior. It contains no vault data or source-derived fingerprints. Public repository revisions identify source snapshots; they are not provider-import certification. No dependencies, tools, or accounts were installed or acquired.

## Evidence and release claims

The highest priority route is Bitwarden ↔ 1Password. Generated files remain experimental until a synthetic import is recorded with the destination app version and platform. Local validation and self-roundtrips do not establish provider acceptance, and retaining passkey payloads does not establish working authentication.

Current primary documentation was fetched with Firecrawl. GitHub HTML identified the current main revisions, and allowed raw source fetches supplied exact types and importer behavior:

- Bitwarden clients: `df9641824436b65207f393d35b8d07225129797b`.
- Proton WebClients: `d70c6131012876da970d08f81fdcbb89723a88f1`.

The cloud proxy denied `api.github.com` with HTTP 403. No policy was changed or bypassed; primary source was read from the separately allowed `github.com` and `raw.githubusercontent.com` hosts. Source links below use pinned revisions.

## 1Password 1PUX v3

Primary documentation: [1PUX format](https://support.1password.com/1pux-format/), [export](https://support.1password.com/export/), [import](https://support.1password.com/import/), [Bitwarden importer](https://support.1password.com/import-bitwarden/).

The documented archive is ZIP with root files `export.attributes`, `export.data`, and an optional `files/` directory. `export.attributes` has these exact format literals:

```json
{"version":3,"description":"1Password Unencrypted Export","createdAt":0}
```

`createdAt` is Unix time; the zero above is only a synthetic skeleton. `export.data` has the structural tree `accounts[] → {attrs,vaults[]} → {attrs,items[]}`. Reject unsupported attributes versions; do not use file extension alone as proof of the format.

The documentation describes these attributes, but does not publish a formal exhaustive required-field JSON Schema for generated-file import. Its examples are evidence of spelling and shape, not a guarantee that omitted attributes are accepted by 1Password. The proprietary native importer was not available for source review. The independently reviewed Bitwarden types declare `overview.subtitle`, `overview.title`, and `overview.url` as required strings, all five vault attributes including `avatar` as required strings, and the common details members as optional. Canonical generated output should include those declared common strings; empty placeholders are synthetic structural data, not claims of source metadata fidelity.

| Object | Independently documented keys |
| --- | --- |
| Account `attrs` | `accountName`, `name`, `avatar`, `email`, `uuid`, `domain` |
| Vault `attrs` | `uuid`, `desc`, `avatar`, `name`, `type` |
| Vault type | `P` personal, `E` everyone/shared, `U` user-created |
| Item | `uuid`, `favIndex`, `createdAt`, `updatedAt`, `state`, `categoryUuid`, `overview`, `details` |
| Item state | `active`, `archived` |
| `overview` | `subtitle`, `title`, `url`, `urls:[{label,url}]`, `tags:string[]` |
| `details` | `loginFields`, `notesPlain`, `sections`, `passwordHistory`; item-specific properties can also occur |
| Section | `title`, `name`, `fields[]` |
| Section field | `title`, `id`, `value`; common extra attributes are listed below |
| Password history entry | `value:string`, `time:Unix-seconds` |
| Document attributes | `fileName`, `documentId`, `decryptedSize` |

Item UUID is unique within a vault, not globally. Preserve vault membership and do not globally deduplicate by item UUID. `favIndex > 0` means favorite in the public specification.

There is a documentation inconsistency: prose calls the login HTML field type `type`, while the official page's JSON example uses `fieldType`. The pinned Bitwarden 1PUX types and importer consistently use `fieldType`; a generated writer should use this independently evidenced literal. `loginFields[].value` is documented as a string, including empty string. Native acceptance of null is not documented. `designation` is `username` or `password`, with at most one of each per item.

### Exact types independently corroborated by importer source

[Bitwarden 1PUX types](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/onepassword/types/onepassword-1pux-importer-types.ts), [Bitwarden 1PUX importer](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/onepassword/onepassword-1pux-importer.ts), [Proton 1PUX types](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/1password/1pux.types.ts).

| Category ID | Category |
| --- | --- |
| `001` | Login |
| `002` | Credit card |
| `003` | Secure note |
| `004` | Identity |
| `005` | Password |
| `006` | Document |
| `100` | Software license |
| `101` | Bank account |
| `102` | Database |
| `103` | Driver's license |
| `104` | Outdoor license |
| `105` | Membership |
| `106` | Passport |
| `107` | Rewards program |
| `108` | Social security number |
| `109` | Wireless router |
| `110` | Server |
| `111` | Email account |
| `112` | API credential |
| `113` | Medical record |
| `114` | SSH key |

`loginFields` uses `{value,id,name,fieldType,designation?}`. Independently sourced `fieldType` literals are `T`, `E`, `U`, `N`, `P`, `A`, `TEL`, and `C` (checkbox). The public documentation notes its HTML-type list is not exhaustive.

Section `value` is a tagged object, with independently declared tags `totp`, `date`, `string`, `concealed`, `email`, `phone`, `menu`, `gender`, `monthYear`, `url`, `address`, `creditCardType`, `creditCardNumber`, `reference`, and `sshKey`. Preserve unknown tags and multiple tags; do not select the first object key as a fidelity rule.

- `date` is numeric Unix seconds; `monthYear` is a number. Card expiry interpretation is `YYYYMM` in the independently reviewed importer.
- `email` is `{email_address:string,provider:string|null}`.
- `address` is `{street,city,country,zip,state}`, with string values.
- `sshKey` is `{privateKey,metadata:{privateKey,publicKey,fingerprint,keyType}}`.
- Common field flags/attributes are `guarded`, `multiline`, `dontGenerate`, `placeholder`, `inputTraits:{keyboard,correction,capitalization}`, and `clipboardFilter`. The official example also contains `indexAtSource`; preserve it when present.
- Proton's reviewed 1PUX source independently handles `value.file:{documentId?,fileName}`. File objects are separate from text custom fields.

Card template IDs are `ccnum`, `cvv`, `cardholder`, `expiry`, and `type`; Proton independently declares `validFrom` and `pin` as well. The Bitwarden synthetic [credit-card fixture](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/spec-data/onepassword-1pux/credit-card.ts) verifies `value.creditCardType:"discover"`. No exhaustive primary enumeration of credit-card-type literals was found. Do not infer all brand spellings from that one literal.

Independently evidenced identity template IDs map as follows:

| 1PUX field | Bitwarden field |
| --- | --- |
| `firstname` | `firstName` |
| `initial` | `middleName` |
| `lastname` | `lastName` |
| `defphone` | `phone` |
| `company` | `company` |
| `email`, or `value.email.email_address` | `email` |
| `username` | `username` |
| `value.address.street` | `address1` |
| `value.address.city` | `city` |
| `value.address.state` | `state` |
| `value.address.zip` | `postalCode` |
| `value.address.country` | `country` |

For fields without independently evidenced equivalents, exact custom relocation is safer than claiming native mapping. Never concatenate Bitwarden `address1/2/3` or split arbitrary full names without accounting for the transformation. Preserve lexical expiry components when integer `monthYear` cannot represent them exactly.

### Importer assumptions and limitations

1Password documents 1PUX import in Mac, Windows, Linux, iOS, and Android apps. Accounts lacking permission to create vaults can only import items from the Employee/Personal/Private vault in the file. Actual acceptance of generated 1PUX remains untested here.

1Password desktop exports omit passkeys. iOS and Android Credential Exchange are separate native workflows that can include passkeys. 1PUX carries Documents, attachments, and icons in `files/`; the documented filename prefix is `documentId` followed by `___` and the original name. Enforce exact/unique ownership and bounded safe archive reads. Export format coverage does not prove native attachment import behavior for every generated shape.

The reviewed Bitwarden 1PUX importer assumes `accounts[0]`, then loops its vaults. It is not an exact-preservation oracle: only `favIndex === 1` becomes favorite; it uses the first tag as a capitalized/trimmed folder; notes receive newline normalization and `trimEnd`; archive state gets the import time; date values can be rendered as UTC text; unsupported categories can fall through its login initialization. Generated Bitwarden JSON can avoid several of those upstream conversions, but still needs independent acceptance testing.

SSH import in the reviewed Bitwarden 1PUX importer uses `value.sshKey.metadata.privateKey`, then the maintained provider SDK converts PKCS#8 into OpenSSH. The source explicitly says the other `sshKey.privateKey` representation is inconsistent. A direct copy of either representation does not establish a working SSH key.

1Password's native Bitwarden import route accepts password-protected encrypted JSON, and documents plaintext/account-restricted JSON as unsupported. Argon2id-encrypted exports currently produce an error; its help page advises switching Bitwarden to PBKDF2. It imports logins, cards, identities and secure notes, excluding passkeys and shared-collection items. This is a useful native route recommendation when those limits fit, not a reason to silently alter the account's KDF.

## Bitwarden custom JSON

Primary documentation: [custom import](https://bitwarden.com/help/condition-bitwarden-import/), [export](https://bitwarden.com/help/export-your-data/), [1Password import](https://bitwarden.com/help/import-from-1password/).

Field names are case-sensitive. JSON is UTF-8 plaintext. Unlike 1PUX, the reviewed ordinary JSON export has no independent schema-version integer. Identify directional profile provenance with the pinned public provider revision in documentation; public reports must not carry vault fingerprints.

The documentation's minimum item shapes require `type`, `name`, and the matching item object: type 1 with `login:{}`, 2 with `secureNote:{}`, 3 with `card:{}`, or 4 with `identity:{}`. Most other keys are optional. Canonical generated individual output should explicitly include `encrypted:false`, `folders:[]`, and `items:[]`; source export types require those fields, although the native import type guard accepts absent `encrypted` and absent folders. Do not copy invalid trailing commas from rendered help-page examples. Organization `collectionIds` is an array in the correct existing-collection example, despite an inconsistent earlier rendered example using a string.

[Export envelope types](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts), [JSON importer](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/bitwarden/bitwarden-json-importer.ts), [cipher export](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/cipher.export.ts).

| Scope/type | Exact source keys |
| --- | --- |
| Individual root | `encrypted:false`, `folders:[{id,name}]`, `items:[]` |
| Organization root | `encrypted:false`, `collections:[{id,organizationId,name,externalId}]`, `items:[]` |
| Item common | `id`, `organizationId`, `folderId`, `collectionIds`, `type`, `name`, `notes`, `favorite`, `reprompt`, `fields`, `passwordHistory`, `creationDate`, `revisionDate`, `deletedDate`, `archivedDate` |
| Login | `uris:[{uri,match}]`, `username`, `password`, `totp`, `fido2Credentials` |
| Secure note | `type` (generic is 0) |
| Card | `cardholderName`, `brand`, `number`, `expMonth`, `expYear`, `code` |
| Identity | `title`, `firstName`, `middleName`, `lastName`, `address1`, `address2`, `address3`, `city`, `state`, `postalCode`, `country`, `company`, `email`, `phone`, `ssn`, `username`, `passportNumber`, `licenseNumber` |
| SSH key | `privateKey`, `publicKey`, `keyFingerprint` |
| Custom field | `name`, `value`, `type`, `linkedId?` |
| Password history | `password`, `lastUsedDate` |

Rich-model sources: [login](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/login.export.ts), [card](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/card.export.ts), [identity](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/identity.export.ts), [SSH](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/ssh-key.export.ts), [custom fields](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/field.export.ts).

Custom-field types are exactly 0 text, 1 hidden, 2 boolean, 3 linked, from the [enum](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/vault/enums/field-type.enum.ts). Linked fields have behavior as well as a value; turning them into text is a transformation, not native migration.

The current [cipher enum](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/vault/enums/cipher-type.ts) also declares 5 SSH key, 6 bank account, 7 driver's license, and 8 passport. Those new source types are beyond the original accepted type 1–5 projections. Preserve them as unfamiliar types until separately implemented; never reinterpret them as logins. Native SSH JSON conversion requires nonblank private key, public key, and fingerprint by default; an empty object is not a valid minimum for SSH.

The native JSON importer clears item IDs, organization IDs, collection IDs and encryption keys, rebuilds folder/collection relationships, and truncates password history to the first five entries. Its [base cleanup](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/base-importer.ts) replaces blank item names and whitespace-only notes. Those observable changes limit comparison claims even when a generated JSON field is structurally supported.

Bitwarden JSON includes passkey payloads. Exact [FIDO2 export keys](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/common/src/models/export/fido2-credential.export.ts) are `credentialId`, `keyType`, `keyAlgorithm`, `keyCurve`, `keyValue`, `rpId`, `userHandle`, `userName`, `counter`, `rpName`, `userDisplayName`, `discoverable`, `creationDate`. `counter` and `discoverable` are exported as strings. Do not translate cross-provider passkeys without independent key-format and authentication tests.

Attachments must be uploaded separately in custom JSON import. Export ZIP attachment ownership can be ambiguous because provider names are sanitized without an attachment-ID manifest; do not guess the owning item. Individual exports exclude organization data. Exports omit trash and Sends. Bitwarden warns that pre-2024.3.1 passkey counters can become stale for long-term backups.

## Proton unencrypted JSON/ZIP source profile

Primary documentation: [export and reimport](https://proton.me/support/pass-export). It documents unencrypted ZIP, ZIP containing PGP-encrypted JSON, and CSV; native reimport selects Proton Pass and consumes ZIP. Browser extension, web and Windows export/import are documented; mobile export is not documented as supported here.

[Archive source](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/export/archive.ts), [export types](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/export/types.ts), [export selector](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/store/selectors/export.ts), [native JSON reader](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/protonpass/protonpass.json.reader.ts), [native ZIP reader](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/protonpass/protonpass.zip.reader.ts).

Archive entry paths are exactly `Proton Pass/data.json`, `Proton Pass/data.pgp`, and `Proton Pass/files/<filename>`. The exporter creates an uncompressed ZIP. The encrypted option protects the JSON data entry; its separately streamed attachments remain unencrypted. Do not claim the entire ZIP is encrypted.

The export root is `{userId?:string,vaults:Record<string,ExportedVault>,version:string}`. `version` comes from `config.APP_VERSION`, not a numbered schema format. The reviewed [application changelog](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/applications/pass/CHANGELOG.md) begins with `Version 1.42.0`. A 1.42.0 source-based profile can be named and tested, but it is not a native-provider acceptance certificate. The native reader interprets versions below `1.18.0` differently: login `content.username` becomes `itemEmail`, and `itemUsername` is set empty.

Vault shape is `{name,description,display:{icon?,color?},folders?:[],items:[]}`. Folders are `{folderId,parentFolderId,name}`. Export selector includes owned vault shares only. Each exported item has `itemId`, `shareId`, `folderId`, `data`, `state`, `aliasEmail`, `contentFormatVersion`, `createTime`, `modifyTime`, `pinned`, `shareCount`, and `files:string[]`; undefined properties can be absent after JSON serialization. Exported items omit runtime `revision`, `revisionTime`, `lastUseTime` and `flags`.

[Item model](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/types/data/items.ts), [protobuf field names](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/types/protobuf/item-v1.ts), [enum literals](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/types/protobuf/item-v1.static.ts), [share content](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/types/data/shares.ts).

`data` is a deobfuscated object `{type,metadata:{name,note,itemUuid},content,extraFields,platformSpecific?}`. Exact item types include `login`, `note`, `alias`, `creditCard`, `identity`, `sshKey`, `wifi`, and `custom`. State enum is 1 active and 2 trashed. Unknown types must remain unknown in migration inventory.

| Type | Exact native content keys |
| --- | --- |
| Login | `itemEmail`, `itemUsername`, `password`, `urls:string[]`, `autofillUrls:[{url,mode}]`, `totpUri`, `passkeys:[]` |
| Note | Empty object |
| Credit card | `cardholderName`, `cardType`, `number`, `verificationNumber`, `expirationDate`, `pin` |
| SSH key | `privateKey`, `publicKey`, `sections:[{sectionName,sectionFields}]` |

Extra fields are `{fieldName,type,data}`. Exact type/data pairs are `text`/`{content:string}`, `hidden`/`{content:string}`, `totp`/`{totpUri:string}`, and `timestamp`/`{timestamp?:Timestamp}`. Do not treat all custom fields as text. Identity and SSH section fields use the deobfuscated extra-field shape in exports.

Identity native keys are `fullName`, `email`, `phoneNumber`, `firstName`, `middleName`, `lastName`, `birthdate`, `gender`, `extraPersonalDetails`, `organization`, `streetAddress`, `zipOrPostalCode`, `city`, `stateOrProvince`, `countryOrRegion`, `floor`, `county`, `extraAddressDetails`, `socialSecurityNumber`, `passportNumber`, `licenseNumber`, `website`, `xHandle`, `secondPhoneNumber`, `linkedin`, `reddit`, `facebook`, `yahoo`, `instagram`, `extraContactDetails`, `company`, `jobTitle`, `personalWebsite`, `workPhoneNumber`, `workEmail`, `extraWorkDetails`, and `extraSections`. The four `extra*Details` arrays contain extra fields; `extraSections` contains `{sectionName,sectionFields}` objects. None of these imply that arbitrary full names can be split exactly.

`CardType` is 0 unspecified, 1 other, 2 Visa, 3 Mastercard, 4 American Express. The generated protobuf comment says expiry `YYYY-MM`, but the operational Bitwarden importer and independent [importer test](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/bitwarden/bitwarden.reader.spec.ts) use `MMYYYY`. Record that source discrepancy; native generated-file testing is required before promising date fidelity.

Autofill modes are 0 Default, 1 Exact, 2 Never, 3 StartWith, 4 Pattern, 5 RegularExpression, 6 ExactPath. Current export writes all `autofillUrls` and duplicates only Default-mode entries in legacy `urls`. Native import prefers nonempty `autofillUrls` and falls back to `urls` as Default entries. Its sanitizer can reject or deduplicate malformed/unsupported entries. Copying URLs alone loses matching policies.

Native Proton reimport makes new vaults (`shareId:null`) and new item UUIDs; keeps trash state and create/modify times; resolves filenames through `Proton Pass/files/`; ignores aliases owned by a different account and skips existing aliases. In the reviewed JSON reader, exported folders are not rebuilt (`folders:[]`), and vault description/display, pinned status and share counts are not explicitly reconstructed. These provider behavior limits should be caveats and comparison gaps.

The [native JSON reader test](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/protonpass/protonpass.json.reader.spec.ts) independently uses `contentFormatVersion:1`. The reader does not consult the wrapper `contentFormatVersion`, `itemId` or `shareId` when rebuilding the import item; it overwrites `metadata.itemUuid`. Its [obfuscation step](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/items/item.obfuscation.ts) retains the native JSON TOTP string without the foreign-provider OTP parser/normalization. That does not establish that every TOTP string will function after import.

### Bitwarden ↔ Proton mappings and native importer limits

[Bitwarden importer](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/bitwarden/bitwarden.reader.ts), [mapping utilities](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/bitwarden/bitwarden.utils.ts), [import constructors](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/helpers/transformers.ts).

The native Bitwarden importer rejects encrypted JSON. Its login constructor initializes passkeys to empty. It decides whether Bitwarden's username is email with email validation, maps checkbox fields to text, ignores linked custom fields, merges identity address lines with spaces, and maps identity username to `xHandle`. Those conversions are not automatically pwmigrate policy.

Mappings supported by independently reviewed key names include login password↔password, TOTP↔totpUri, Bitwarden card code↔verificationNumber, identity phone↔phoneNumber, postalCode↔zipOrPostalCode, state↔stateOrProvince, country↔countryOrRegion, ssn↔socialSecurityNumber, and passport/license numbers by their exact names. Email and username remain distinct; if the destination only has one username slot, relocate one exact string with a disclosed issue. Do not reinterpret an arbitrary username as email.

Bitwarden URI matching maps in the reviewed Proton importer: base-domain/default→0, host→1, never→2, starts-with→3, regular-expression→5, exact→6. Pattern mode 4 has no evidenced Bitwarden equivalent. Android `androidapp://` URIs become platform allowed-app data in the native importer; they are not ordinary website URLs.

### Proton SSH projection and candidate mappings

The pinned Proton item model declares native `data.type:"sshKey"` with
`content:{privateKey:string,publicKey:string,sections:[{sectionName,sectionFields}]}`.
This is a native SSH item, not a login or a notes encoding. The reviewed
[Bitwarden reader](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/bitwarden/bitwarden.reader.ts#L93)
passes the raw private/public strings to
[the SSH import constructor](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/helpers/transformers.ts#L239).
The [mapping utility](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/import/providers/bitwarden/bitwarden.utils.ts#L135)
places Bitwarden `keyFingerprint` in section `Extra fields`, as a hidden field
named `Key fingerprint`, with its original string in `data.content`.
These are public schema/importer literals, not a claim that native import or
authentication has been run.

The candidate admits validated Ed25519 and RSA 2048/3072/4096-bit pairs for
Bitwarden ↔ Proton. Existing maintained, bounded SSH parsing checks supported
PEM material, public-key consistency and the Bitwarden source's required SHA256
fingerprint. Encrypted individual SSH keys and other key types/profiles remain
unsupported.

- **Bitwarden → Proton:** admitted unencrypted PKCS#8, RSA PKCS#1 and OpenSSH
  private strings, and the exact public text, are retained in native key fields.
  The exact source fingerprint relocates to the documented hidden section field;
  it does not become a native Proton fingerprint property. Source custom fields
  retain only their admitted/disclosed destination representations.
- **Proton → Bitwarden:** an admitted OpenSSH private string remains exact;
  PKCS#8/PKCS#1 is re-encoded as OpenSSH and receives a transformed disposition.
  The original private representation is consequently unobservable there. The
  required Bitwarden SHA256 fingerprint is derived privately from the validated
  key pair. Arbitrary section names/labels are never decoded as native
  fingerprint metadata.
- **SSH section fields:** admitted text/hidden values relocate to Bitwarden
  custom fields with exact original names, values and concealment. Section
  grouping labels remain unsupported; TOTP, timestamp and unfamiliar section
  types require explicit unsupported-field review. A recovered original can
  preserve them, but recovery does not count as their destination migration.
- **Composed routes:** Ed25519 works through the audited Bitwarden model in both
  Proton ↔ 1PUX directions. RSA 2048/3072/4096-bit 1PUX → Proton uses the admitted
  1PUX → Bitwarden source mapping. Bitwarden/Proton RSA → 1PUX is blocked pending
  an independently verified 1PUX writer `metadata.keyType` literal.

Generated-output pair validation and independent local key/field checks remain
separate from provider-native acceptance and SSH authentication. Every route is
experimental; native import/authentication qualification is **NOT RUN**.

## Encryption and recovery dependency gate

No implementation or provider acceptance is established by this dependency research. Provisioning is a prerequisite to independently reviewed crypto work; missing modules must not be replaced with invented primitives.

### Bitwarden password-protected export

[Password-protected importer](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.ts), [envelope](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/tools/export-vault-core/src/types/bitwarden-json-export-types.ts), [key derivation](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/legacy-crypto/src/services/default-key-generation.service.ts), [KDF config](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/legacy-crypto/src/models/kdf-config.ts), [KDF enum](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/legacy-crypto/src/enums/kdf-type.enum.ts).

Exact envelope: `encrypted:true`, `passwordProtected:true`, `salt:string`, `kdfIterations:number`, `kdfMemory?:number`, `kdfParallelism?:number`, `kdfType:number`, `encKeyValidation_DO_NOT_EDIT:string`, and `data:string`. KDF type 0 is PBKDF2-SHA256; 1 is Argon2id. Password and salt string arguments are UTF-8 encoded; export-key derivation stretches provider KDF material with HKDF-expand labels `enc` and `mac`, each 32 bytes. The current KDF work delegates to provider SDK code; this packet does not independently establish all SDK salt preprocessing or encryption internals. Read authoritative SDK source and use independent encrypted-export vectors before implementing those details. Do not base an implementation on default account settings, and reject unfamiliar KDF/envelope variants.

Go's maintained [`crypto/pbkdf2`](https://pkg.go.dev/crypto/pbkdf2) and `crypto/hkdf`, AES, HMAC and SHA-256 cover the PBKDF2 primitive needs on the provisioned modern Go toolchain. [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) supplies maintained Argon2id; memory units are KiB, while the Bitwarden config declares MiB, so a bounded reviewed conversion is necessary.

### Proton password-based OpenPGP

[Export crypto source](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/crypto/utils/export.ts) uses armored OpenPGP, `passwords:[passphrase]`, `s2kIterationCountByte:255`, and binary data. Its comment explicitly says Argon2 is a future change. Do not choose a newer writer profile merely because a library supports it; exact compatibility requires independent provider vectors. The outer ZIP's optional files are not protected by encryption of `data.pgp`.

Maintained high-level candidate: [`github.com/ProtonMail/gopenpgp/v3` v3.5.2](https://github.com/ProtonMail/gopenpgp/releases/tag/v3.5.2), released September 30, 2026. The [README](https://github.com/ProtonMail/gopenpgp/blob/v3.5.2/README.md) documents password encryption/decryption and explicit RFC4880/RFC9580 profiles. Its [manifest](https://github.com/ProtonMail/gopenpgp/blob/v3.5.2/go.mod) requires Go ≥1.23.0 and `go-crypto` v1.5.2, `go-mime`, and the transitive module graph.

Smaller low-level alternative: [`github.com/ProtonMail/go-crypto` v1.5.2](https://github.com/ProtonMail/go-crypto/blob/v1.5.2/go.mod). Its OpenPGP reader rejects unauthenticated messages by default and exposes a decompressed-message limit; the plaintext body must be fully read and integrity-checked before success. Choosing this lower-level API requires separate packet/KDF/resource and complete-stream review.

### Encrypted recovery

Candidate: [`filippo.io/age` v1.3.2](https://github.com/FiloSottile/age/releases/tag/v1.3.2), released August 29, 2026. The release adds hardening, including header and recipient-count limits. Its [manifest](https://github.com/FiloSottile/age/blob/v1.3.2/go.mod) has Go floor 1.25.0 and a release-build `toolchain go1.27.0` directive. Keep `GOTOOLCHAIN=local`; a dependency's suggested release toolchain is not permission to download one. Recovery still needs an encrypted manifest plus payload, a reader, independent CLI interoperability, and full-stream tamper/truncation tests. Prefer an explicit X25519 recovery identity as the first scoped profile over claiming every age plugin/recipient type.

### Historical provisioning request (resolved)

The user authorized fetching these pinned maintained dependencies on 2026-10-12.
They are now locked in go.mod/go.sum. Bitwarden PBKDF2/Argon2id, bounded Proton
OpenPGP, and age recovery writer/reader are implemented; see
[provider crypto evidence](../../internal/providercrypto/README.md),
[Proton crypto evidence](../../internal/providercrypto/proton.md), and
[recovery evidence](../../internal/recovery/README.md). Package tests and separate
independent/adversarial reviews pass. Native provider-export and destination
import qualification remain separate open gates. The request below records
the research basis, not a current missing dependency.

The smallest incremental bundle for Bitwarden Argon2id is a verified offline module cache/vendor tree for `golang.org/x/crypto` v0.58.0 and `golang.org/x/sys` v0.49.0. The [x/crypto manifest](https://github.com/golang/crypto/blob/v0.58.0/go.mod) has Go floor 1.26.0 and graph requirements x/net v0.60.0, x/term v0.47.0, x/text v0.43.0; a complete offline module graph may need those manifests even when their packages are not compiled.

For all accepted encryption goals, ask once for a reviewed offline dependency bundle covering these direct modules and their complete pinned transitive graph: x/crypto v0.58.0; gopenpgp/v3 v3.5.2 (or a deliberately reviewed go-crypto v1.5.2 alternative); age v1.3.2. Relevant manifests identify go-crypto v1.5.2, circl v1.6.3, go-mime, edwards25519 v1.2.0, hpke v0.4.0, nistec v0.0.4 and Go x/* modules; module version selection must reconcile the shared x/* requirements and verify checksums. Do not assume a list of direct modules is the entire offline build/test closure.

The user need not supply any real vault, password, recovery identity, account credentials, or account access. Separate external qualification can use new synthetic provider accounts/data and locally recorded app versions; source research alone leaves those gates open.
