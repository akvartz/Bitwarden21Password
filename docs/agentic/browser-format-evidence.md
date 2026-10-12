# Browser CSV format evidence

Checked 2026-10-12, America/New_York. Only public documentation/source literals
and synthetic fixtures were used. No actual browser export or provider import
was exercised. These profiles identify supported file schemas, not the browser
that produced an arbitrary matching CSV.

## Chrome-compatible CSV

Primary source:
[Chromium password_csv_writer.cc at revision 10ea04ff21714a3d35ec61364847890aacccde4e](https://github.com/chromium/chromium/blob/10ea04ff21714a3d35ec61364847890aacccde4e/components/password_manager/core/browser/export/password_csv_writer.cc).
The inspected source's `chrome/VERSION` is `157.0.8101.0`; this is a source
snapshot, not native qualification. Its exact current header is
`name,url,username,password,note`; `note` is emitted even when empty. The
declared compatible profile requires the first four fields and accepts optional
`note`, so four-column files remain supported without claiming that the current
Chromium exporter omits its note column.

The historical
[Chromium exporter at revision 636fe4f58d47fe231e86556c894d80fe08681eb6](https://github.com/chromium/chromium/blob/636fe4f58d47fe231e86556c894d80fe08681eb6/components/password_manager/core/browser/export/password_csv_writer.cc)
independently confirms the four-column spelling. The current exporter sorts rows
and expands affiliated domains into separate rows; Android URLs can be
`android://` facet URIs. Preserve supplied row multiplicity and URL text exactly.

Files exported by Chrome, Edge, or Brave are covered only when their schema
matches this compatible profile. No browser-specific Edge/Brave schema or native
export has been independently qualified, and matching the header does not
identify the browser. Unknown columns retain their exact original labels and
values as concealed custom fields.

## Firefox native CSV

Primary evidence: Mozilla's
[LoginExport.sys.mjs at revision e00a7636053d44c48b523c20b24fde9d3548062a](https://searchfox.org/firefox-main/rev/e00a7636053d44c48b523c20b24fde9d3548062a/toolkit/components/passwordmgr/LoginExport.sys.mjs)
and the
[login metadata interface at the same revision](https://raw.githubusercontent.com/mozilla-firefox/firefox/e00a7636053d44c48b523c20b24fde9d3548062a/toolkit/components/passwordmgr/nsILoginMetaInfo.idl).
The inspected revision is dated 2026-10-10 and belongs to the `160.0a1` nightly
source snapshot; this is source inspection, not native testing of that release.

The exact exporter header is:

```text
url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
```

The exporter writes UTF-8, CRLF record terminators, doubled quotes within quoted
cells, and empty cells for null/undefined values. The metadata interface defines
timestamps as Unix milliseconds; `timePasswordChanged` also covers username
changes. GUIDs need not have UUID syntax. The parser retains each cell as exact
text, including lexical timestamp representations and empty cells, without
converting numbers or validating GUIDs as UUIDs.

All nine headers are required for this profile. Reordering, ASCII case changes,
and whitespace around header labels are accepted for schema matching only;
original header labels and credential cells remain exact. Additional columns
remain concealed custom fields, including extras named `name`, `note`, `totp`,
`Title`, `Notes`, or `OTPAuth`. Firefox metadata is also retained as concealed
custom fields; native realm, form action, timestamp, or GUID behavior at the
destination is not established.

Firefox has no source title column. A generated destination title uses the exact
source URL and is disclosed separately; it does not increase source-field counts.
Suspected duplicates use the exact `(url, username)` tuple, never passwords;
all rows remain present even when their passwords or realm metadata differ.

## Safari password CSV

Primary evidence: Apple's
[Importing data exported from Safari](https://developer.apple.com/documentation/SafariServices/importing-data-exported-from-safari)
explicitly documents these six password CSV columns:

```text
Title,URL,Username,Password,Notes,OTPAuth
```

Apple documents `OTPAuth` as an `otpauth` URL. Its public example includes
`otpauth://totp?secret=ASDFA&algorithm=SHA1&digits=6&period=30`, without an account
path. Preserve the exact URI; do not insert a slash, add a label, decode/re-encode
query parameters, trim whitespace, or reinterpret arbitrary text as a TOTP
secret. This evidence establishes the documented source representation; it does
not establish that every destination app accepts every URI unchanged.

All six headers are required for this profile. Reordering, ASCII case changes,
and surrounding header whitespace are accepted for schema matching only.
`Title`, `Notes`, and `OTPAuth` project to title, notes, and TOTP slots only in
the Safari profile. Original labels and all cells remain exact. Alias collisions
such as both `Title` and `name`, `Notes` and `note`, or `OTPAuth` and `totp` are
rejected as duplicate headers. Additional unambiguous columns remain concealed
custom fields. Suspected duplicates use the exact `(title, url, username)` tuple;
password differences do not merge or remove records.

The current primary
[Apple Passwords CSV export documentation](https://support.apple.com/en-ie/guide/passwords/mchl35b12625/mac)
confirms CSV export but does not document its header schema. A Passwords export
matching the six-column Safari schema can be parsed under this profile; no claim
is made that every Passwords release emits that schema. Neither browser CSV has
a schema-version column. The JSON `schema_version` described elsewhere in Apple's
Safari export documentation concerns other Safari data, not this password CSV.
Safari's broader ZIP export and payment-card JSON are outside this CSV profile.

## Detection and exact parsing

Auto-detection requires exactly one complete known header schema: Chrome's
`name,url,username,password`, Firefox's nine columns, or Safari's six columns.
Unknown extras cannot create Safari aliases in another profile. Mixed schemas,
duplicate/empty headers, incomplete schemas, and malformed header CSV do not
select a browser adapter. `url,username,password` or the four-column
`Title,URL,Username,Password` header alone is insufficient. A JSON-looking custom
header does not override an otherwise complete, unique CSV schema.

CSV parsing shares the existing strict record parser. It retains embedded CRLF,
LF, bare CR, doubled quotes, trailing empty cells, duplicates, and whitespace in
credential values. Blank logical rows, uneven row lengths, stray/unclosed quotes,
and characters following a closing quote are rejected. Existing input, record,
column, and total-field budgets apply. Header-only exports have zero records;
explicit all-empty rows remain records. Source-field accounting uses the original
column count and never counts generated destination fields.

Browser CSVs cover login data exposed by those exports. They do not prove account
completeness or migration of passkeys, cookies, sessions, attachments, or browser
settings. Native TOTP functionality and destination import acceptance require
separate synthetic qualification. Chrome, Edge, and Brave files are accepted under
the Chrome-compatible profile only when they match its declared schema; matching
that header does not identify which browser exported the file.
