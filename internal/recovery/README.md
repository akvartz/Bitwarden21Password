# Encrypted source recovery, version 1

This package keeps an exact original source export in a binary age v1 file,
using the maintained `filippo.io/age v1.3.2` implementation and one native X25519
identity/recipient. It preserves data; it does not certify destination migration
or passkey functionality. It performs no network calls and writes no files.

`Encrypt` retains **the whole supplied source**, including records excluded from
conversion, unsupported fields, archive members, and metadata. Selection does
not trim recovery. Callers must disclose this retention before output. Keeping
original provider archives can preserve unencrypted attachment members inside
the encrypted recovery. Retention is only as complete as the supplied snapshot:
when a caller supplies decrypted data rather than the original encrypted export,
it must explain that distinction.

`GenerateIdentity` returns a new secret age key only to the in-memory caller.
Neither `Payload` nor any error contains a recovery key. The caller must create
or read a private local key file or prompt for the key, keep keys out of argv,
logs, reports and preferences, and explain that a lost key makes recovery
unreadable. Store a recovery key separately from its encrypted recovery. Reading
uses exactly one X25519 key; conventional age key-file comments and blank lines
are accepted. Password/scrypt, hybrid, SSH, plugin and multiple-recipient recovery
files are intentionally unsupported in this version.

The decrypted envelope is:

1. The 19 ASCII bytes `pwmigrate-recovery\n`.
2. A 4-byte unsigned big-endian manifest byte length.
3. Exactly that many bytes of UTF-8 JSON.
4. Exactly `source_bytes` original source bytes, then EOF.

The manifest has exactly these five keys, in any order on input:

```json
{"schema":"pwmigrate-recovery","version":1,"source_format":"chrome-csv","retention":"whole_source","source_bytes":4}
```

Source formats are `chrome-csv`, `firefox-csv`, `safari-csv`, `bitwarden-json`,
`onepassword-1pux`, and `proton-pass-zip`. `version` and `source_bytes` are nonnegative JSON integers
without fraction/exponent syntax. Wrong versions, missing/unknown/duplicate keys
(including escaped duplicate spellings), wrong scalar types, invalid UTF-8,
malformed framing, length mismatches, multiple JSON documents, extra source or
payload bytes, and trailing/truncated/tampered ciphertext fail the operation.
Original source bytes are opaque: recovery does not normalize credentials,
Unicode, line endings, or binary archive bytes.

Bounds are 32 MiB source, 4 KiB manifest, 16 KiB identity file, and 48 MiB
ciphertext. Decoded plaintext is limited to 32 MiB + 4 KiB + 23 framing bytes.
The ciphertext allowance covers the bounded age header, 16-byte stream nonce and
16-byte authentication tag per 64 KiB plaintext chunk. The pinned age parser
independently bounds headers to 2 MiB and 1,024 stanzas; this package subsequently
requires a single X25519 stanza. An ordinary maximum-size recovery is about
32 MiB + 8.4 KiB. Input over a bound fails; no partial payload is returned.

The reader buffers and authenticates every age chunk, the final-chunk marker and
EOF before parsing the manifest or returning source bytes. An over-limit stream
may stop early, with no plaintext returned. It clears its plaintext staging
buffer on both success and failure, although Go copies, garbage collection, SSDs
and snapshots prevent guarantees of perfect memory or disk erasure. Protect any
plaintext source recovered by the calling CLI using the same private, no-clobber
output policy as destination exports.

Tests use independent literal envelope framing, directly maintained age API
encryption/decryption, and the upstream static `testdata/example.age` vector
distributed with age v1.3.2. Its documented known plaintext is `Black lives
matter.` and its public synthetic identity appears in upstream `age_test.go`.
The copied fixture is covered by `testdata/AGE-LICENSE`. This checks maintained
age interoperability and exact framing, alongside whole-stream tamper/truncation,
full-length final-chunk EOF, strict manifest, recipient and resource boundaries.
The opt-in `TestOfficialAgeCLIInterop` also checks both directions through the
provisioned official age CLI for all six source formats, with independently
constructed framing and opaque binary source bytes. Run it offline with an
absolute `PWMIGRATE_AGE_CLI` executable path. On 2026-10-12 it passed on Linux
using a source build of the authorized, pinned age v1.3.2 module (version output
`(devel)`); no tool was installed. This demonstrates official CLI compatibility,
not a second cryptographic implementation. Other implementation testing, native
provider import qualification and cross-provider passkey functionality remain
separate evidence.
