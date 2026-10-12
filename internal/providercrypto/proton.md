# Proton Pass encrypted input boundary

`UnlockProton` reads the `Proton Pass/data.pgp` entry. The reviewed Proton
[export crypto source](https://github.com/ProtonMail/WebClients/blob/d70c6131012876da970d08f81fdcbb89723a88f1/packages/pass/lib/crypto/utils/export.ts)
uses armored password-based OpenPGP, binary data, and iterated S2K count byte
255; its comment leaves Argon2 for a future change. The separate ZIP attachments
remain unencrypted. This implementation unlocks data; archive validation and
strict provider JSON/version validation belong to the caller.

The supported profile is exactly one v4 symmetric-key encrypted session-key
packet followed by one v1 symmetrically encrypted integrity-protected packet.
The session-key protection and decrypted data cipher must be AES-128, AES-192
or AES-256. S2K must be salted/iterated with SHA-256, SHA-384 or SHA-512. It
accepts the direct derived-key form and wrapped AES session keys. All count
bytes are supported; byte255 requires 65,011,712 hash-input bytes, with at most
one hash pass for the supported cipher/hash combinations. Simple/salt-only
S2K, SHA-1/legacy hashes, Argon2, v5/v6 session keys, AEAD, unauthenticated
encryption, public-key packets and multiple session keys are rejected before
any KDF work.

Input, the decrypted packet stream and any expanded stream each have a 32 MiB
ceiling. Password bytes have a 1 MiB ceiling and are used exactly, including
whitespace and empty input. Only complete, bounded definite or new partial
packet lengths are accepted outside encryption. New partial packets require a
first chunk of at least 512 bytes. Declared sizes are checked against actual
remaining bytes before allocation; session-key bodies have a fixed small size
allowlist. Armor requires one complete `PGP MESSAGE` block, up to 16 printable
header lines, body lines up to 96 bytes and no non-whitespace trailing data.
Optional CRC24 syntax is checked; its checksum is ignored by the maintained
armor reader. Ciphertext integrity relies on the complete MDC check.

[`gopenpgp/v3` v3.5.2](https://github.com/ProtonMail/gopenpgp/tree/v3.5.2)
derives and unwraps the bounded session key.
[`go-crypto` v1.5.2](https://github.com/ProtonMail/go-crypto/tree/v1.5.2)
decrypts the SEIPD stream and authenticates its MDC on `Close`. The entire
bounded inner stream is read and its close succeeds before any inner packet
is parsed or any plaintext is returned. This avoids the high-level message
reader's signature-candidate allocation path for hostile inner messages.
Crypto, key derivation and MDC are entirely maintained-library operations.

Authenticated inner data must be one binary literal packet, optionally inside
one uncompressed, ZIP/DEFLATE or ZLIB wrapper. A terminal authenticated
compressed wrapper may use an old indeterminate length. Nested compression,
signed/text messages, unknown compression, extra inner packets, malformed
literal metadata and compressed trailing bytes are rejected. Expansion is
bounded before parsing a literal. Plaintext is copied into the return value
only after complete authentication and framing validation. Owned password,
session key and intermediate plaintext buffers are cleared on return; Go
memory clearing is best effort and is not a secure-erasure guarantee.

Errors expose only `providercrypto.Error` fixed codes. Failures return nil
plaintext. No diagnostics include provider labels, payloads, paths, passwords
or library error strings.

## Synthetic evidence

`proton_vectors_test.go` contains three fixed vectors independently generated
with the pre-existing GnuPG 2.4.7/libgcrypt 1.11.0 executable: AES256, iterated
salted SHA256 count 65011712, binary literal, MDC and none/ZIP/ZLIB compression.
Generation used an isolated 0700 temporary GnuPG home and passphrase file:

```
gpg --homedir TEMP_HOME --batch --yes --pinentry-mode loopback \
  --passphrase-file SYNTHETIC_PASS_FILE --no-symkey-cache \
  --s2k-mode 3 --s2k-count 65011712 --s2k-digest-algo SHA256 \
  --cipher-algo AES256 --compress-algo none --force-mdc --set-filename '' \
  --armor --output SYNTHETIC_OUTPUT --symmetric SYNTHETIC_INPUT
```

The other vectors change `--compress-algo` to `zip` and `zlib`. Fixture
plaintext includes Unicode, exact whitespace, NUL and CRLF to verify the
opaque binary boundary. Tests consume each independently generated vector as
armor and binary and reject wrong/trimmed/empty passwords, tampering,
truncation, malformed armor, trailing/multiple packets, obsolete/unsupported
algorithms and hostile Argon2 descriptors. Additional maintained-library
generated authenticated packets probe malicious inner frames, a greater than
32 MiB expansion bomb, and valid/unfinished partial lengths. Those additional
messages test defensive behavior, not independent interoperability.

This is local cryptographic interoperability and source-format evidence.
There is no actual Proton account export/import qualification or claim that
every OpenPGP profile is supported.
