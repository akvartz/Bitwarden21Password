# Bitwarden unlock profile and evidence

This package implements local unlocking of password-protected Bitwarden JSON
envelopes with KDF type 0 (PBKDF2-SHA256) or 1 (Argon2id v1.3), followed by
HKDF-expand `enc` and `mac` subkeys and type-2 AES-256-CBC/HMAC-SHA256 records.
It does not unlock account-restricted exports or type-0 unauthenticated records.
Other cipher types, including newer COSE records, remain unsupported.

Primary public sources checked 2026-10-12, America/New_York:

- [Client export key derivation](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/legacy-crypto/src/services/default-key-generation.service.ts)
  encodes the password and export salt strings as UTF-8 without normalization,
  calls the SDK KDF material derivation, then expands labels `enc` and `mac`
  to 32 bytes each. The envelope salt is a string, not decoded from Base64.
- [Client importer](https://github.com/bitwarden/clients/blob/df9641824436b65207f393d35b8d07225129797b/libs/importer/src/importers/bitwarden/bitwarden-password-protected-importer.ts)
  authenticates/decrypts `encKeyValidation_DO_NOT_EDIT` before consuming `data`.
  It does not require a particular plaintext validation token.
- [SDK KDF](https://github.com/bitwarden/sdk-internal/blob/7d5b1010297d6f2352b55c3d2ff27352e37433cd/crates/bitwarden-crypto/src/keys/kdf.rs)
  passes raw salt bytes to PBKDF2. Argon2id hashes those bytes with SHA-256,
  converts configured MiB to KiB, uses version 0x13, and derives 32 bytes.
  Provider minimums are PBKDF2 5,000 iterations; Argon2id 2 iterations,
  16 MiB, and parallelism 1. Account email normalization belongs to a separate
  method; export key derivation does not use it.
- [SDK stretching](https://github.com/bitwarden/sdk-internal/blob/7d5b1010297d6f2352b55c3d2ff27352e37433cd/crates/bitwarden-crypto/src/keys/utils.rs)
  contains independent literal subkey vectors.
- [SDK type-2 cipher](https://github.com/bitwarden/sdk-internal/blob/7d5b1010297d6f2352b55c3d2ff27352e37433cd/crates/bitwarden-crypto/src/hazmat/symmetric_encryption/aes256_cbc_hmac_sha256_ae.rs)
  specifies PKCS#7 AES-256-CBC encryption and HMAC-SHA256 over IV followed by
  ciphertext. It contains a literal cipher vector independent of this package.
- [SDK record encoding](https://github.com/bitwarden/sdk-internal/blob/7d5b1010297d6f2352b55c3d2ff27352e37433cd/crates/bitwarden-crypto/src/enc_string/symmetric.rs)
  specifies `2.<base64-IV>|<base64-ciphertext>|<base64-MAC>`.

These source snapshots document an explicit profile; they are not a claim that
the pinned client build embeds the exact same SDK revision or that every current
encrypted export uses type 2.

## Bounds and authentication

The caller must bound the complete original JSON to 32 MiB and apply strict
JSON typing, duplicate-key checks, and missing-field checks before calling this
package. The package additionally bounds combined envelope strings to 32 MiB,
the decrypted payload to 32 MiB, the exact UTF-8 password to 1 MiB, the UTF-8 salt
to 1 KiB, and the entire encoded validation record to 4 KiB. It accepts only
canonical padded standard Base64, 16-byte IVs, 32-byte MACs, and nonempty
block-aligned ciphertexts. Component splitting uses a fixed allocation bound.

PBKDF2 iterations range from 5,000 to 2,000,000. Argon2id iterations range
from 2 to 10, memory from 16 to 256 MiB, parallelism from 1 to 16, and the
memory-times-iterations product must not exceed 768 MiB-passes. Bounds are
checked before multiplication or narrowing integer conversions. These limits
may reject otherwise valid provider exports with unusually expensive settings;
they are deliberate resource limits, not a request to alter an account's KDF.
PBKDF2 envelopes with nonzero memory/parallelism are an unsupported variant.

Both validation and data MACs are verified before either record is decrypted.
Strict PKCS#7 padding and UTF-8 validation are applied to both plaintexts.
Failures return only a fixed code and nil plaintext. Validation plaintext and
temporary keys are cleared; callers must clear their password and returned
plaintext when no longer needed. Go does not guarantee erasure of every
internal copy. Passwords are never accepted through process arguments here.

## Test evidence and qualification limits

Tests use synthetic literal vectors independently generated with an already
available Python `cryptography` 50.0.0 installation, plus public provider SDK
KDF, HKDF, and cipher component literals. `testdata/generate_bitwarden_vectors.py`
documents how the complete synthetic PBKDF2 and Argon2id envelopes were produced;
normal Go tests consume the retained JSON literals and do not run Python.
The Argon2id subkey literal combines the provider's published KDF material with
Python's maintained HKDF-expand implementation. Fixed passwords and IVs occur
only in synthetic tests and are never examples for production encryption.

Tests cover exact whitespace/Unicode handling, wrong passwords, mutation of
every record component, every single-byte truncation of a synthetic record,
invalid Base64/padding/IV/MAC/block sizes, authenticated malformed PKCS#7,
authenticated invalid UTF-8, rejected account-bound envelopes, KDF limits,
integer overflow inputs, allocation bounds, and record parser fuzzing.

No end-to-end encrypted export produced by a native Bitwarden application has
been qualified here. No native provider import or passkey authentication has
been established. The complete independent synthetic envelope tests and source
component vectors improve implementation confidence while leaving those
external qualification gates open.
