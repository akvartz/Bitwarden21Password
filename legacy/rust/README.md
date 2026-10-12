# Archived Rust reference

The original Rust implementation is preserved here, unchanged, while the Go CLI is developed. Source, manifest, tests and fixtures moved together so relative Cargo paths remain valid. Git history retains the original paths.

This is reference material, not the supported product or an independent correctness oracle. Review found credential trimming, secret-bearing errors, incomplete mappings, ambiguous notes-marker encoding and unprotected output. The Go CLI never falls back to Rust. The old adapter count does not establish current Go support or provider compatibility.

With an existing Rust toolchain, run from the repository root:

```sh
cargo build --release --manifest-path legacy/rust/Cargo.toml
cargo test --manifest-path legacy/rust/Cargo.toml
cargo clippy --manifest-path legacy/rust/Cargo.toml
```

The legacy executable is `pwmigrate`; the supported Go entry point is `cmd/pwmigrate`, built as `pwmigrate-go`. Rust is excluded from Go release archives and CI. This relocation was checked for byte-for-byte preservation; Cargo was unavailable locally, so no Rust test pass is claimed.
