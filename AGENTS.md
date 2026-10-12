# pwmigrate project instructions

Read the user's working agreement, docs/superpowers/specs/2026-10-11-go-migration-design.md, and docs/agentic/README.md. Resume from docs/agentic/go-migration-status.md and verify its claims against Git/evidence.

- Preserve legacy Rust under legacy/rust while Go milestones are validated. Rust is not the correctness oracle; never silently fall back to it.
- Keep migration/security rules in Go. The product direction is CLI-only on Linux, macOS and Windows; no desktop/Wails dependencies.
- Preserve exact credentials, unknown fields/types, and duplicates. Never silently normalize, merge, drop, or reinterpret data.
- Synthetic tests only. No real vaults/secret files, raw parser excerpts, sensitive labels/values, or source-derived fingerprints in logs/reports/commits.
- No runtime network, telemetry, remote UI assets, or automatic source deletion.
- No new tools/dependencies installed. M1 uses the standard library. Run Go checks with GOTOOLCHAIN=local GOPROXY=off and approved scratch caches when needed.
- Parsing, credentials, encryption, output, and approval changes need edge-case tests first, independent review, and adversarial review.
- Report local tests, cross-compilation, native platform checks, and provider imports separately. Self-roundtrips prove neither provider acceptance nor passkey functionality.
- Workers own bounded paths and preserve others' work. Main owns Git integration and durable status.
- Stage explicit paths. Security-sensitive PRs remain unmerged; releases/tags/production remain user actions.
