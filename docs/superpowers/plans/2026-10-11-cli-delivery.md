# CLI delivery implementation plan

Use the bounded goal loop in docs/agentic/README.md: brief -> behavioral RED -> implementation -> checks -> independent/adversarial review -> fix/re-review -> commit -> publish PR -> record evidence. Main owns integration, Git and docs. Workers have disjoint paths and preserve others' work.

Base: canonical merged main d4e1dc219a3c50fb3de36608122c0f894c84cf9a. Feature branch: chore/cli-delivery. Existing feature branches remain preserved. Exact canonical Git commit objects were verified/imported because terminal Git transport is unavailable; no history was rewritten.

1. Version worker owns internal/buildinfo/**, internal/cli/run.go, internal/cli/run_test.go and a new version-specific process test. Add tested version/--version and JSON metadata with checked writes and release stamping. No parsing/output/approval changes.
2. Packaging worker owns cmd/pwmigrate-release/** and internal/releasepack/**. Implement the design contract with rejection/archiving/checksum tests first. Build using internal/buildinfo Version/Commit flags. Validate exact clean HEAD and fresh output path. No new dependencies.
3. CI worker owns .github/workflows/** and scripts/ci/** only. Add native/race/root/build checks and dispatch-only draft release with separated permissions and exact-commit/tag checks. Include local stdlib validation tests for release guard inputs where useful; no tool acquisition.
4. Main relocates Cargo.toml, src and tests unchanged to legacy/rust; writes legacy README, root README, .gitignore, AGENTS, release runbook, overall design and status updates. Replace desktop roadmap with CLI usability, automation and destination comparison.
5. Run go test -count=1 ./..., go test -race ./..., go vet ./..., formatting/whitespace checks and unchanged Rust blob verification. Test six actual packaged builds from a clean committed checkout, inspect manifests/checksums/archive members and native version/help/formats. Root/native hosted evidence comes from CI; no local sudo claim.
6. Independent reviewer and separate adversarial reviewer inspect current files against canonical base, including new files. Resolve/re-review material findings. Commit explicit owned paths, publish feature branch/PR and attach it. Verify remote tree equality and CI on exact PR head. Leave privileged-release workflow PR unmerged under the project gate. Record any unavailable checks and exact commands for user-triggered release; do not tag or publish a release.

Hosted tool references checked 2026-10-11: Go 1.26.9; actions/checkout v7.0.1, setup-go v7.0.0, upload-artifact v7.0.2, download-artifact v8.0.2. Local Go is 1.26.0; no local upgrade is implied.
