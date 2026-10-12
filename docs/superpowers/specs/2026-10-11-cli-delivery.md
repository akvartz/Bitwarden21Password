# CLI delivery design

Accepted direction, 2026-10-11: CLI-only on Linux, macOS and Windows. No desktop/Wails milestone. Keep guided review, exact issue acknowledgment, whole-export default and optional selection. Terminal path drag-and-drop is a usability goal; no native desktop launcher is claimed.

## Scope

Move the unchanged Rust manifest, sources, tests and fixtures together into legacy/rust. Preserve Git history and mark it as archived reference with known correctness issues. Go stays standard-library-only.

Add version/--version and version --json, including program, version, commit, go_version, goos and goarch. Development defaults are dev/unknown. Release builds stamp internal/buildinfo.Version and Commit using linker flags; metadata never depends on vault input.

A Go release packager builds CGO-disabled linux/darwin/windows binaries for amd64/arm64 from an exact clean Git HEAD. Explicit strict semantic version and full commit are mandatory; no inferred tags, overwrites or automatic publication. Use the local toolchain and offline dependency mode. Package only the binary, LICENSE, README.md and BUILD-INFO.json with deterministic archive metadata. Unix uses tar.gz and Windows zip. Asset names: pwmigrate-go_VERSION_GOOS_GOARCH.EXT. Add release-manifest.json (schema_version 1, version, commit, go_version, artifacts array with name, sha256, size) and SHA256SUMS covering the six archives plus manifest. SHA256SUMS is integrity evidence, not signing. Output must be a new directory; failure never replaces an existing release directory.

GitHub CI runs the actual suite and vet on Linux, macOS and Windows, plus Linux race and separate uncached privileged test binaries for permission coverage. Read-only CI permissions, full action SHA pins, Go 1.26.9 and explicit runner versions. Packaging CI builds all six archives and smoke-tests the native executable.

Release workflow is manually dispatched from main for an already existing explicit tag. Validate strict version syntax, resolve exact tag object/commit, require ancestry of dispatch main, run reusable CI against that commit, build with read-only permissions, then publish a draft prerelease only. The separate publishing job executes no checked-out repository code, validates the complete asset set/manifest/checksums and unchanged remote tag, refuses existing releases, and uses contents:write only there. No tag creation, release overwrite, latest promotion or automatic tag-push release. Actual tag/release actions remain the user's responsibility.

## Evidence boundaries

Conversion remains experimental and Linux-only. macOS/Windows binaries support read-only commands and fail closed for writes. Native hosted tests are separate from local cross-builds. Provider import, encrypted inputs, recovery, signing and production release qualification remain outstanding. No tool installation locally, new modules, migration behavior changes, runtime network or source deletion.
