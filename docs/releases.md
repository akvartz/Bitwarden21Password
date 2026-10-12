# CLI release runbook

Releases are manual maintainer actions. This repository prepares an experimental CLI; packaging does not qualify provider imports or enable macOS/Windows output. Use synthetic data for every smoke/import test.

## Build and inspect locally

Use an already installed, maintained Go toolchain. Hosted builds pin Go 1.26.9; the module floor is 1.26.0. No module dependencies are downloaded.

From a clean committed repository root, choose a strict version such as `v0.1.0-rc.1`. Each build embeds its version and commit; do not reuse a version for different bytes. The packager accepts major.minor.patch and optional prerelease identifiers, but not a +build suffix.

```sh
mkdir -p dist
GOTOOLCHAIN=local GOPROXY=off go run ./cmd/pwmigrate-release \
  --version v0.1.0-rc.1 \
  --commit "$(git rev-parse HEAD)" \
  --output dist/v0.1.0-rc.1
```

The output directory must not exist; its parent must already exist. Use an ignored `dist/` path or a new path outside the checkout. The source checkout must be clean, including untracked files. Failed builds can leave partial release artifacts; inspect them and select a fresh output directory for a retry. The packager never replaces an existing directory or creates a tag.

Expected output: six `pwmigrate-go_VERSION_GOOS_GOARCH` archives (`.tar.gz` for linux/darwin, `.zip` for windows), `release-manifest.json` and `SHA256SUMS`. Each archive contains only its binary, LICENSE, README.md and BUILD-INFO.json. Archives do not include Rust, test exports or repository history. CGO is disabled. Archive metadata and member order are deterministic for the same inputs; this is not a claim of independently reproduced builds.

Verify checksums before extraction. Run this inside the downloaded release directory on Linux:

```sh
sha256sum --check SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS`; on Windows use `Get-FileHash -Algorithm SHA256` for each archive and compare against SHA256SUMS. Compare the manifest's commit with the intended release commit. SHA-256 checksums detect mismatched bytes; an unsigned checksum file does not establish publisher authenticity.

After extraction, run the native binary:

```sh
./pwmigrate-go version --json
./pwmigrate-go help
./pwmigrate-go formats --json
```

On Windows use `.\pwmigrate-go.exe`. Version JSON reports program, version, commit, go_version, goos and goarch. Unstamped development builds report `dev` and `unknown`.

## Prepare a GitHub draft

First merge the reviewed infrastructure PR, verify the intended commit's CI, and complete the applicable [provider/platform qualification](agentic/go-migration-status.md). Choose the version and exact commit deliberately. Tag creation and workflow dispatch below are for the maintainer to run; they are not performed by the coding agent.

Replace VERSION and COMMIT_SHA with the chosen `vMAJOR.MINOR.PATCH[-prerelease]` and full reviewed commit SHA. The commit must be reachable from main, contain this workflow/tooling and have clean native CI. Then run:

```sh
git tag -a VERSION COMMIT_SHA -m "Experimental CLI VERSION"
git push origin refs/tags/VERSION
gh workflow run release.yml --repo akvartz/Bitwarden21Password --ref main -f tag=VERSION
```

Dispatch is accepted only from main. The workflow resolves the existing tag to an exact commit, requires it to be an ancestor of the main revision used for dispatch, runs CI against that commit, builds with read-only repository permissions, and checks the tag again before creating a draft prerelease. Existing releases are rejected instead of overwritten. A separate publishing job validates the archive set, manifest and checksums before using its write token; it does not execute checked-out project or artifact code.

Review the draft assets, build metadata, capability limitations and CI results before any public release. The workflow always marks drafts as prereleases and never makes them latest. Signing, notarization and independent build provenance are not implemented. Publication, tag changes, stable-release promotion and distribution are separate user decisions.

## Verification boundaries

CI executes tests/vet natively on Linux amd64, macOS arm64 and Windows amd64. Linux additionally runs race tests and a separate privileged test pass for permission edge cases. Packaging cross-compiles six architecture/platform combinations. Cross-compilation is not native runtime proof for Linux arm64, macOS amd64 or Windows arm64.

Protected conversion remains Linux-only. macOS/Windows builds fail closed for writes until ACL/DACL policy and native evidence qualify them. A successful local conversion receipt is not destination acceptance. Actual Bitwarden import, passkey functionality, encryption interoperability and recovery require their own evidence.
