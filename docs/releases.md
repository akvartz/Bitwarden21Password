# CLI release runbook

Releases, tags, security-sensitive merges and stable promotion are maintainer
actions. This candidate remains experimental: all provider import profiles are
unqualified. Linux, macOS and Windows public output are enabled; native macOS
and Windows privacy qualification passed on amd64 and arm64 before enablement.
Source-built public CLI journeys and native packaged-binary version/help/formats
smoke checks passed on all six targets; the documented Windows PowerShell setup
passed on both architectures. Packaging alone
does not satisfy the finished 1.0 objective.
Use synthetic data for every smoke/import/recovery check.

Infrastructure [PR #4](https://github.com/akvartz/Bitwarden21Password/pull/4)
was merged at `7777ae112f787b8d6e1ddbc00b24f0496733501b`. The old instruction
to merge that PR is obsolete. Its successful CI establishes the earlier
baseline; changed candidate code needs fresh evidence at its own exact commit.

## Candidate gates

Before calling a candidate ready for stable 1.0, record all of the following in
the [acceptance ledger](agentic/release-1.0-progress.md):

| Gate | Required evidence |
| --- | --- |
| Reviewed implementation | Exact reviewed source commit; independent and adversarial review of parsing, credentials, crypto, output and approval, with findings resolved |
| Local verification | Uncached tests, race tests, vet, bounded parser/crypto fuzzing and meaningful CLI subprocess journeys using synthetic inputs |
| Provider acceptance | [Disposable-vault import and re-export evidence](agentic/provider-qualification.md) for each claimed directional/profile/item capability; provider/client/platform versions recorded |
| Native private output | Qualified Linux/macOS/Windows writers with permission, ACL/DACL, volume, no-clobber, cancellation and failure evidence; authored code/cross-compilation does not pass this gate |
| Encrypted inputs and recovery | Independent vectors, authenticated full-stream failure tests, bounded KDF/archive handling, exact original recovery and documented interoperability limits |
| User journeys | Accurate packaged README/help/formats; selection, review, passwords, recovery, comparison and failure/retry instructions |
| Delivery | Exact-head native CI, all six checked archives, native archive smoke checks by platform/architecture, release-path evidence and a documented authenticity/provenance decision |

The current candidate does not pass all these gates. Do not relabel an
experimental draft as stable to make the checklist appear complete. If scope
is deliberately changed, record and review that decision before changing claims.
No passkey/SSH authentication claim follows from carrying data in a file.

## Build and inspect locally

Use an existing maintained Go toolchain and a provisioned pinned module cache.
Hosted builds pin Go 1.26.9; the module floor is 1.26.0. Dependencies are pinned
in `go.mod`/`go.sum`; `GOTOOLCHAIN=local GOPROXY=off` prevents downloads and
fails with an incomplete cache. The user authorized provisioning these pinned
dependencies; that does not require an automatic toolchain upgrade.

From a clean committed repository root, choose a strict candidate version such
as `v1.0.0-rc.1`. Builds embed version and source commit; never reuse a version
for different bytes. The packager accepts `vMAJOR.MINOR.PATCH` with an optional
prerelease identifier, not a `+build` suffix.

```sh
mkdir -p dist
GOTOOLCHAIN=local GOPROXY=off go run ./cmd/pwmigrate-release \
  --version v1.0.0-rc.1 \
  --commit "$(git rev-parse HEAD)" \
  --output dist/v1.0.0-rc.1
```

The output directory must not exist; its parent must exist. Choose an ignored
`dist/` path or a new path outside the checkout. The packager requires a clean
checkout including untracked files, refuses clobbering, and creates no tag.
Failed builds can leave partial assets: inspect the failure and choose a fresh
directory for retry.

Expect six `pwmigrate-go_VERSION_GOOS_GOARCH` archives: Linux and macOS
`.tar.gz`, Windows `.zip`, each for amd64 and arm64; also
`release-manifest.json` and `SHA256SUMS`. Each archive contains only its binary,
LICENSE, README.md, THIRD-PARTY-NOTICES.md and BUILD-INFO.json. CGO is disabled. Deterministic archive
member order/metadata is not independently reproduced-build evidence.

Inspect every archive's member set, embedded version/commit/platform/architecture,
manifest sizes and checksums. On Linux, in the release directory:

```sh
sha256sum --check SHA256SUMS
```

On macOS use `shasum -a 256 -c SHA256SUMS`; on Windows compare
`Get-FileHash -Algorithm SHA256` for each asset against SHA256SUMS. Compare the
manifest commit to the exact intended release commit. After extraction, run
the native binary:

```sh
./pwmigrate-go version --json
./pwmigrate-go help
./pwmigrate-go formats --json
```

On Windows use `.\pwmigrate-go.exe`. Then exercise the supported synthetic
inspect/plan/convert/recovery/compare journeys using the packaged binary.
Record architecture and limitations honestly. A local six-archive exercise
does not prove that a GitHub dispatch or native foreign-platform writer ran.

## Prepare a GitHub draft

First complete review and obtain fresh exact-head CI. For a 1.0 tag, also
complete every stable gate above. Choose the version and full source SHA
deliberately. Replace `VERSION` and `COMMIT_SHA` below with that chosen strict
version and reviewed commit. The source must be reachable from main, include
the reviewed release tooling and have the intended native CI evidence.

These commands are for the maintainer; the coding agent does not create the
tag, dispatch the release or merge a security-sensitive implementation PR:

```sh
git tag -a VERSION COMMIT_SHA -m "pwmigrate-go VERSION"
git push origin refs/tags/VERSION
gh workflow run release.yml --repo akvartz/Bitwarden21Password --ref main -f tag=VERSION
```

The manually dispatched workflow accepts main, resolves the existing tag to an
exact commit, checks ancestry, and passes that commit plus the validated tag as
`source_sha`/`source_version` to reusable CI. CI packages the six archives once
with read-only repository permissions. All six native packaged-binary hosts
verify and run version/help/formats checks against those same assets. After CI
succeeds, the publishing job downloads the same current-run `ci-release-assets`
artifact; it does not rebuild the archives. It validates the exact eight assets,
manifest and checksums and rechecks the immutable tag object before creating a
draft prerelease. Only the publisher has `contents:write`, and it does not
execute checked-out project/artifact code. No release is created just by merging
a PR or pushing a tag. Review the current workflow's actual permissions and
steps at the chosen commit when recording release-path evidence.

Normal CI omits `source_version` and stamps `v0.0.0-ci.RUN_NUMBER`; local release
candidates carry their chosen version. Their passes do not establish that a
release-tag dispatch or upload ran. The tagged draft workflow still needs its
own recorded execution and exact asset evidence. Native version/help/formats
smoke checks are separate from packaged conversion/recovery journeys and
provider-native acceptance.

An existing release is rejected instead of overwritten. Failed uploads can
leave a partial draft; inspect workflow logs and assets before retrying.
Cleanup/replacement is a maintainer action. Keep candidate drafts explicitly
experimental with current format and platform restrictions, matching the
packaged README and ledger. Verify their asset URLs, completeness, checksum
contents, source SHA and workflow run before any publication.

## Deliberate stable 1.0 promotion

The workflow always creates a draft prerelease with `latest=false`. Stable
promotion is a separate, deliberate action after the full 1.0 gates pass.
Build the reviewed stable source as tag `v1.0.0` through the same workflow;
do not rename `v1.0.0-rc.1` archives or reuse candidate bytes stamped with a
different version. Review the resulting `v1.0.0` draft and release notes,
including provider/profile/native evidence and any accepted limits.

After verifying that exact stable tag, exact-head CI and complete assets, the
maintainer can publish and promote the reviewed draft:

```sh
gh release edit v1.0.0 --repo akvartz/Bitwarden21Password \
  --draft=false --prerelease=false --latest
```

This changes public release state. Engineering readiness, draft creation and
stable publication are different events; record the actual one that occurred.
Do not claim a release was published from successful local packaging.

## Authenticity and verification boundaries

The maintainer selected **cryptographically signed release files** for 1.0 on
2026-10-12 (America/New_York). Final distribution must bind all six archives and
their manifest/checksums to a documented signer identity, and verify those
signatures before publication. A signed checksum manifest can cover the whole
set; a workflow-bound keyless signature is another possible mechanism. The
mechanism and trust anchor still need to be selected and exercised. Setup is
deferred at the maintainer's request and tracked in
[issue #6](https://github.com/akvartz/Bitwarden21Password/issues/6). This
decision does not require macOS notarization or platform executable signing.

The existing archive/manifest/checksum path is unsigned. Signing, macOS
notarization and independently reproduced builds are not established. Checksums
and BUILD-INFO identify bytes/source; they do not authenticate a publisher.
The existing rc.2 artifacts are unsigned historical test candidates and do not
meet the selected 1.0 distribution policy. Until signing and verification are
implemented and their actual evidence is recorded, stable promotion is blocked.
Any added CI build attestation needs its
own recorded generation and verification evidence; it is separate from binary
signing, provider certification and independent reproducibility.

CI declares native tests/vet and binary smoke checks for all six distributed
Linux/macOS/Windows amd64/arm64 targets; Linux amd64 adds race and privileged
permission tests. Exact-head results must be recorded before claiming a pass. New dependency
graphs must be available to all steps, including offline root tests and release
builds. Native help/version smoke tests do not qualify a disabled writer.
Packaging still cross-compiles Linux/macOS/Windows amd64/arm64; each packaged
archive needs runtime evidence on its corresponding native target.

Public conversion, recovery key creation/save and recovery writes are enabled
on Linux, macOS and Windows. Native macOS ACL/volume and Windows DACL/volume
qualification and public CLI journeys passed on both architectures. The
documented Windows PowerShell setup passed on both architectures under the CI
runner account; standard-user writer qualification is separate. See the
[native output evidence](agentic/native-output-journey.md#evidence-and-enablement)
and acceptance ledger for the exact commits/runs. Provider acceptance, encrypted-export
interoperability, recovery interoperability and working authentication are
independent checks. Record unsupported/missing checks as gaps, not passes.
