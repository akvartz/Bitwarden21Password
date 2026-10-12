# pwmigrate 1.0 acceptance and execution ledger

Updated 2026-10-12 UTC. Objective: the finished, qualified 1.0 Go CLI in the
accepted design and supplied [handoff](handoff-1.0.0.md). **Not yet complete.**
Tags, publication and security-sensitive merges remain maintainer actions.

Canonical base: `7777ae112f787b8d6e1ddbc00b24f0496733501b`, independently checked
against ordinary Git fetch and live PR #4 merged state. Work is on
`feat/1.0-release`, preserving earlier histories. Initial reviewed candidate
commit `e4cfedf6e33d601e036a8c8b5c67cae9bca182ae`, tree
`2623d903813019330050f17b1e30ead9e8e80416`, was pushed through ordinary
Git without rewriting history and is attached as unmerged draft
[PR #5](https://github.com/akvartz/Bitwarden21Password/pull/5). This ledger substitutes for a
native goal API, which is unavailable. The referenced personal working agreement
is absent; AGENTS.md, accepted design and the handoff govern this session.
Local primary-source research scratch is excluded from Git and build inputs.

## Acceptance matrix

| Gate | Current implementation and evidence | Remaining completion condition |
| --- | --- | --- |
| Provider routes | Six directional Bitwarden/1PUX/Proton profiles; strict snapshots; login/note/card/identity and documented typed fields; intermediary losses disclosed; independent/adversarial review | Actual disposable-vault import and re-export qualification for each claimed profile |
| Browser sources | Chrome/Chromium, native Firefox and Safari/OTPAuth CSV into all three providers: nine routes; primary schema evidence and independent fixtures | Native browser export and destination import qualification |
| Auditable fidelity | Every selected leaf/empty container and metadata field receives a disposition; exact credentials/duplicates retained; unsafe unfamiliar records block; omitted attachments/passkeys/vault relationships require exact review | Provider observations of supported values and disclosed losses; no working passkey claim |
| SSH | Ed25519 across all six provider directions; RSA 2048/3072/4096 Bitwarden↔Proton and 1PUX→Bitwarden/Proton; maintained SSH/x509 parsing, exact ASN checks, validated pairs and fingerprints; native custom-section relocation and private representation dispositions | Native import/agent authentication; Bitwarden/Proton RSA→1PUX metadata token unverified and blocked |
| Archives | Extraction-free ZIP, local/central/index validation, compressed/expanded/entry/depth bounds, unconditional CRC and complete compressed-span consumption; negative/fuzz/race reviews | Native exporter fixtures and provider archive acceptance |
| Encrypted inputs | Bitwarden password-protected PBKDF2/Argon2id authenticated envelopes; bounded Proton OpenPGP profile; independent cryptography/GnuPG/provider component vectors, tamper tests and two review seats | Native app-created encrypted-export qualification; account-bound/unknown profiles remain rejected |
| Recovery | age v1.3.2 X25519 writer/reader, authenticated exact whole-original framing, key handling, standalone save/recover and conversion retention; static upstream vector and both official CLI directions for all six formats pass | Other implementation testing is distinct; user verifies saved key/original during provider qualification |
| Selection/comparison | Intersecting ordinal item/vault/folder/kind selection; multiset destination comparison, ambiguity/unobservable fields; SSH key representations compared semantically; no values/fingerprints in reports | Supplied native destination re-export tests; comparison never certifies import/authentication |
| Linux output | Native private anchored output, fixed names, no replacement, sync/readback/close, cancellation/fault/concurrency tests; reviewer probes including recovery failure/cancellation pass | Final exact-commit CI/root and packaged runtime checks |
| macOS/Windows output | macOS native amd64/arm64 privacy qualification passed, public pipeline enabled; Windows candidate DACL/owner/local-volume/fault/alternate-principal denial probes pass except standard-user child; Windows public writes remain disabled | Fresh macOS public CLI journeys; diagnose Windows child and qualify both architectures before enablement, then Windows public CLI journeys |
| CLI | Human/JSON help, safe inventory/plan/review/receipts, explicit one-shot issue acknowledgment, progress, exact hidden/stdin/JSON passwords, recovery/comparison; actual PTY and blocked-stream signal probes pass independent/adversarial review | Final packaged/native end-to-end smoke and usability qualification |
| Documentation | Full ordinary-user journeys, limits, recovery/selection/comparison and directional matrix; stale merged status corrected; provider procedure explicitly NOT RUN | Synthetic-only kit checks all fifteen routes/591 values; twelve retained protocol/privacy tests pass; final native acceptance and candidate links/evidence pending |
| Release candidate | Pinned patched Go 1.26.9; six-target no-clobber packager and existing guarded draft workflow; dependency-cache tamper review | Dependency pin/source/cache/environment gates and two review seats pass; clean-commit archives/asset guards and exact-head hosted/native and packaged runtime evidence pending |
| Stable promotion | Runbook defines deliberate v1.0.0 build/promotion; no tag/release created | All qualification gates; explicit signing/notarization/provenance policy; user-owned merge/tag/draft/promotion |

## Dependencies and execution

The user explicitly authorized fetching maintained pinned dependencies on
2026-10-12: x/crypto v0.58.0, gopenpgp/v3 v3.5.2, age v1.3.2 and required
transitive dependencies. The reviewed graph is frozen in go.mod/go.sum; it also
includes direct go-crypto v1.5.2, x/sys v0.49.0 and x/term v0.47.0. No tools were
installed. The already-provisioned toolchain is Go 1.26.9 at
`/workspace/toolchains/go1.26.9/go/bin/go`; `/usr/bin/go` is unrelated software.

Local checks use GOTOOLCHAIN=local, GOPROXY=off, GOCACHE=/tmp/pwmigrate-go-build
and GOMODCACHE=/tmp/pwmigrate-go-mod. Fetching is a separate bounded build step
through the configured proxy. circl v1.6.3 was fetched from its allowed upstream
with GOPROXY=direct after the module proxy's storage redirect was denied; the
configured network proxy remained in use. Hosted workflows separately download
and verify pins, require unchanged module files, then test/build offline.

## Review and verification evidence

- Full uncached Go suite, full uncached race suite, full vet and ten Python
  release-guard tests passed before the final SSH/dependency/CLI corrections.
  The final integrated uncached suite, full race suite and vet passed after SSH, dependency preflight and provider exact-output guard integration. A later formats capability Boolean passed its focused RED/GREEN; native-only fixtures await hosted execution.
- Independent and adversarial seats covered parsing/archives, provider mappings,
  field accounting, crypto/recovery, approval/output, selection/comparison,
  actual CLI processes and workflow permissions. Synthetic fixtures only.
- Review-driven RED/GREEN corrections include archive zero-CRC and ignored
  compressed-tail data; transient/deep JSON path amplification; cross-route
  quadratic accounting; understated importer-loss locations; terminal signal
  restoration and canonical-line truncation; blocked prompt/report/completion
  cancellation; and duplicate/unknown ASN fields in PKCS8/RSA containers.
  Scoped post-fix re-reviews pass. The coordinated mutable module-cache hash and inherited private-module
  network bypass findings were reproduced, fixed with maintained Go preflights
  and explicit offline environment pins, then passed separate re-reviews.
- Official age CLI interoperation passed for six formats in both directions,
  independently framed with opaque binary source bytes. The executable was
  built, not installed, from the authorized pinned age v1.3.2 module and reports
  `(devel)`; it is the official CLI using the maintained implementation, not
  independent cryptographic implementation evidence. The opt-in test makes
  this check reproducible with a provisioned absolute executable path.
- Linux tests execute native operations. macOS/Windows candidate test binaries
  have only cross-compiled locally; no native success is asserted. Hosted native fixtures now include real alternate-principal denial and
  ordinary-user positive output, foreign-owner rejection, private retained
  partials, permitted/rejected volumes and real junction controls. Separate
  source review found and corrected a native API call and fixture ownership/
  cleanup premises; cross-compilation never substitutes for executing them.
- Actual provider imports, native app-created encrypted exports, SSH agent
  authentication, signing and public release promotion are NOT RUN.
  Foreign-platform archive runtime smoke passed in the initial hosted run
  recorded below. Checklists do not substitute for results.

## Next executable steps

1. Finish synthetic kit and packaged-native helper reviews; the dependency-pin
   preflight and exact generated-provider-output guards are integrated and pass
   independent and adversarial review. All fifteen routes pass 591 independent
   local kit checks, with every actual import still NOT RUN. The kit refuses
   duplicate JSON keys, wrong item/custom/concealment types and completion plans
   that differ from the live approved review; fixed-error regressions cover
   malformed protocol and archive failures. The archive/native smoke helper
   passes fifteen regressions plus separate adversarial probes before execution.
2. Run final integrated checks, commit explicit owned paths, package all six
   targets from the clean exact commit and verify every member/header/metadata/
   checksum plus packaged Linux journeys.
3. Push the feature branch, attach a reviewable unmerged PR and obtain fresh
   exact-head hosted CI, including candidate native privacy qualification.
   Correct native failures; enable supported writers only after evidence.
4. Run the concrete synthetic provider qualification procedure with the user;
   record provider/version/platform/case outcomes. Continue independent work
   while awaiting results; never receive real vault files or credentials.
5. Resolve delivery authenticity/provenance policy and record remaining native
   architecture evidence. Only a fully qualified candidate can be called 1.0
   ready; publication remains the maintainer's deliberate action.

## Initial clean candidate and hosted evidence

Clean `e4cfedf` built all six `v1.0.0-rc.1` archives with Go 1.26.9. The
complete set passed the native archive helper on Linux amd64 and the actual
publishing workflow's eight-asset/manifest/checksum validator without dispatch.
Each archive contains the executable, README, project license, dependency
notices and exact BUILD-INFO. No tag or release exists. Preserved artifacts:
`/workspace/artifacts/pwmigrate/pwmigrate-release-1.0.0-rc.1-e4cfedf`.

[Initial hosted CI 38211874470](https://github.com/akvartz/Bitwarden21Password/actions/runs/38211874470)
ran against that exact commit. Linux amd64/arm64 tests, vet and source smoke,
Linux race/root/helper guards, six-platform packaging, and **all six actual
packaged native binary** checks passed. Public macOS/Windows writing remained
disabled. Native qualification exposed concrete failures being corrected:

- Intel macOS's cold linker-metadata test build exceeded its old 60-second
  deadline; compilation and runtime deadlines are being separated.
- ARM macOS passed ordinary candidate tests and APFS/HFS/second-principal/
  foreign-owner probes, but its FAT fixture was not writable by the caller.
- Both Windows architectures passed ordinary candidate tests and negative
  privacy probes, but the standard-user child probe failed and the owned FAT
  VHD could not be detached during cleanup. Fixed child diagnostics and exact
  native cleanup will identify/correct the boundary before public enablement.

These failures are not passes or a reason to skip qualification. Candidate
routing stays disabled until the corrected non-skipping privacy gates pass,
then public conversion/recovery journeys must pass on a fresh exact commit.
The user has been asked for available disposable provider testing and the
required signing/authenticity policy; no answer or approval is inferred.

The next reviewed test-only correction separates a 180-second cold compilation
budget from the five-second version runtime budget, makes the macOS FAT fixture
writable with an independently checked ordinary-user positive control, and
uses owned-image native Windows VHD detachment with scoped, checked privilege.
Windows child diagnostics expose only a fixed phase enum and still require a
successful child exit plus the complete marker. Independent and adversarial
source reviews, focused Linux race tests, and four-target cross-build/vet pass;
only the next actual native run can establish whether those fixtures pass.

Test-only private-parent fixtures and six provider job/three CLI target journeys
are ready to execute through the public APIs after platform enablement. Windows
parents receive an explicit protected user/SYSTEM DACL at creation, then an
independent handle readback. Public Darwin/Windows writing remains disabled.
The ordinary-user parent recipe is in native-output-journey.md; its Windows
PowerShell recipe has source review but has not been executed natively.

## Second native run and macOS activation

[CI 38215250163](https://github.com/akvartz/Bitwarden21Password/actions/runs/38215250163)
at exact `39802b9cfefc4ddc4c92168060150d158bdeb489` passed both Linux native jobs,
Linux race/root/helper guards, packaging, all six packaged native checks, and
both macOS native jobs. Both macOS privacy suites passed actual second-principal
published/retained-partial denial, foreign-owner rejection and APFS/HFS/FAT
volume probes without skips. Windows VHD cleanup and other privacy probes now
pass; both standard-user children still fail before a readable phase marker.
No Windows enablement follows from this run.

macOS public wrappers are now connected to the identical qualified pipeline,
with native capability assertions and packaged checks expecting true. The
activation passes independent/adversarial source review, Linux protected-output/
CLI race tests, two Darwin cross-build/vet checks and ten release guards.
The next exact-head CI must establish public conversion/recovery journeys;
the prior candidate-only run does not establish that evidence.

## Proton SSH completion

The pinned Proton native schema and Bitwarden reader independently establish
the `sshKey` type, raw private/public strings, sections and hidden fingerprint
relocation. The adapter admits validated Ed25519 and RSA 2048/3072/4096 pairs;
it preserves exact admitted raw values or discloses a PKCS#8/PKCS#1→OpenSSH
representation transformation. User section labels never become native key
ownership metadata. Text/hidden fields relocate; grouping and unfamiliar fields
remain explicitly unsupported. RSA output to 1PUX remains blocked.

True behavioral RED/GREEN preceded parser/mapping/output-validation changes.
Focused tests cover all admitted directions, malformed/encrypted/conflicting/
oversized keys, unknown and duplicate custom fields, exact output validation,
source ownership and report redaction. Proton semantic SSH comparison is bound
to its declared item type and source paths, retaining duplicate counts and
unobservable-original-encoding caveats. The integrated uncached Go suite, full
race suite and vet pass. Independent and adversarial source/probe reviews are
recorded separately before integration. Actual native SSH imports and agent
authentication remain NOT RUN. An additive independent synthetic SSH kit is
being prepared; the existing default kit still has fifteen routes/591 core
checks and does not contain SSH fixtures.

Final independent and adversarial reviews pass the stable Proton adapter,
comparison hooks and macOS public activation. The next Windows probe grants the
exact temporary account access only to its shared synthetic startup fixtures,
then requires the real non-elevated process identity and strict private-writer
checks. Bounded diagnostics add fixed marker reasons and numeric native/exit
statuses without paths, SIDs, passwords or child stdout/stderr. Separate source
reviews and Windows cross-build/vet pass; no native success is inferred.

## Public macOS evidence and Windows diagnostic correction

[CI 38216802179](https://github.com/akvartz/Bitwarden21Password/actions/runs/38216802179)
at exact `f0c8f15fd6a05a484f667c485352449f5da515a7` passed both macOS native
jobs with public output enabled. This includes ordinary provider conversion,
live JSON approval, key creation, whole-source recovery/restoration and the
native privacy suites. Both Linux native jobs, Linux race/root/helper guards,
packaging and all six actual packaged native binaries passed as well.

Both Windows children started and created their diagnostic markers but exited
nonzero. The parent's anchored marker opener returned EINVAL: its synchronous
NtCreateFile options require an explicit SYNCHRONIZE access bit. The test-only
correction uses FILE_GENERIC_READ, preserving no-reparse/single-link and bounded
fixed-code reads, with known/unknown/overlimit/hardlink regressions. Reading the
marker will identify the remaining child failure; this correction alone does
not qualify Windows or enable public output.

[CI 38217701084](https://github.com/akvartz/Bitwarden21Password/actions/runs/38217701084)
at `14ba6d13a9294998bdf8761df1bed3f5808d47cf` passed the marker regressions and
all non-Windows jobs. The Windows child is now observed at `private_parent`,
with a valid fixed marker and nonzero exit, before writer invocation. The next
reviewed test-only probe records the exact constructor/drive/ancestor/base/
create/close stage and numeric native status, plus an enabled/missing/unknown
BUILTIN Users premise from its actual token. It is read-only after primary
failure, never repairs membership/ACLs or substitutes success. Independent and
adversarial source reviews and both Windows cross-builds/vet pass; actual cause
observation remains the next native check. Public Windows output stays false.

## Independent SSH qualification companion

The additive `scripts/qualification/prepare_ssh.py` prepares three independent
synthetic Ed25519 records, including duplicate items/custom fields and exact
whitespace, for all six provider directions. Its stored-key oracle uses public
RFC 8032 seed/public literals and independently framed PKCS#8/OpenSSH bytes,
before any candidate command. All six routes pass **144 local checks**, and
fourteen protocol/material/privacy/archive/pipe regressions pass. The original
default kit remains fifteen routes/591 checks with twelve regressions.

Independent review reproduced ZIP64 and special-file entry acceptance in the
new archive oracle. Behavioral RED/GREEN corrected local/central versions,
names, flags, modes, extra fields, spans, descriptors and bounded complete
decompression/CRC; twenty negative variants and ordinary Go mode/timestamp
positives remain tested. Independent and adversarial final re-reviews pass.
CI runs the companion guards alongside existing helpers. Every manifest still
states source-app export, provider import and SSH authentication NOT RUN.
The companion prepares synthetic files on Linux; its artifacts can be imported
manually on any claimed native provider client during user-controlled testing.
