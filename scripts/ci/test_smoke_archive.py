"""Synthetic behavioral coverage for the native packaged-artifact smoke guard."""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile


SCRIPT = Path(__file__).with_name("smoke_archive.py")
SPEC = importlib.util.spec_from_file_location("smoke_archive", SCRIPT)
smoke_archive = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke_archive)
VERSION = "v0.0.0-ci.123"
COMMIT = "0123456789abcdef0123456789abcdef01234567"
TARGETS = [(goos, arch) for goos in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]


def metadata(goos, arch):
    return {"program": "pwmigrate-go", "version": VERSION, "commit": COMMIT,
            "go_version": "go1.26.9", "goos": goos, "goarch": arch}


def binary_header(goos, arch):
    # Independent minimal header literals. These are never actually executed;
    # runtime output is supplied by a test executor below.
    payload = bytearray(512)
    if goos == "linux":
        payload[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", payload, 16, 2, 62 if arch == "amd64" else 183, 1)
        struct.pack_into("<Q", payload, 32, 64)
        struct.pack_into("<HHH", payload, 52, 64, 56, 1)
    elif goos == "darwin":
        struct.pack_into("<IIIIIII", payload, 0, 0xfeedfacf,
                         0x01000007 if arch == "amd64" else 0x0100000c,
                         3 if arch == "amd64" else 0, 2, 1, 8, 0)
        struct.pack_into("<II", payload, 32, 1, 8)
    else:
        payload[:2] = b"MZ"
        struct.pack_into("<I", payload, 60, 64)
        payload[64:68] = b"PE\x00\x00"
        struct.pack_into("<HH", payload, 68, 0x8664 if arch == "amd64" else 0xaa64, 1)
        struct.pack_into("<HH", payload, 84, 112, 2)
        struct.pack_into("<H", payload, 88, 0x20b)
    return bytes(payload)


def member_bytes(goos, arch):
    executable = "pwmigrate-go.exe" if goos == "windows" else "pwmigrate-go"
    return [(executable, binary_header(goos, arch)), ("LICENSE", b"synthetic license\n"),
            ("README.md", b"synthetic readme\n"), ("THIRD-PARTY-NOTICES.md", b"synthetic notices\n"),
            ("BUILD-INFO.json", json.dumps(metadata(goos, arch)).encode() + b"\n")]


def archive_bytes(goos, members, special=None):
    stream = io.BytesIO()
    if goos == "windows":
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, payload in members:
                header = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                header.create_system = 3
                mode = 0o755 if name.endswith(".exe") else 0o644
                header.external_attr = (0o100000 | mode) << 16
                if name == special:
                    header.external_attr = (0o120000 | mode) << 16
                header.compress_type = zipfile.ZIP_DEFLATED
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    archive.writestr(header, payload)
        return stream.getvalue()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in members:
            header = tarfile.TarInfo(name)
            header.mode = 0o755 if name == "pwmigrate-go" else 0o644
            header.size = len(payload)
            if name == special:
                header.type = tarfile.SYMTYPE
                header.linkname = "synthetic-target"
                header.size = 0
                payload = b""
            archive.addfile(header, io.BytesIO(payload))
    raw = stream.getvalue()
    # Python's writer pads to 10KiB; Go's release writer emits exactly two
    # terminating blocks after the member data.
    end = sum(512 + ((len(value) + 511) // 512) * 512 for _, value in members)
    if special:
        end -= ((len(dict(members)[special]) + 511) // 512) * 512
    return gzip.compress(raw[:end + 1024], mtime=0)


def capabilities(supported=True):
    providers = ("bitwarden-json", "onepassword-1pux", "proton-pass-zip")
    formats = []
    for source in ("chrome-csv", "firefox-csv", "safari-csv", *providers):
        targets = [target for target in providers if target != source]
        formats.append({"id": source, "inspect": True, "plan_targets": targets,
                        "convert_targets": targets, "destination_comparison": True,
                        "provider_import_verified": False})
    return {"formats": formats, "output_platform_supported": supported}


class SmokeArchiveTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.directory = Path(self.scratch.name) / "assets"
        self.directory.mkdir()
        self.members = {}
        for goos, arch in TARGETS:
            self.members[(goos, arch)] = member_bytes(goos, arch)
            self.write_archive(goos, arch)
        self.write_manifest()
        self.calls = []

    def name(self, goos, arch):
        extension = "zip" if goos == "windows" else "tar.gz"
        return f"pwmigrate-go_{VERSION}_{goos}_{arch}.{extension}"

    def write_archive(self, goos, arch, special=None):
        (self.directory / self.name(goos, arch)).write_bytes(archive_bytes(goos, self.members[(goos, arch)], special))

    def write_manifest(self, mutate=None):
        self.manifest = {"schema_version": 1, "version": VERSION, "commit": COMMIT,
                         "go_version": "go1.26.9", "artifacts": []}
        for goos, arch in TARGETS:
            name = self.name(goos, arch)
            data = (self.directory / name).read_bytes()
            self.manifest["artifacts"].append({"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        if mutate:
            mutate(self.manifest)
        (self.directory / "release-manifest.json").write_text(json.dumps(self.manifest) + "\n", encoding="utf-8")
        self.write_checksums()

    def write_checksums(self):
        names = [self.name(goos, arch) for goos, arch in TARGETS] + ["release-manifest.json"]
        (self.directory / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((self.directory / name).read_bytes()).hexdigest()}  {name}\n" for name in names), encoding="ascii")

    def executor(self, executable, args, work):
        self.assertTrue(Path(executable).is_file())
        self.assertEqual(Path(executable).parent, Path(work))
        self.assertEqual(set(path.name for path in Path(work).iterdir()), {"pwmigrate-go"})
        if os.name != "nt":
            self.assertEqual(Path(work).stat().st_mode & 0o777, 0o700)
            self.assertEqual(Path(executable).stat().st_mode & 0o777, 0o700)
        self.calls.append((Path(executable), tuple(args)))
        if args == ["version", "--json"]:
            return 0, json.dumps(metadata("linux", "amd64")).encode(), b""
        if args == ["help"]:
            return 0, b"pwmigrate-go: inspect plan convert compare recovery-key recover formats version\nGenerated exports are plaintext; destination provider acceptance is unverified.\n", b""
        if args == ["formats", "--json"]:
            return 0, json.dumps(capabilities()).encode(), b""
        self.fail("unexpected runtime invocation")

    def invoke(self, **changes):
        arguments = dict(directory=self.directory, goos="linux", goarch="amd64", commit=COMMIT,
                         version=VERSION, expect_output_supported=True, executor=self.executor)
        arguments.update(changes)
        with mock.patch.object(smoke_archive, "host_target", return_value=("linux", "amd64"), create=True):
            return smoke_archive.smoke(**arguments)

    def rejected_without_execution(self, **changes):
        with self.assertRaises(smoke_archive.SmokeError):
            self.invoke(**changes)
        self.assertEqual(self.calls, [])

    def test_valid_complete_set_runs_only_selected_verified_binary_and_cleans(self):
        self.invoke()
        self.assertEqual([args for _, args in self.calls], [("version", "--json"), ("help",), ("formats", "--json")])
        self.assertFalse(self.calls[0][0].parent.exists())

    def test_wrong_requested_identity_prevents_execution(self):
        self.rejected_without_execution(commit="f" * 40)
        self.rejected_without_execution(version="v0.0.0-ci.124")

    def test_manifest_identity_toolchain_and_schema_are_exact(self):
        for key, value in (("commit", "f" * 40), ("version", "v1.0.0"), ("go_version", "go1.26.0"),
                           ("schema_version", True), ("schema_version", 2), ("extra", "unknown")):
            with self.subTest(key=key):
                self.write_manifest(lambda value_map: value_map.update({key: value}))
                self.rejected_without_execution()

    def test_checksum_tampering_and_missing_complete_set_prevent_execution(self):
        target = self.directory / self.name("linux", "amd64")
        original = target.read_bytes()
        target.write_bytes(original + b"tamper")
        self.rejected_without_execution()
        target.write_bytes(original)
        (self.directory / self.name("windows", "arm64")).unlink()
        self.rejected_without_execution()

    def test_bad_checksum_rows_and_duplicate_json_keys_prevent_execution(self):
        sums = self.directory / "SHA256SUMS"
        text = sums.read_text()
        for changed in (text.rstrip("\n"), text + text.splitlines(keepends=True)[0], text + "0" * 64 + "  ../outside\n"):
            sums.write_text(changed)
            self.rejected_without_execution()
        sums.write_text(text)
        manifest = self.directory / "release-manifest.json"
        manifest.write_text(manifest.read_text().replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1'))
        self.write_checksums()
        self.rejected_without_execution()

    def test_unsafe_duplicate_extra_and_special_members_prevent_execution(self):
        for goos in ("linux", "windows"):
            original = self.members[(goos, "amd64")]
            for kind in ("traversal", "duplicate", "extra", "special"):
                with self.subTest(goos=goos, kind=kind):
                    changed = list(original)
                    special = None
                    if kind == "traversal":
                        changed[1] = ("../outside", changed[1][1])
                    elif kind == "duplicate":
                        changed[1] = changed[0]
                    elif kind == "extra":
                        changed.append(("unexpected", b"synthetic"))
                    else:
                        special = changed[0][0]
                    self.members[(goos, "amd64")] = changed
                    self.write_archive(goos, "amd64", special)
                    self.write_manifest()
                    self.rejected_without_execution()
            self.members[(goos, "amd64")] = original
            self.write_archive(goos, "amd64")
        self.write_manifest()

    def test_each_archive_header_and_embedded_identity_checked_before_execution(self):
        for goos, arch in TARGETS:
            original = self.members[(goos, arch)]
            for changed_index, changed_bytes in ((0, b"invalid executable"), (4, json.dumps(metadata(goos, "arm64" if arch == "amd64" else "amd64")).encode())):
                with self.subTest(goos=goos, arch=arch, changed_index=changed_index):
                    changed = list(original)
                    changed[changed_index] = (changed[changed_index][0], changed_bytes)
                    self.members[(goos, arch)] = changed
                    self.write_archive(goos, arch)
                    self.write_manifest()
                    self.rejected_without_execution()
            self.members[(goos, arch)] = original
            self.write_archive(goos, arch)
        self.write_manifest()

    def test_foreign_native_target_prevents_execution(self):
        self.rejected_without_execution(goos="darwin")
        self.rejected_without_execution(goarch="arm64")

    def test_failed_runtime_and_false_provider_claim_are_redacted_and_cleaned(self):
        def failing(executable, args, work):
            self.calls.append((Path(executable), tuple(args)))
            return 1, b"synthetic private stdout", b"synthetic private stderr"
        with self.assertRaises(smoke_archive.SmokeError) as error:
            self.invoke(executor=failing)
        self.assertNotIn("synthetic private", str(error.exception))
        self.assertFalse(self.calls[0][0].parent.exists())
        self.calls.clear()
        def false_capability(executable, args, work):
            result = self.executor(executable, args, work)
            if args == ["formats", "--json"]:
                report = capabilities()
                report["formats"][0]["provider_import_verified"] = True
                return 0, json.dumps(report).encode(), b""
            return result
        with self.assertRaises(smoke_archive.SmokeError):
            self.invoke(executor=false_capability)
        self.assertFalse(self.calls[0][0].parent.exists())

    def test_platform_support_disclosure_must_match_expected(self):
        with self.assertRaises(smoke_archive.SmokeError):
            self.invoke(expect_output_supported=False)

    def test_all_six_selected_targets_use_fixed_name_and_exact_native_metadata(self):
        for goos, arch in TARGETS:
            paths = []
            executable_name = "pwmigrate-go.exe" if goos == "windows" else "pwmigrate-go"
            def executor(executable, args, work):
                self.assertEqual(set(path.name for path in Path(work).iterdir()), {executable_name})
                paths.append(Path(executable))
                if args[0] == "version":
                    return 0, json.dumps(metadata(goos, arch)).encode(), b""
                if args[0] == "formats":
                    return 0, json.dumps(capabilities(goos == "linux")).encode(), b""
                return 0, b"pwmigrate-go: inspect plan convert compare recovery-key recover formats version plaintext; destination provider acceptance is unverified", b""
            with self.subTest(goos=goos, arch=arch), mock.patch.object(smoke_archive, "host_target", return_value=(goos, arch)):
                smoke_archive.smoke(self.directory, goos, arch, COMMIT, VERSION, goos == "linux", executor)
            self.assertEqual(len(paths), 3)
            self.assertFalse(paths[0].parent.exists())

    def test_archive_and_binary_limits_reject_before_execution(self):
        with mock.patch.object(smoke_archive, "MAX_ARCHIVE", 8):
            self.rejected_without_execution()
        with mock.patch.object(smoke_archive, "MAX_BINARY", 256):
            self.rejected_without_execution()

    def test_wrong_architecture_header_prevents_execution_with_matching_metadata(self):
        original = self.members[("linux", "amd64")]
        changed = list(original)
        changed[0] = (changed[0][0], binary_header("linux", "arm64"))
        self.members[("linux", "amd64")] = changed
        self.write_archive("linux", "amd64")
        self.write_manifest()
        self.rejected_without_execution()

    def test_runtime_version_identity_failure_cleans_private_directory(self):
        def wrong_identity(executable, args, work):
            self.calls.append((Path(executable), tuple(args)))
            changed = metadata("linux", "amd64")
            changed["commit"] = "f" * 40
            return 0, json.dumps(changed).encode(), b""
        with self.assertRaises(smoke_archive.SmokeError):
            self.invoke(executor=wrong_identity)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.calls[0][0].parent.exists())

    def test_real_subprocess_capture_is_bounded(self):
        code, stdout, stderr = smoke_archive.run_binary(Path(sys.executable), ["-c", "print('synthetic runtime')"], self.scratch.name)
        self.assertEqual((code, stdout, stderr), (0, b"synthetic runtime\n", b""))
        with self.assertRaises(smoke_archive.SmokeError) as error:
            smoke_archive.run_binary(Path(sys.executable), ["-c", "import sys; sys.stdout.write('x' * 131072); sys.stdout.flush()"], self.scratch.name)
        self.assertEqual(str(error.exception), "archive_smoke_runtime")


if __name__ == "__main__":
    unittest.main()
