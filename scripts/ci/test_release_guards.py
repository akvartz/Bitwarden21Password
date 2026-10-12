"""Exercise the release workflow's inline guards without executing a release."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/release.yml"
TAG = "v1.2.3-rc.1"
COMMIT = "1234567890abcdef1234567890abcdef12345678"
ARCHIVES = (
    f"pwmigrate-go_{TAG}_darwin_amd64.tar.gz",
    f"pwmigrate-go_{TAG}_darwin_arm64.tar.gz",
    f"pwmigrate-go_{TAG}_linux_amd64.tar.gz",
    f"pwmigrate-go_{TAG}_linux_arm64.tar.gz",
    f"pwmigrate-go_{TAG}_windows_amd64.zip",
    f"pwmigrate-go_{TAG}_windows_arm64.zip",
)


class ReleaseGuards(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.assets = self.root / "assets"
        self.assets.mkdir()
        self.manifest = {
            "schema_version": 1,
            "version": TAG,
            "commit": COMMIT,
            "go_version": "go1.26.9",
            "artifacts": [],
        }
        for name in ARCHIVES:
            payload = b"synthetic archive content: " + name.encode()
            (self.assets / name).write_bytes(payload)
            self.manifest["artifacts"].append(
                {"name": name, "sha256": hashlib.sha256(payload).hexdigest(), "size": len(payload)}
            )
        self.write_manifest()

    def script(self, name):
        self.assertTrue(WORKFLOW.is_file(), "release workflow guards are not implemented")
        lines = WORKFLOW.read_text().splitlines()
        begin = [i for i, line in enumerate(lines) if line.strip() == f"# BEGIN {name}"]
        end = [i for i, line in enumerate(lines) if line.strip() == f"# END {name}"]
        self.assertEqual(len(begin), 1, "guard marker must be unique")
        self.assertEqual(len(end), 1, "guard marker must be unique")
        indent = len(lines[begin[0]]) - len(lines[begin[0]].lstrip())
        return "\n".join(line[indent:] for line in lines[begin[0] + 1 : end[0]]) + "\n"

    def run_guard(self, name="asset validation", **overrides):
        env = dict(os.environ)
        env.update(
            TAG=TAG,
            COMMIT=COMMIT,
            EXPECTED_GO_VERSION="go1.26.9",
            RELEASE_DIR=str(self.assets),
            GITHUB_OUTPUT=str(self.root / "output"),
        )
        env.update(overrides)
        return subprocess.run(
            [sys.executable, "-c", self.script(name)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def write_manifest(self):
        (self.assets / "release-manifest.json").write_text(json.dumps(self.manifest) + "\n")
        self.write_checksums()

    def write_checksums(self):
        rows = []
        for name in sorted((*ARCHIVES, "release-manifest.json")):
            rows.append(f"{hashlib.sha256((self.assets / name).read_bytes()).hexdigest()}  {name}\n")
        (self.assets / "SHA256SUMS").write_text("".join(rows))

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse((self.root / "output").exists(), "rejected input produced trusted output")

    def test_accepts_strict_versions_and_exports_only_validated_tag(self):
        for tag in ("v0.0.0", "v1.2.3", "v1.2.3-rc.1", "v1.2.3-0", "v1.2.3-alpha-01"):
            with self.subTest(tag=tag):
                output = self.root / "output"
                output.unlink(missing_ok=True)
                result = self.run_guard("tag validation", TAG=tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), f"tag={tag}\n")

    def test_rejects_unsafe_and_noncanonical_tags(self):
        for tag in ("", "1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2.3-01",
                    "v1.2.3-rc.01", "v1.2.3-", "v1.2.3-a..b", "v1.2.3+build",
                    "v1.2.3\n", "v1.2.3\ncommit=bad", "v1.2.3/other", "--help",
                    "v1.2.3-$(id)", "v1.2.3-💥", "v1.2.3-" + "a" * 200):
            with self.subTest(tag=tag):
                self.assert_rejected(self.run_guard("tag validation", TAG=tag))

    def test_accepts_complete_verified_asset_set(self):
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_missing_extra_directory_and_symlink_assets(self):
        variants = ("missing", "extra", "directory", "symlink")
        for variant in variants:
            with self.subTest(variant=variant):
                target = self.assets / ARCHIVES[0]
                original = target.read_bytes()
                extra = self.assets / "unexpected"
                if variant == "missing":
                    target.unlink()
                elif variant == "extra":
                    extra.write_bytes(b"synthetic")
                elif variant == "directory":
                    target.unlink()
                    target.mkdir()
                else:
                    target.unlink()
                    try:
                        target.symlink_to(self.assets / ARCHIVES[1])
                    except OSError:
                        target.write_bytes(original)
                        continue
                result = self.run_guard()
                if target.is_dir():
                    target.rmdir()
                elif target.exists() or target.is_symlink():
                    target.unlink()
                target.write_bytes(original)
                extra.unlink(missing_ok=True)
                self.assert_rejected(result)

    def test_rejects_wrong_release_identity_and_metadata(self):
        for key, value in (("version", "v1.2.4"), ("commit", "0" * 40),
                           ("go_version", "go1.26.0"), ("schema_version", True),
                           ("schema_version", 2), ("extra", "unknown")):
            with self.subTest(key=key):
                original = dict(self.manifest)
                self.manifest[key] = value
                self.write_manifest()
                result = self.run_guard()
                self.manifest = original
                self.assert_rejected(result)

    def test_rejects_duplicate_and_traversal_manifest_names(self):
        for name in (ARCHIVES[1], "../outside", "/tmp/outside", "--help"):
            with self.subTest(name=name):
                self.manifest["artifacts"][0]["name"] = name
                self.write_manifest()
                self.assert_rejected(self.run_guard())
        self.manifest["artifacts"][0]["name"] = ARCHIVES[0]

    def test_rejects_duplicate_json_keys(self):
        path = self.assets / "release-manifest.json"
        path.write_text(path.read_text().replace('"schema_version": 1', '"schema_version": 2, "schema_version": 1'))
        self.write_checksums()
        self.assert_rejected(self.run_guard())

    def test_rejects_wrong_archive_size_or_digest(self):
        original = dict(self.manifest["artifacts"][0])
        for key, value in (("size", original["size"] + 1), ("size", True), ("sha256", "0" * 64)):
            with self.subTest(key=key):
                self.manifest["artifacts"][0] = dict(original)
                self.manifest["artifacts"][0][key] = value
                self.write_manifest()
                self.assert_rejected(self.run_guard())

    def test_rejects_modified_archive_and_checksum_path_injection(self):
        target = self.assets / ARCHIVES[0]
        original = target.read_bytes()
        target.write_bytes(b"modified synthetic bytes")
        self.assert_rejected(self.run_guard())
        target.write_bytes(original)
        sums = self.assets / "SHA256SUMS"
        sums.write_text(sums.read_text() + "0" * 64 + "  ../outside\n")
        self.assert_rejected(self.run_guard())

    def test_rejects_checksum_duplicates_missing_rows_and_missing_newline(self):
        sums = self.assets / "SHA256SUMS"
        original = sums.read_text()
        rows = original.splitlines(keepends=True)
        for text in (original + rows[0], "".join(rows[1:]), original.rstrip("\n")):
            with self.subTest(text=text[:8]):
                sums.write_text(text)
                self.assert_rejected(self.run_guard())


if __name__ == "__main__":
    unittest.main()
