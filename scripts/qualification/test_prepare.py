#!/usr/bin/env python3
"""Synthetic qualification-helper protocol and privacy regressions (stdlib)."""

import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib


REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / "scripts/qualification/prepare.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("qualification_prepare", HELPER)
KIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KIT)


class ProtocolProcess:
    def __init__(self, review, completed=b'{"event":"completed","receipt":{}}'):
        self.stdout, self.stdin = io.BytesIO(review + b"\n"), io.BytesIO()
        self.completed, self.approval = completed, None
        self.returncode = 0

    def communicate(self, approval, timeout=None):
        self.approval = approval
        return self.completed, None

    def poll(self):
        return 0

    def wait(self, timeout=None):
        return 0


class PrepareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not sys.platform.startswith("linux"):
            raise unittest.SkipTest("public qualification conversion requires Linux")
        cls.workspace = tempfile.TemporaryDirectory(prefix="pwmigrate-kit-tests-")
        cls.parent = Path(cls.workspace.name)
        os.chmod(cls.parent, 0o700)
        configured = os.environ.get("PWMIGRATE_QUALIFICATION_BINARY")
        cls.binary = Path(configured).absolute() if configured else cls.parent / "candidate"
        if not configured:
            completed = subprocess.run(["go", "build", "-o", str(cls.binary), "./cmd/pwmigrate"],
                                       cwd=REPOSITORY, capture_output=True, timeout=120, check=False)
            if completed.returncode:
                raise RuntimeError("qualification test candidate build failed")

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="case-", dir=self.parent))
        os.chmod(self.directory, 0o700)

    def invoke(self, binary=None, output=None, extra=()):
        return subprocess.run([sys.executable, "-B", str(HELPER), "--binary", str(binary or self.binary),
                               "--output", str(output or self.directory / "kit"), *extra],
                              capture_output=True, text=True, timeout=60, check=False)

    def assert_safe_failure(self, completed, fixed=None, code=1):
        self.assertTrue(completed.returncode == code, "unexpected helper return code")
        self.assertTrue(completed.stdout == "", "failure must emit no stdout")
        self.assertTrue(completed.stderr.startswith("qualification_kit: ")
                        and completed.stderr.count("\n") == 1, "failure must emit one fixed-code line")
        if fixed:
            self.assertTrue(completed.stderr == "qualification_kit: " + fixed + "\n", "wrong fixed failure code")
        self.assertTrue(not any(value in completed.stderr for value in
                        ("Traceback", "PRIVATE_JSON_SENTINEL", str(self.directory), str(REPOSITORY))),
                        "diagnostic leaked a traceback, payload or path")

    def fake_protocol(self, phase, value):
        marker = self.directory / "approval-received"
        path = self.directory / "fake-candidate"
        plan = {"source": "chrome-csv", "target": "bitwarden-json", "state": "planned", "total_records": 4, "selected_records": 4,
                "excluded_records": 0, "output_emitted": False,
                "destination_import_verified": False, "fields": []}
        program = '''#!/usr/bin/env python3
from pathlib import Path
import json,subprocess,sys
PHASE=__PHASE__
VALUE=json.loads(__VALUE__)
REAL=__REAL__
PLAN=json.loads(__PLAN__)
MARKER=__MARKER__
command=sys.argv[1]
if command=="version" and PHASE=="version":
    print(json.dumps(VALUE));sys.exit(0)
if command=="formats" and PHASE in ("formats","format_entry"):
    print(json.dumps({"formats":VALUE} if PHASE=="formats" else {"formats":[VALUE]}));sys.exit(0)
if command!="convert":
    sys.exit(subprocess.call([REAL,*sys.argv[1:]]))
review={"event":"review","review":{"profile":"chrome-to-bitwarden-json-v1","review_id":"ABCDEFGHIJKLMNOP","plan":PLAN,"issues":[{"id":"experimental-import","code":"experimental_import"}]}}
if PHASE=="review_event":review=VALUE
elif PHASE=="review":review["review"]=VALUE
elif PHASE=="issue":review["review"]["issues"].append(VALUE)
elif PHASE=="issue_id":review["review"]["issues"][0]["id"]=VALUE
elif PHASE=="issue_code":review["review"]["issues"][0]["code"]=VALUE
elif PHASE=="plan":review["review"]["plan"]=VALUE
elif PHASE=="plan_fields":review["review"]["plan"]["fields"]=VALUE
elif PHASE=="plan_field":review["review"]["plan"]["fields"]=[VALUE]
print(json.dumps(review),flush=True)
approval=sys.stdin.readline()
if approval:Path(MARKER).write_text("approval_received")
if PHASE.startswith("receipt"):
    outcome=dict(PLAN);outcome.update(state="output_validated",output_emitted=True)
    event={"event":"completed","receipt":{"profile":"chrome-to-bitwarden-json-v1","plan":outcome}}
    if PHASE=="receipt_event":event=VALUE
    elif PHASE=="receipt":event["receipt"]=VALUE
    else:event["receipt"]["plan"]=VALUE
    print(json.dumps(event),flush=True)
'''
        for token, literal in (("__PHASE__", repr(phase)), ("__VALUE__", repr(json.dumps(value))),
                               ("__REAL__", repr(str(self.binary))), ("__PLAN__", repr(json.dumps(plan))),
                               ("__MARKER__", repr(str(marker)))):
            program = program.replace(token, literal)
        path.write_text(program)
        os.chmod(path, 0o700)
        return path, marker

    def test_wrong_protocol_types_are_fixed_and_do_not_approve_bad_reviews(self):
        invalid = [None, [], 7, "PRIVATE_JSON_SENTINEL"]
        cases = [(phase, value) for phase in
                 ("version", "review_event", "review", "issue", "receipt_event", "receipt", "receipt_plan")
                 for value in invalid]
        cases += [("issue_id", []), ("issue_code", []), ("plan", []), ("plan_fields", {}),
                  ("plan_field", []), ("formats", []), ("format_entry", None)]
        for number, (phase, value) in enumerate(cases):
            with self.subTest(phase=phase, kind=type(value).__name__):
                fake, marker = self.fake_protocol(phase, value)
                result = self.invoke(fake, self.directory / ("kit-" + str(number)))
                self.assert_safe_failure(result)
                self.assertTrue(marker.exists() == phase.startswith("receipt"), "malformed review received approval")
                if marker.exists():
                    marker.unlink()
                self.assertFalse((self.directory / ("kit-" + str(number)) / "result-manifest.json").exists())

    def test_unknown_issue_is_never_approved(self):
        fake, marker = self.fake_protocol("issue", {"id": "unexpected-issue", "code": "unexpected_issue"})
        self.assert_safe_failure(self.invoke(fake), "unreviewed_issue")
        self.assertFalse(marker.exists(), "unknown issue received approval")

    def review_fixture(self):
        return {"event": "review", "review": {"profile": "chrome-to-bitwarden-json-v1", "review_id": "ABCDEFGHIJKLMNOP",
                "plan": {"source": "chrome-csv", "target": "bitwarden-json", "state": "planned",
                         "total_records": 4, "selected_records": 4, "excluded_records": 0,
                         "output_emitted": False, "destination_import_verified": False,
                         "fields": [{"record": 1, "field": 1, "disposition": "native", "target_field": "name", "concealed": False}]},
                "issues": [{"id": "experimental-import", "code": "experimental_import"}]}}

    def test_duplicate_review_keys_cannot_hide_unreviewed_issue(self):
        for duplicate in ('"issues"', '"\\u0069ssues"'):
            with self.subTest(escaped=duplicate.startswith('"\\')):
                raw = json.dumps(self.review_fixture()).replace('"issues": [',
                       '"issues": [{"id":"unknown-synthetic-issue","code":"unknown_synthetic_issue"}],'
                       + duplicate + ': [').encode()
                process = ProtocolProcess(raw)
                with patch.object(KIT.subprocess, "Popen", return_value=process):
                    with self.assertRaises(KIT.Rejected):
                        KIT.convert(self.binary, self.directory / "source", "chrome-csv", "bitwarden-json", self.directory, 4)
                self.assertIsNone(process.approval, "duplicate issue key received approval")

    def test_completed_plan_must_match_current_review_with_exact_types(self):
        job = self.directory / "job"
        job.mkdir(mode=0o700)
        KIT.private_write(job / "bitwarden.json", b"{}")
        review = self.review_fixture()
        baseline = copy.deepcopy(review["review"]["plan"])
        baseline.update(state="output_validated", output_emitted=True)
        mutations = [("source", []), ("target", None), ("selected_records", "wrong"), ("selected_records", 4.0),
                     ("total_records", False), ("total_records", 99), ("excluded_records", 99),
                     ("excluded_records", False), ("state", "planned")]
        for field, value in mutations:
            with self.subTest(field=field, kind=type(value).__name__):
                outcome = copy.deepcopy(baseline)
                outcome[field] = value
                completed = {"event": "completed", "receipt": {"profile": "chrome-to-bitwarden-json-v1",
                             "job_directory": "job", "file_name": "bitwarden.json", "plan": outcome}}
                process = ProtocolProcess(json.dumps(review).encode(), KIT.encoded(completed))
                with patch.object(KIT.subprocess, "Popen", return_value=process), self.assertRaises(KIT.Rejected):
                    KIT.convert(self.binary, self.directory / "source", "chrome-csv", "bitwarden-json", self.directory, 4)
        for field, value in (("record", True), ("field", 1.0), ("concealed", "false"), ("disposition", "unknown"), ("target_field", None)):
            with self.subTest(ordinal_field=field):
                outcome = copy.deepcopy(baseline)
                outcome["fields"][0][field] = value
                completed = {"event": "completed", "receipt": {"profile": "chrome-to-bitwarden-json-v1",
                             "job_directory": "job", "file_name": "bitwarden.json", "plan": outcome}}
                process = ProtocolProcess(json.dumps(review).encode(), KIT.encoded(completed))
                with patch.object(KIT.subprocess, "Popen", return_value=process), self.assertRaises(KIT.Rejected):
                    KIT.convert(self.binary, self.directory / "source", "chrome-csv", "bitwarden-json", self.directory, 4)

    def test_artifact_item_and_custom_types_are_not_coerced(self):
        expected = KIT.expected_records("bitwarden-json", KIT.cases())
        baseline = json.loads(KIT.bitwarden_fixture(KIT.cases()))
        mutations = [("item", value) for value in (True, 1.0)]
        mutations += [("custom", value) for value in (False, 0.0, 2, 3, "0")]
        for number, (kind, value) in enumerate(mutations):
            with self.subTest(kind=kind, value_kind=type(value).__name__):
                data = copy.deepcopy(baseline)
                if kind == "item":
                    data["items"][0]["type"] = value
                else:
                    data["items"][0]["fields"][0]["type"] = value
                path = self.directory / ("typed-" + str(number) + ".json")
                KIT.private_write(path, KIT.encoded(data))
                with self.assertRaises(KIT.Rejected):
                    KIT.check_artifact(path, "bitwarden-json", expected)

    def test_duplicate_artifact_keys_rejected_in_json_and_archives(self):
        fixtures = [("bitwarden-json", KIT.bitwarden_fixture(KIT.cases())),
                    ("onepassword-1pux", KIT.onepassword_fixture(KIT.cases())),
                    ("proton-pass-zip", KIT.proton_fixture(KIT.cases()))]
        for target, payload in fixtures:
            with self.subTest(target=target):
                if target == "bitwarden-json":
                    mutated = payload.replace(b'"items": [', b'"items": [],"items": [', 1)
                else:
                    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                        entries = {entry.filename: archive.read(entry) for entry in archive.infolist()}
                    member = "export.data" if target == "onepassword-1pux" else "Proton Pass/data.json"
                    if target == "onepassword-1pux":
                        entries[member] = entries[member].replace(b'"accounts": [', b'"accounts": [],"accounts": [', 1)
                    else:
                        entries[member] = entries[member].replace(b'"vaults": {', b'"vaults": {},"vaults": {', 1)
                    mutated = KIT.zip_fixture(entries)
                path = self.directory / target
                KIT.private_write(path, mutated)
                with self.assertRaises(KIT.Rejected):
                    KIT.check_artifact(path, target, KIT.expected_records(target, KIT.cases()))

    def test_onepassword_concealment_and_proton_custom_kinds_are_explicit(self):
        payload = KIT.onepassword_fixture(KIT.cases())
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            baseline = {entry.filename: archive.read(entry) for entry in archive.infolist()}
        for number, guarded in enumerate((0, "false", True)):
            with self.subTest(guarded_kind=type(guarded).__name__):
                data = json.loads(baseline["export.data"])
                data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][0]["guarded"] = guarded
                entries = dict(baseline)
                entries["export.data"] = KIT.encoded(data)
                path = self.directory / ("guarded-" + str(number) + ".1pux")
                KIT.private_write(path, KIT.zip_fixture(entries))
                with self.assertRaises(KIT.Rejected):
                    KIT.check_artifact(path, "onepassword-1pux", KIT.expected_records("onepassword-1pux", KIT.cases()))
        data = json.loads(baseline["export.data"])
        value = data["accounts"][0]["vaults"][0]["items"][0]["details"]["sections"][0]["fields"][0]["value"]
        value["concealed"] = value["string"]
        entries = dict(baseline)
        entries["export.data"] = KIT.encoded(data)
        path = self.directory / "ambiguous.1pux"
        KIT.private_write(path, KIT.zip_fixture(entries))
        with self.assertRaises(KIT.Rejected):
            KIT.check_artifact(path, "onepassword-1pux", KIT.expected_records("onepassword-1pux", KIT.cases()))
        with zipfile.ZipFile(io.BytesIO(KIT.proton_fixture(KIT.cases()))) as archive:
            data = json.loads(archive.read("Proton Pass/data.json"))
        for number, kind in enumerate((True, "totp", "unknown")):
            with self.subTest(proton_kind=type(kind).__name__):
                mutated = copy.deepcopy(data)
                mutated["vaults"]["kit-vault"]["items"][0]["data"]["extraFields"].append(
                    {"fieldName": "kit unexpected", "type": kind, "data": {"content": "kit value"}})
                path = self.directory / ("proton-kind-" + str(number) + ".zip")
                KIT.private_write(path, KIT.zip_fixture({"Proton Pass/data.json": KIT.encoded(mutated)}))
                with self.assertRaises(KIT.Rejected):
                    KIT.check_artifact(path, "proton-pass-zip", KIT.expected_records("proton-pass-zip", KIT.cases()))

    def test_completed_bad_archive_is_sanitized(self):
        fake = self.directory / "archive-mutator"
        program = '''#!/usr/bin/env python3
from pathlib import Path
import json,subprocess,sys
REAL=__REAL__
args=sys.argv[1:]
if args[0]!="convert" or args[args.index("--to")+1]!="onepassword-1pux":
    sys.exit(subprocess.call([REAL,*args]))
child=subprocess.Popen([REAL,*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
print(child.stdout.readline(),end="",flush=True)
child.stdin.write(sys.stdin.readline());child.stdin.flush()
rest,_=child.communicate()
receipt=json.loads(rest)["receipt"]
parent=Path(args[args.index("--output-dir")+1])
(parent/receipt["job_directory"]/receipt["file_name"]).write_bytes(b"not-a-zip")
print(rest,end="",flush=True)
sys.exit(child.returncode)
'''.replace("__REAL__", repr(str(self.binary)))
        fake.write_text(program)
        os.chmod(fake, 0o700)
        self.assert_safe_failure(self.invoke(fake), "preparation_failed")
        self.assertFalse((self.directory / "kit/result-manifest.json").exists())

    def test_library_errors_and_cancellation_keep_fixed_boundary(self):
        errors = [zipfile.BadZipFile("PRIVATE_JSON_SENTINEL"), zlib.error("PRIVATE_JSON_SENTINEL"),
                  RuntimeError("PRIVATE_JSON_SENTINEL"), NotImplementedError("PRIVATE_JSON_SENTINEL"),
                  KeyboardInterrupt()]
        for error in errors:
            with self.subTest(kind=type(error).__name__):
                output, diagnostic = io.StringIO(), io.StringIO()
                with patch.object(KIT, "prepare", side_effect=error), contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostic):
                    code = KIT.main(["--binary", "unused", "--output", "unused"])
                self.assertTrue(output.getvalue() == "", "exception emitted stdout")
                cancelled = isinstance(error, KeyboardInterrupt)
                self.assertTrue(code == (130 if cancelled else 1), "wrong exception return code")
                self.assertTrue(diagnostic.getvalue() == ("qualification_kit: cancelled\n" if cancelled else
                                "qualification_kit: preparation_failed\n"), "library exception escaped fixed boundary")

    def test_all_routes_private_manifest_and_no_clobber(self):
        root = self.directory / "kit"
        completed = self.invoke(output=root)
        self.assertTrue(completed.returncode == 0, "synthetic fifteen-route preparation failed")
        manifest_path = root / "result-manifest.json"
        before = manifest_path.read_bytes()
        manifest = json.loads(before)
        self.assertEqual(len(manifest["routes"]), 15)
        self.assertTrue(all(route["provider_import"] == "not_run" for route in manifest["routes"]))
        self.assertEqual(set(manifest), {"schema_version", "version", "commit", "source_app_export", "provider_import", "routes"})
        allowed = {"route_id", "profile", "records", "case_ids", "acknowledged_issues", "local_field_checks", "local_mapping", "provider_import"}
        self.assertTrue(all(set(route) == allowed for route in manifest["routes"]))
        for path in root.rglob("*"):
            self.assertFalse(path.is_symlink())
            self.assertTrue(stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600), "generated mode is not private")
        self.assertTrue(not any(value in before.decode("utf-8") for value in
                        ("kit-user", "kit-password", "kit@example.invalid", "qualification.invalid", str(root), "kit text", "kit hidden")),
                        "public manifest leaked a source value, label or path")
        self.assert_safe_failure(self.invoke(output=root), "output_exists")
        self.assertTrue(manifest_path.read_bytes() == before, "existing output was changed")
        index = json.loads((root / "private-index.json").read_bytes())
        route = next(entry for entry in index["routes"] if entry["route_id"] == "chrome-csv-to-bitwarden-json")
        data = json.loads((root / route["artifact_file"]).read_bytes())
        data["items"][0]["login"]["username"] += " "
        mutated = self.directory / "mutated.json"
        KIT.private_write(mutated, KIT.encoded(data))
        expected = json.loads((root / "private-expectations.json").read_bytes())["routes"][route["route_id"]]
        with self.assertRaisesRegex(KIT.Rejected, "^local_field_mismatch$"):
            KIT.check_artifact(mutated, "bitwarden-json", expected)

    def test_insecure_and_symlink_parents_rejected(self):
        insecure = self.directory / "insecure"
        insecure.mkdir(mode=0o700)
        insecure.chmod(0o777)
        self.assert_safe_failure(self.invoke(output=insecure / "kit"), "private_parent_required")
        self.assertFalse((insecure / "kit").exists())
        link = self.directory / "symlink"
        link.symlink_to(self.directory, target_is_directory=True)
        self.assert_safe_failure(self.invoke(output=link / "kit"), "private_parent_required")

    def test_argument_diagnostics_do_not_echo_values(self):
        self.assert_safe_failure(self.invoke(extra=("--unexpected", "PRIVATE_JSON_SENTINEL")), "invalid_arguments", code=2)


if __name__ == "__main__":
    unittest.main()
