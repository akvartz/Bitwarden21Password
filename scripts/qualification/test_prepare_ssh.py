#!/usr/bin/env python3
"""Independent synthetic SSH companion regressions, standard library only."""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


REPOSITORY = Path(__file__).resolve().parents[2]
HELPER = REPOSITORY / "scripts/qualification/prepare_ssh.py"
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("qualification_prepare_ssh", HELPER)
KIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KIT)


class SSHMaterialTests(unittest.TestCase):
    def test_public_rfc8032_literals_and_known_der(self):
        self.assertEqual(KIT.PUBLIC_TEXT, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea\n")
        self.assertEqual(KIT.PKCS8_DER.hex(), "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        KIT.verify_private(KIT.PKCS8, "pkcs8")
        KIT.verify_private(KIT.OPENSSH, "openssh", "kit synthetic key")
        KIT.check_public(KIT.PUBLIC_TEXT)

    def test_private_seed_public_wrapper_comment_checkints_padding_and_count_rejected(self):
        packet = KIT.decode_pem(KIT.OPENSSH, "OPENSSH PRIVATE KEY")
        reader = KIT.WireReader(packet[len(KIT.MAGIC):])
        reader.string(); reader.string(); reader.string()
        count_offset = len(KIT.MAGIC) + reader.position
        reader.uint32()
        wrapper = reader.string()
        inner_offset = len(KIT.MAGIC) + reader.position + 4
        private = reader.string()
        inner = KIT.WireReader(private)
        inner.uint32(); inner.uint32(); inner.string(); inner.string()
        seed_offset = inner_offset + inner.position + 4
        mutations = []
        for offset in (packet.index(KIT.PUBLIC), seed_offset, seed_offset + 32, inner_offset + 4, len(packet) - 1):
            changed = bytearray(packet); changed[offset] ^= 1
            mutations.append(bytes(changed))
        changed = bytearray(packet); struct.pack_into(">I", changed, count_offset, 2); mutations.append(bytes(changed))
        mutations += [packet + b"unlisted", packet.replace(b"kit synthetic key", b"kit synthetic Key")]
        for number, changed in enumerate(mutations):
            with self.subTest(case=number), self.assertRaises(KIT.COMMON.Rejected):
                KIT.verify_private(KIT.pem("OPENSSH PRIVATE KEY", changed), "openssh", "kit synthetic key")
        for changed in (KIT.PKCS8_DER[:-1] + bytes([KIT.PKCS8_DER[-1] ^ 1]), KIT.PKCS8_DER + b"extra"):
            with self.assertRaises(KIT.COMMON.Rejected):
                KIT.verify_private(KIT.pem("PRIVATE KEY", changed), "pkcs8")

    def test_malformed_multiple_encrypted_and_large_key_representations_rejected(self):
        values = ["prefix\n" + KIT.OPENSSH, KIT.OPENSSH + KIT.OPENSSH, KIT.OPENSSH + "suffix",
                  KIT.OPENSSH.replace("OPENSSH PRIVATE KEY", "ENCRYPTED PRIVATE KEY"),
                  "x" * (KIT.KEY_LIMIT + 1)]
        for number, value in enumerate(values):
            with self.subTest(case=number), self.assertRaises(KIT.COMMON.Rejected):
                KIT.verify_private(value, "openssh", "kit synthetic key")
        for value in ("prefix\n" + KIT.PUBLIC_TEXT, KIT.PUBLIC_TEXT * 2, KIT.PUBLIC_TEXT.replace("AAAAC3", "AAAAD3"),
                      "command=\"invalid\" " + KIT.PUBLIC_TEXT):
            with self.assertRaises((KIT.COMMON.Rejected, ValueError)):
                KIT.check_public(value)

    def test_onepassword_key_metadata_aliases_and_duplicate_custom_multiplicity_rejected(self):
        with zipfile.ZipFile(io.BytesIO(KIT.fixture("onepassword-1pux", KIT.cases()))) as archive:
            root = json.loads(archive.read("export.data"))
        item = root["accounts"][0]["vaults"][0]["items"][0]
        original = copy.deepcopy(item)
        fields = item["details"]["sections"][0]["fields"]
        for change in ("type", "duplicate_private", "public", "fingerprint", "extra_alias", "multiple_ssh", "custom_type"):
            with self.subTest(case=change):
                item = copy.deepcopy(original)
                fields = item["details"]["sections"][0]["fields"]
                key = fields[0]["value"]["sshKey"]
                if change == "type": key["metadata"]["keyType"] = "rsa"
                elif change == "duplicate_private": key["privateKey"] += " "
                elif change == "public": key["metadata"]["publicKey"] += "extra"
                elif change == "fingerprint": key["metadata"]["fingerprint"] = "SHA256:invalid"
                elif change == "extra_alias": key["metadata"]["public_key"] = key["metadata"]["publicKey"]
                elif change == "multiple_ssh": fields.append(copy.deepcopy(fields[0]))
                else: fields[1]["guarded"] = 1
                with tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-metadata-") as scratch:
                    data = copy.deepcopy(root)
                    data["accounts"][0]["vaults"][0]["items"] = [item]
                    path = Path(scratch) / "mutated.1pux"
                    KIT.COMMON.private_write(path, KIT.COMMON.zip_fixture({"export.attributes": b'{"version":3}', "export.data": KIT.COMMON.encoded(data)}))
                    expected = KIT.expectations("bitwarden-json", "onepassword-1pux", KIT.cases()[:1])
                    with self.assertRaises(KIT.COMMON.Rejected): KIT.check_artifact(path, "onepassword-1pux", expected)
        actual = KIT.observed(original, "onepassword-1pux")
        self.assertEqual(actual["custom"], KIT.CUSTOM)
        self.assertEqual(actual["custom"][0], actual["custom"][1])

    def test_record_order_custom_multiplicity_and_archive_aliases_rejected(self):
        records = KIT.cases()
        data = json.loads(KIT.fixture("bitwarden-json", records))
        expected = KIT.expectations("bitwarden-json", "bitwarden-json", records)
        with tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-order-") as scratch:
            for number, change in enumerate(("count", "order", "custom_count", "custom_order", "public_comment")):
                mutated = copy.deepcopy(data)
                if change == "count": mutated["items"].pop()
                elif change == "order": mutated["items"][0], mutated["items"][1] = mutated["items"][1], mutated["items"][0]
                elif change == "custom_count": mutated["items"][0]["fields"].pop(0)
                elif change == "custom_order": mutated["items"][0]["fields"].reverse()
                else: mutated["items"][0]["sshKey"]["publicKey"] = KIT.PUBLIC_TEXT.rstrip("\n") + " changed comment\n"
                path = Path(scratch) / (str(number) + ".json")
                KIT.COMMON.private_write(path, KIT.COMMON.encoded(mutated))
                with self.subTest(case=change), self.assertRaises(KIT.COMMON.Rejected): KIT.check_artifact(path, "bitwarden-json", expected)
            payload = KIT.fixture("onepassword-1pux", records)
            with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                entries = {entry.filename: archive.read(entry) for entry in archive.infolist()}
            for number, change in enumerate(("extra", "duplicate", "nul_alias", "duplicate_json")):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    for name, value in entries.items():
                        if change == "duplicate" and name == "export.attributes": continue
                        if change == "duplicate_json" and name == "export.data":
                            value = value.replace(b'"accounts": [', b'"accounts": [],"accounts": [', 1)
                        archive.writestr(name, value)
                    if change == "extra": archive.writestr("unexpected", b"synthetic")
                    elif change == "duplicate":
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", UserWarning)
                            archive.writestr("export.data", entries["export.data"])
                payload = buffer.getvalue()
                if change == "nul_alias": payload = payload.replace(b"export.data", b"export\x00data")
                path = Path(scratch) / (str(number) + ".1pux")
                KIT.COMMON.private_write(path, payload)
                with self.subTest(case=change), self.assertRaises(KIT.COMMON.Rejected): KIT.artifact_records(path, "onepassword-1pux")

    def test_bounded_stdout_stderr_and_hung_descendant_pipes(self):
        for channel in ("stdout", "stderr"):
            code = "import sys;sys." + channel + ".write('x'*4096);sys." + channel + ".flush()"
            with self.subTest(channel=channel), patch.object(KIT, "REPORT_LIMIT", 128), self.assertRaises(KIT.COMMON.Rejected):
                KIT.run_json(Path(sys.executable), ["-c", code])
        with tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-pipe-") as scratch:
            marker = Path(scratch) / "pid"
            code = "import pathlib,subprocess,sys;child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']);pathlib.Path(sys.argv[1]).write_text(str(child.pid));print('{}',flush=True)"
            try:
                with self.assertRaises(KIT.COMMON.Rejected):
                    KIT.run_json(Path(sys.executable), ["-c", code, str(marker)])
            finally:
                if marker.exists():
                    os.kill(int(marker.read_text()), 9)

    def test_zip64_and_special_members_rejected_before_local_checks(self):
        records = KIT.cases()
        for record in records: record["pkcs8"] = KIT.PKCS8
        with zipfile.ZipFile(io.BytesIO(KIT.fixture("onepassword-1pux", records))) as archive:
            entries = {entry.filename: archive.read(entry) for entry in archive.infolist()}
        expected = KIT.expectations("bitwarden-json", "onepassword-1pux", records)
        cases = ["zip64", "local_zip64_only", "zip64_extra", "dangling_extra", "unknown_extra", "local_zip64_extra", "version45", "local_version45", "local_sentinel",
                 "central_sentinel", "local_flags", "local_method", "local_name", "symlink", "directory", "fifo", "socket", "char", "block", "public_mode"]
        modes = {"symlink": stat.S_IFLNK, "directory": stat.S_IFDIR, "fifo": stat.S_IFIFO,
                 "socket": stat.S_IFSOCK, "char": stat.S_IFCHR, "block": stat.S_IFBLK}
        with tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-archive-profile-") as scratch:
            for number, case in enumerate(cases):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    for name, data in entries.items():
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = (modes.get(case, stat.S_IFREG) | (0o777 if case == "public_mode" else 0o600)) << 16
                        if case == "zip64_extra": info.extra = struct.pack("<HHQ", 1, 8, len(data))
                        elif case == "dangling_extra": info.extra = b"X"
                        elif case == "unknown_extra": info.extra = struct.pack("<HHI", 0x4242, 4, 0)
                        elif case == "local_zip64_extra": info.extra = struct.pack("<HHBI", 0x5455, 5, 1, 0)
                        with archive.open(info, "w", force_zip64=case in ("zip64", "local_zip64_only")) as output: output.write(data)
                payload = bytearray(buffer.getvalue())
                central = payload.index(b"PK\x01\x02")
                if case == "local_zip64_only":
                    cursor = central
                    while payload[cursor:cursor + 4] == b"PK\x01\x02":
                        struct.pack_into("<H", payload, cursor + 6, 20)
                        lengths = struct.unpack_from("<3H", payload, cursor + 28)
                        cursor += 46 + sum(lengths)
                elif case == "version45": struct.pack_into("<H", payload, central + 6, 45)
                elif case == "local_version45": struct.pack_into("<H", payload, 4, 45)
                elif case == "central_sentinel": struct.pack_into("<I", payload, central + 24, 0xffffffff)
                elif case == "local_sentinel": struct.pack_into("<I", payload, 18, 0xffffffff)
                elif case == "local_flags": struct.pack_into("<H", payload, 6, 1)
                elif case == "local_method": struct.pack_into("<H", payload, 8, zipfile.ZIP_DEFLATED)
                elif case == "local_name": payload[30] ^= 1
                elif case == "local_zip64_extra": struct.pack_into("<H", payload, 30 + struct.unpack_from("<H", payload, 26)[0], 1)
                path = Path(scratch) / (str(number) + ".1pux")
                KIT.COMMON.private_write(path, bytes(payload))
                with self.subTest(case=case), self.assertRaises(KIT.COMMON.Rejected):
                    KIT.check_artifact(path, "onepassword-1pux", expected)

    def test_regular_unspecified_zero_modes_and_go_timestamps_are_admitted(self):
        records = KIT.cases()
        for record in records: record["pkcs8"] = KIT.PKCS8
        with zipfile.ZipFile(io.BytesIO(KIT.fixture("onepassword-1pux", records))) as archive:
            entries = {entry.filename: archive.read(entry) for entry in archive.infolist()}
        expected = KIT.expectations("bitwarden-json", "onepassword-1pux", records)
        with tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-ordinary-modes-") as scratch:
            for number, mode in enumerate((stat.S_IFREG | 0o600, 0o600, 0)):
                buffer = io.BytesIO()
                with zipfile.ZipFile(buffer, "w") as archive:
                    for name, data in entries.items():
                        info = zipfile.ZipInfo(name); info.create_system = 3
                        info.external_attr = mode << 16
                        info.extra = struct.pack("<HHBI", 0x5455, 5, 1, 0)
                        archive.writestr(info, data)
                payload = bytearray(buffer.getvalue())
                if mode == 0:
                    cursor = payload.index(b"PK\x01\x02")
                    while payload[cursor:cursor + 4] == b"PK\x01\x02":
                        struct.pack_into("<I", payload, cursor + 38, 0)
                        cursor += 46 + sum(struct.unpack_from("<3H", payload, cursor + 28))
                path = Path(scratch) / (str(number) + ".1pux")
                KIT.COMMON.private_write(path, bytes(payload))
                with self.subTest(mode_index=number): self.assertEqual(KIT.check_artifact(path, "onepassword-1pux", expected), 25)

    def test_library_failure_and_cancel_are_fixed(self):
        for error in (RuntimeError("PRIVATE_SENTINEL"), zipfile.BadZipFile("PRIVATE_SENTINEL"), KeyboardInterrupt()):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(KIT, "prepare", side_effect=error), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                result = KIT.main(["--binary", "unused", "--output", "unused"])
            cancelled = isinstance(error, KeyboardInterrupt)
            self.assertEqual(result, 130 if cancelled else 1)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(err.getvalue(), "qualification_ssh_kit: " + ("cancelled" if cancelled else "preparation_failed") + "\n")


class SSHJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not sys.platform.startswith("linux"):
            raise unittest.SkipTest("synthetic companion requires qualified Linux output")
        cls.scratch = tempfile.TemporaryDirectory(prefix="pwmigrate-ssh-kit-tests-")
        cls.parent = Path(cls.scratch.name)
        os.chmod(cls.parent, 0o700)
        configured = os.environ.get("PWMIGRATE_QUALIFICATION_BINARY")
        cls.binary = Path(configured).absolute() if configured else cls.parent / "candidate"
        if not configured:
            built = subprocess.run(["go", "build", "-o", str(cls.binary), "./cmd/pwmigrate"],
                                   cwd=REPOSITORY, capture_output=True, timeout=180, check=False)
            if built.returncode:
                raise RuntimeError("synthetic SSH candidate build failed")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix="case-", dir=self.parent))
        os.chmod(self.directory, 0o700)

    def invoke(self, binary=None, output=None, extra=()):
        return subprocess.run([sys.executable, "-B", str(HELPER), "--binary", str(binary or self.binary),
                               "--output", str(output or self.directory / "kit"), *extra],
                              capture_output=True, text=True, timeout=90, check=False)

    def safe_failure(self, completed, code=1):
        self.assertEqual(completed.returncode, code)
        self.assertEqual(completed.stdout, "")
        self.assertRegex(completed.stderr, r"\Aqualification_ssh_kit: [a-z_]+\n\Z")
        for forbidden in ("PRIVATE_SENTINEL", "Traceback", str(self.directory), "PRIVATE KEY"):
            self.assertNotIn(forbidden, completed.stderr)

    def test_existing_insecure_symlink_parent_and_arguments_rejected(self):
        root = self.directory / "existing"; root.mkdir(mode=0o700)
        marker = root / "unchanged"; marker.write_bytes(b"synthetic unchanged")
        self.safe_failure(self.invoke(output=root))
        self.assertEqual(marker.read_bytes(), b"synthetic unchanged")
        parent = self.directory / "insecure"; parent.mkdir(mode=0o777); parent.chmod(0o777)
        self.safe_failure(self.invoke(output=parent / "kit"))
        self.assertFalse((parent / "kit").exists())
        link = self.directory / "link"; link.symlink_to(self.directory, target_is_directory=True)
        self.safe_failure(self.invoke(output=link / "kit"))
        self.safe_failure(self.invoke(extra=("--input", "PRIVATE_SENTINEL")), code=2)

    def test_expectations_exist_before_any_candidate_command(self):
        fake = self.directory / "expectation-checker"
        root = self.directory / "kit"
        script = "#!/usr/bin/env python3\nimport pathlib,subprocess,sys\nroot=pathlib.Path(" + repr(str(root)) + ")\n"
        script += "if not (root/'private-expectations.json').is_file() or len(list((root/'sources').iterdir()))!=3:sys.exit(90)\n"
        script += "sys.exit(subprocess.call([" + repr(str(self.binary)) + ",*sys.argv[1:]]))\n"
        fake.write_text(script); fake.chmod(0o700)
        self.assertEqual(self.invoke(binary=fake, output=root).returncode, 0)

    def test_bad_review_not_approved_and_completed_plan_cannot_change(self):
        for phase in ("unknown_issue", "duplicate_json", "wrong_count", "completion_change"):
            with self.subTest(phase=phase):
                marker = self.directory / (phase + "-approved")
                fake = self.directory / (phase + "-candidate")
                script = '''#!/usr/bin/env python3
import json,pathlib,subprocess,sys
REAL=__REAL__
PHASE=__PHASE__
MARKER=__MARKER__
args=sys.argv[1:]
if args[0]!='convert':sys.exit(subprocess.call([REAL,*args]))
source=args[args.index('--from')+1];target=args[args.index('--to')+1]
plan={'source':source,'target':target,'state':'planned','total_records':3,'selected_records':3,'excluded_records':0,'output_emitted':False,'destination_import_verified':False,'fields':[],'metadata':[]}
profile='bitwarden-to-'+target+'-v1'
review={'event':'review','review':{'profile':profile,'review_id':'ABCDEFGHIJKLMNOP','plan':plan,'issues':[{'id':'experimental-import','code':'experimental_import'}]}}
if PHASE=='unknown_issue':review['review']['issues'].append({'id':'PRIVATE_SENTINEL','code':'unknown'})
if PHASE=='wrong_count':plan['selected_records']=True
body=json.dumps(review)
if PHASE=='duplicate_json':body=body.replace('"event": "review"','"event":"ignored","event":"review"')
print(body,flush=True)
reply=sys.stdin.readline()
if reply:pathlib.Path(MARKER).write_text(reply)
if PHASE=='completion_change':
 outcome=dict(plan);outcome.update(state='output_validated',output_emitted=True)
 outcome['fields']=[{'record':1,'field':1,'target_field':'/name','disposition':'native','concealed':False}]
 print(json.dumps({'event':'completed','receipt':{'profile':profile,'plan':outcome}}),flush=True)
'''
                for token, literal in (("__REAL__", repr(str(self.binary))), ("__PHASE__", repr(phase)), ("__MARKER__", repr(str(marker)))):
                    script = script.replace(token, literal)
                fake.write_text(script); fake.chmod(0o700)
                result = self.invoke(binary=fake, output=self.directory / (phase + "-kit"))
                self.safe_failure(result)
                self.assertEqual(marker.exists(), phase == "completion_change")
                if marker.exists(): self.assertEqual(marker.read_text(), "approve ABCDEFGHIJKLMNOP experimental-import\n")

    def test_completed_mutated_key_material_refuses_manifest(self):
        fake = self.directory / "mutator"
        script = '''#!/usr/bin/env python3
import base64,json,pathlib,subprocess,sys,zipfile,io
REAL=__REAL__
args=sys.argv[1:]
if args[0]!='convert':sys.exit(subprocess.call([REAL,*args]))
child=subprocess.Popen([REAL,*args],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
print(child.stdout.readline(),end='',flush=True)
child.stdin.write(sys.stdin.readline());child.stdin.flush()
rest,_=child.communicate(timeout=30)
receipt=json.loads(rest)['receipt'];parent=pathlib.Path(args[args.index('--output-dir')+1])
path=parent/receipt['job_directory']/receipt['file_name']
with zipfile.ZipFile(path) as archive:entries={f.filename:archive.read(f) for f in archive.infolist()}
data=json.loads(entries['export.data']);key=data['accounts'][0]['vaults'][0]['items'][0]['details']['sections'][0]['fields'][0]['value']['sshKey']
pem=key['privateKey'];raw=bytearray(base64.b64decode(''.join(pem.splitlines()[1:-1])));raw[-1]^=1
text=base64.b64encode(raw).decode();changed='-----BEGIN PRIVATE KEY-----\\n'+text+'\\n-----END PRIVATE KEY-----\\n'
key['privateKey']=key['metadata']['privateKey']=changed
entries['export.data']=json.dumps(data).encode()
with zipfile.ZipFile(path,'w') as archive:
 for name,value in entries.items():archive.writestr(name,value)
print(rest,end='',flush=True)
sys.exit(child.returncode)
'''.replace("__REAL__", repr(str(self.binary)))
        fake.write_text(script); fake.chmod(0o700)
        self.safe_failure(self.invoke(binary=fake))
        self.assertFalse((self.directory / "kit/result-manifest.json").exists())

    def test_real_candidate_six_routes_private_files_and_honest_evidence(self):
        completed = self.invoke()
        self.assertEqual(completed.returncode, 0, "SSH preparation must complete six routes")
        self.assertEqual(completed.stderr, "")
        self.assertEqual(completed.stdout, "qualification_ssh_kit: prepared; routes=6; local_key_material=passed; provider_import=not_run; ssh_authentication=not_run\n")
        root = self.directory / "kit"
        manifest = json.loads((root / "result-manifest.json").read_text())
        self.assertEqual(len(manifest["routes"]), 6)
        self.assertEqual(manifest["provider_import"], "not_run")
        self.assertEqual(manifest["ssh_authentication"], "not_run")
        for route in manifest["routes"]:
            self.assertEqual(route["records"], 3)
            self.assertEqual(route["case_ids"], ["ssh-ed25519-basic", "ssh-ed25519-whitespace", "ssh-ed25519-duplicate"])
            self.assertEqual(route["local_key_material"], "passed")
            self.assertEqual(route["provider_import"], "not_run")
            self.assertEqual(route["ssh_authentication"], "not_run")
        for path in [root, *root.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o700 if path.is_dir() else 0o600)
        serialized = json.dumps(manifest)
        for forbidden in ("PRIVATE KEY", "ssh-ed25519 ", "SHA256:", "kit SSH text", str(root), "review_id"):
            self.assertNotIn(forbidden, serialized, "safe manifest must not contain key material or paths")


if __name__ == "__main__":
    unittest.main()
