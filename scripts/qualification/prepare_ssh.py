#!/usr/bin/env python3
"""Prepare independent synthetic Ed25519 fixtures for six provider directions.

This is a narrow verifier for one public RFC 8032 fixture, not a crypto library.
It checks stored key bytes; native import and SSH authentication are not run.
"""
import base64
import copy
import hashlib
import importlib.util
import io
from pathlib import Path
import queue
import re
import stat
import struct
import subprocess
import sys
import threading
import zipfile
import zlib


# Reuse the reviewed private-file and exact live approval protocol, not any
# production adapter or converter output as an expected fixture.
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("qualification_common", Path(__file__).with_name("prepare.py"))
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

FORMATS = ("bitwarden-json", "onepassword-1pux", "proton-pass-zip")
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
ALGORITHM = b"ssh-ed25519"
MAGIC = b"openssh-key-v1\x00"
PKCS8_DER = bytes.fromhex("302e020100300506032b657004220420") + SEED
KEY_LIMIT = 16 * 1024
REPORT_LIMIT = COMMON.BYTE_LIMIT
CUSTOM = [{"name": "kit SSH text", "value": " text\r\nvalue ", "hidden": False},
          {"name": "kit SSH text", "value": " text\r\nvalue ", "hidden": False},
          {"name": "kit SSH hidden", "value": " hidden\r\nvalue ", "hidden": True}]


class SafeParser(COMMON.SafeParser):
    def error(self, message):
        self.exit(2, "qualification_ssh_kit: invalid_arguments\n")


class Candidate:
    """Bound each private pipe while draining both; publish no child diagnostics."""
    def __init__(self, binary, args, approval=False):
        self.process = subprocess.Popen([str(binary), *map(str, args)],
                                        stdin=subprocess.PIPE if approval else subprocess.DEVNULL,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self.errors, self.stderr = [], bytearray()
        self.threads = []
        self.start_drain(self.process.stderr, self.stderr)

    def start_drain(self, pipe, result):
        def drain():
            try:
                while True:
                    chunk = pipe.read(4096)
                    if not chunk:
                        return
                    if len(result) + len(chunk) > REPORT_LIMIT:
                        self.errors.append(True)
                        self.process.kill()
                        return
                    result.extend(chunk)
            except Exception:
                self.errors.append(True)
        thread = threading.Thread(target=drain, daemon=True)
        self.threads.append(thread)
        thread.start()

    def review_line(self):
        first = queue.Queue(maxsize=1)
        def read():
            try:
                first.put(self.process.stdout.readline(REPORT_LIMIT + 1))
            except Exception:
                first.put(b"")
        thread = threading.Thread(target=read, daemon=True)
        self.threads.append(thread)
        thread.start()
        line = first.get(timeout=COMMON.TIMEOUT)
        COMMON.require(0 < len(line) <= REPORT_LIMIT and line.endswith(b"\n") and not self.errors, "cli_review_limit")
        return line

    def finish(self, approval=None):
        if self.process.stdin is not None:
            COMMON.require(approval is not None and len(approval) <= 8192, "unexpected_approval")
            COMMON.require(self.process.stdin.write(approval) == len(approval), "unexpected_approval")
            self.process.stdin.close()
        stdout = bytearray()
        self.start_drain(self.process.stdout, stdout)
        self.process.wait(timeout=COMMON.TIMEOUT)
        for thread in self.threads:
            thread.join(timeout=1)
        COMMON.require(not self.errors and not any(thread.is_alive() for thread in self.threads), "cli_report_limit")
        # JSON conversion sends its live approval prompt to stderr. Retain it
        # only in this bounded private buffer; never publish child diagnostics.
        COMMON.require(self.process.returncode == 0 and (approval is not None or not self.stderr), "cli_command_failed")
        return bytes(stdout)

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=COMMON.TIMEOUT)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                pipe.close()


def run_json(binary, args):
    candidate = Candidate(binary, args)
    try:
        report = COMMON.strict_json(candidate.finish())
        COMMON.require(isinstance(report, dict), "unexpected_report")
        return report
    finally:
        candidate.close()


def convert(binary, source_path, source, target, parent, count):
    candidate = Candidate(binary, ["convert", "--input", source_path, "--from", source,
                                    "--to", target, "--output-dir", parent, "--json"], approval=True)
    try:
        event = COMMON.strict_json(candidate.review_line())
        COMMON.require(isinstance(event, dict) and event.get("event") == "review", "unexpected_review")
        review = event.get("review")
        COMMON.require(isinstance(review, dict), "unexpected_review")
        COMMON.check_plan(review.get("plan"), source, target, count)
        profile = COMMON.expected_profile(source, target)
        COMMON.require(review.get("profile") == profile, "unexpected_profile")
        review_id = review.get("review_id", "")
        COMMON.require(isinstance(review_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", review_id), "unexpected_review_id")
        issues = review.get("issues")
        COMMON.require(isinstance(issues, list) and 1 <= len(issues) <= 32, "unexpected_issues")
        identifiers = []
        for issue in issues:
            COMMON.require(isinstance(issue, dict), "unexpected_issues")
            identifier, code = issue.get("id"), issue.get("code")
            COMMON.require(isinstance(identifier, str) and isinstance(code, str), "unexpected_issues")
            COMMON.require(COMMON.KNOWN_ISSUES.get(identifier) == code and identifier not in identifiers, "unreviewed_issue")
            identifiers.append(identifier)
        COMMON.require("experimental-import" in identifiers, "missing_experimental_issue")
        approval = ("approve " + review_id + " " + " ".join(identifiers) + "\n").encode("ascii")
        completed = COMMON.strict_json(candidate.finish(approval))
        COMMON.require(isinstance(completed, dict) and completed.get("event") == "completed", "completion_required")
        receipt = completed.get("receipt")
        COMMON.require(isinstance(receipt, dict), "unexpected_completion")
        outcome = receipt.get("plan")
        COMMON.check_plan(outcome, source, target, count, state="output_validated", emitted=True)
        COMMON.require(receipt.get("profile") == profile
                       and outcome.get("fields", []) == review["plan"].get("fields", [])
                       and outcome.get("metadata", []) == review["plan"].get("metadata", []), "unexpected_completion")
        directory = receipt.get("job_directory")
        filename = {"bitwarden-json": "bitwarden.json", "onepassword-1pux": "onepassword.1pux", "proton-pass-zip": "proton-pass.zip"}[target]
        COMMON.require(isinstance(directory, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", directory)
                       and receipt.get("file_name") == filename, "unsafe_receipt")
        artifact = parent / directory / filename
        info, parent_info = artifact.lstat(), artifact.parent.lstat()
        COMMON.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= REPORT_LIMIT
                       and stat.S_IMODE(info.st_mode) == 0o600 and stat.S_ISDIR(parent_info.st_mode)
                       and stat.S_IMODE(parent_info.st_mode) == 0o700, "artifact_permissions")
        return artifact, profile, len(issues)
    finally:
        candidate.close()


def wire_string(value):
    return struct.pack(">I", len(value)) + value


PUBLIC_WIRE = wire_string(ALGORITHM) + wire_string(PUBLIC)
PUBLIC_TEXT = "ssh-ed25519 " + base64.b64encode(PUBLIC_WIRE).decode("ascii") + "\n"
FINGERPRINT = "SHA256:" + base64.b64encode(hashlib.sha256(PUBLIC_WIRE).digest()).decode("ascii").rstrip("=")


def pem(label, payload):
    text = base64.b64encode(payload).decode("ascii")
    return "-----BEGIN " + label + "-----\n" + "\n".join(text[i:i + 64] for i in range(0, len(text), 64)) + "\n-----END " + label + "-----\n"


PKCS8 = pem("PRIVATE KEY", PKCS8_DER)


def openssh_fixture():
    private = struct.pack(">II", 0x12345678, 0x12345678) + wire_string(ALGORITHM) + wire_string(PUBLIC)
    private += wire_string(SEED + PUBLIC) + wire_string(b"kit synthetic key")
    private += bytes(range(1, 8 - len(private) % 8 + 1))
    packet = MAGIC + wire_string(b"none") + wire_string(b"none") + wire_string(b"")
    packet += struct.pack(">I", 1) + wire_string(PUBLIC_WIRE) + wire_string(private)
    return pem("OPENSSH PRIVATE KEY", packet)


OPENSSH = openssh_fixture()


def cases():
    basic = {"case_id": "ssh-ed25519-basic", "name": "kit SSH Ed25519", "notes": " synthetic SSH note\r\n ",
             "public": PUBLIC_TEXT, "openssh": OPENSSH, "pkcs8": PKCS8, "custom": copy.deepcopy(CUSTOM)}
    whitespace = copy.deepcopy(basic)
    whitespace.update(case_id="ssh-ed25519-whitespace", name=" kit SSH whitespace ", notes=" first\r\nsecond\nthird\r ",
                      public="\t" + PUBLIC_TEXT.rstrip("\n") + " kit synthetic public comment \r\n",
                      openssh=" \n" + OPENSSH + "\t\r\n", pkcs8=" \n" + PKCS8 + "\t\r\n")
    duplicate = copy.deepcopy(basic)
    duplicate["case_id"] = "ssh-ed25519-duplicate"
    return [basic, whitespace, duplicate]


def fixture(source, records):
    items = []
    for ordinal, record in enumerate(records, 1):
        custom = record["custom"]
        if source == "bitwarden-json":
            item = {"type": 5, "name": record["name"], "notes": record["notes"],
                    "sshKey": {"privateKey": record["openssh"], "publicKey": record["public"], "keyFingerprint": FINGERPRINT},
                    "fields": [{"name": f["name"], "value": f["value"], "type": int(f["hidden"])} for f in custom]}
        elif source == "onepassword-1pux":
            fields = [{"id": "kit.ssh", "title": "Private key", "value": {"sshKey": {
                "privateKey": record["pkcs8"], "metadata": {"privateKey": record["pkcs8"], "publicKey": record["public"],
                "fingerprint": FINGERPRINT, "keyType": "ed25519"}}}}]
            fields += [{"id": "kit.custom." + str(i), "title": f["name"],
                        "value": {"concealed" if f["hidden"] else "string": f["value"]}} for i, f in enumerate(custom, 1)]
            item = {"uuid": "kit-ssh-item-" + str(ordinal), "categoryUuid": "114", "state": "active", "favIndex": 0,
                    "createdAt": 0, "updatedAt": 0, "overview": {"title": record["name"], "subtitle": "", "url": ""},
                    "details": {"notesPlain": record["notes"], "sections": [{"name": "kit", "title": "kit fields", "fields": fields}]}}
        else:
            item = {"itemId": "kit-ssh-item-" + str(ordinal), "contentFormatVersion": 1, "state": 1, "pinned": False,
                    "data": {"type": "sshKey", "metadata": {"name": record["name"], "note": record["notes"], "itemUuid": "kit-ssh-uuid-" + str(ordinal)},
                             "content": {"privateKey": record["openssh"], "publicKey": record["public"], "sections": []},
                             "extraFields": [{"fieldName": f["name"], "type": "hidden" if f["hidden"] else "text", "data": {"content": f["value"]}} for f in custom]}}
        items.append(item)
    if source == "bitwarden-json":
        return COMMON.encoded({"encrypted": False, "folders": [], "items": items})
    if source == "onepassword-1pux":
        data = {"accounts": [{"attrs": {"uuid": "kit-ssh-account", "name": "kit SSH", "accountName": "kit SSH", "email": "kit@example.invalid",
                                       "avatar": "", "domain": "qualification.invalid"},
                              "vaults": [{"attrs": {"uuid": "kit-ssh-vault", "name": "kit SSH", "desc": "", "avatar": "", "type": "P"}, "items": items}]}]}
        return COMMON.zip_fixture({"export.attributes": COMMON.encoded({"version": 3, "description": "1Password Unencrypted Export", "createdAt": 0}),
                                   "export.data": COMMON.encoded(data)})
    return COMMON.zip_fixture({"Proton Pass/data.json": COMMON.encoded({"version": "1.42.0", "vaults": {"kit-ssh-vault": {"name": "kit SSH", "items": items}}})})


def expectations(source, target, records):
    expected = []
    for ordinal, record in enumerate(records, 1):
        representation = "pkcs8" if target == "onepassword-1pux" else "openssh"
        exact = PKCS8 if representation == "pkcs8" else (record["openssh"] if source != "onepassword-1pux" else None)
        expected.append({"record": ordinal, "case_id": record["case_id"], "kind": "ssh_key", "name": record["name"], "notes": record["notes"],
                         "public": record["public"], "fingerprint": FINGERPRINT, "custom": copy.deepcopy(record["custom"]),
                         "private": {"representation": representation, "exact": exact,
                                     "comment": "" if source == "onepassword-1pux" else "kit synthetic key",
                                     "seed_hex": SEED.hex(), "public_hex": PUBLIC.hex()}})
    return expected


def decode_pem(value, label):
    COMMON.require(type(value) is str and len(value) <= KEY_LIMIT, "local_key_format")
    expression = r"[ \t\r\n]*-----BEGIN " + label + r"-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END " + label + r"-----[ \t\r\n]*"
    match = re.fullmatch(expression, value)
    COMMON.require(match is not None, "local_key_format")
    body = match[1].replace("\r", "").replace("\n", "")
    return base64.b64decode(body, validate=True)


class WireReader:
    def __init__(self, value):
        self.value, self.position = value, 0

    def uint32(self):
        COMMON.require(self.position + 4 <= len(self.value), "local_key_framing")
        value = struct.unpack_from(">I", self.value, self.position)[0]
        self.position += 4
        return value

    def string(self):
        length = self.uint32()
        COMMON.require(length <= KEY_LIMIT and self.position + length <= len(self.value), "local_key_framing")
        value = self.value[self.position:self.position + length]
        self.position += length
        return value

    def done(self):
        COMMON.require(self.position == len(self.value), "local_key_framing")


def verify_private(value, representation, comment=""):
    if representation == "pkcs8":
        COMMON.require(decode_pem(value, "PRIVATE KEY") == PKCS8_DER, "local_key_material_mismatch")
        return
    COMMON.require(representation == "openssh", "local_key_format")
    packet = decode_pem(value, "OPENSSH PRIVATE KEY")
    COMMON.require(packet.startswith(MAGIC), "local_key_framing")
    reader = WireReader(packet[len(MAGIC):])
    COMMON.require(reader.string() == b"none" and reader.string() == b"none" and reader.string() == b"" and reader.uint32() == 1,
                   "local_key_framing")
    COMMON.require(reader.string() == PUBLIC_WIRE, "local_key_material_mismatch")
    private = reader.string()
    reader.done()
    COMMON.require(len(private) % 8 == 0, "local_key_framing")
    inner = WireReader(private)
    COMMON.require(inner.uint32() == inner.uint32(), "local_key_framing")
    COMMON.require(inner.string() == ALGORITHM and inner.string() == PUBLIC and inner.string() == SEED + PUBLIC,
                   "local_key_material_mismatch")
    COMMON.require(inner.string() == comment.encode("ascii"), "local_key_comment_mismatch")
    padding = private[inner.position:]
    COMMON.require(1 <= len(padding) <= 8 and padding == bytes(range(1, len(padding) + 1)), "local_key_framing")


def check_public(value):
    COMMON.require(type(value) is str and len(value) <= KEY_LIMIT, "local_public_mismatch")
    line = value.strip(" \t\r\n")
    COMMON.require("\n" not in line and "\r" not in line and all(32 <= ord(ch) <= 126 or ch == "\t" for ch in line), "local_public_mismatch")
    parts = line.split()
    COMMON.require(len(parts) >= 2 and parts[0] == "ssh-ed25519" and base64.b64decode(parts[1], validate=True) == PUBLIC_WIRE, "local_public_mismatch")


def custom_value(name, value, hidden):
    COMMON.require(type(name) is str and type(value) is str and type(hidden) is bool, "local_custom_type")
    return {"name": name, "value": value, "hidden": hidden}


def observed(item, target):
    COMMON.require(isinstance(item, dict), "local_artifact_type")
    if target == "bitwarden-json":
        COMMON.require(type(item.get("type")) is int and item["type"] == 5, "local_artifact_type")
        key = item["sshKey"]
        COMMON.require(isinstance(key, dict) and set(key) == {"privateKey", "publicKey", "keyFingerprint"}, "local_key_shape")
        custom = []
        for field in item.get("fields", []):
            COMMON.require(isinstance(field, dict) and type(field.get("type")) is int and field["type"] in (0, 1), "local_custom_type")
            custom.append(custom_value(field["name"], field["value"], field["type"] == 1))
        return {"kind": "ssh_key", "name": item["name"], "notes": item["notes"], "private": key["privateKey"],
                "public": key["publicKey"], "fingerprint": key["keyFingerprint"], "custom": custom}
    if target == "proton-pass-zip":
        data = item["data"]
        COMMON.require(isinstance(data, dict) and data.get("type") == "sshKey", "local_artifact_type")
        key = data["content"]
        COMMON.require(isinstance(key, dict) and set(key) == {"privateKey", "publicKey", "sections"}, "local_key_shape")
        sections = key["sections"]
        COMMON.require(isinstance(sections, list) and len(sections) == 1, "local_fingerprint_shape")
        section = sections[0]
        COMMON.require(section == {"sectionName": "Extra fields", "sectionFields": [{"fieldName": "Key fingerprint", "type": "hidden", "data": {"content": FINGERPRINT}}]}, "local_fingerprint_mismatch")
        custom = []
        for field in data.get("extraFields", []):
            COMMON.require(isinstance(field, dict) and field.get("type") in ("hidden", "text") and set(field["data"]) == {"content"}, "local_custom_type")
            custom.append(custom_value(field["fieldName"], field["data"]["content"], field["type"] == "hidden"))
        return {"kind": "ssh_key", "name": data["metadata"]["name"], "notes": data["metadata"]["note"],
                "private": key["privateKey"], "public": key["publicKey"], "fingerprint": FINGERPRINT, "custom": custom}
    COMMON.require(item.get("categoryUuid") == "114", "local_artifact_type")
    details = item["details"]
    keys, custom = [], []
    for section in details.get("sections", []):
        for field in section.get("fields", []):
            value = field["value"]
            COMMON.require(isinstance(value, dict) and len(value) == 1, "local_key_shape")
            if "sshKey" in value:
                keys.append(value["sshKey"])
            else:
                COMMON.require(set(value) in ({"string"}, {"concealed"}) and type(field.get("guarded", False)) is bool, "local_custom_type")
                tag = next(iter(value))
                custom.append(custom_value(field["title"], value[tag], tag == "concealed" or field.get("guarded", False)))
    COMMON.require(len(keys) == 1 and isinstance(keys[0], dict) and set(keys[0]) == {"privateKey", "metadata"}, "local_key_shape")
    key, metadata = keys[0], keys[0]["metadata"]
    COMMON.require(isinstance(metadata, dict) and set(metadata) == {"privateKey", "publicKey", "fingerprint", "keyType"}
                   and metadata["keyType"] == "ed25519" and key["privateKey"] == metadata["privateKey"], "local_key_metadata_mismatch")
    return {"kind": "ssh_key", "name": item["overview"]["title"], "notes": details["notesPlain"], "private": key["privateKey"],
            "public": metadata["publicKey"], "fingerprint": metadata["fingerprint"], "custom": custom}


def check_zip_extra(extra):
    """Only the generated Go timestamp extension is admitted, with exact TLV framing."""
    position, seen = 0, set()
    while position < len(extra):
        COMMON.require(position + 4 <= len(extra), "local_archive_shape")
        tag, size = struct.unpack_from("<2H", extra, position)
        position += 4
        COMMON.require(position + size <= len(extra) and tag == 0x5455 and tag not in seen
                       and size == 5 and extra[position] == 1, "local_archive_shape")
        seen.add(tag)
        position += size


def check_zip_local(payload, central_offset, name, version, flags, method, crc, compressed, expanded, extra, local_offset):
    COMMON.require(local_offset + 30 <= central_offset and payload[local_offset:local_offset + 4] == b"PK\x03\x04", "local_archive_shape")
    local_version, local_flags, local_method = struct.unpack_from("<3H", payload, local_offset + 4)
    local_crc, local_compressed, local_expanded = struct.unpack_from("<3I", payload, local_offset + 14)
    name_size, extra_size = struct.unpack_from("<2H", payload, local_offset + 26)
    start = local_offset + 30
    data_start = start + name_size + extra_size
    COMMON.require(data_start <= central_offset and (local_version, local_flags, local_method) == (version, flags, method)
                   and payload[start:start + name_size] == name and local_compressed != 0xffffffff and local_expanded != 0xffffffff,
                   "local_archive_shape")
    local_extra = payload[start + name_size:data_start]
    check_zip_extra(local_extra)
    COMMON.require(local_extra == extra, "local_archive_shape")
    if flags & 8:
        COMMON.require(local_crc in (0, crc) and local_compressed in (0, compressed) and local_expanded in (0, expanded), "local_archive_shape")
    else:
        COMMON.require((local_crc, local_compressed, local_expanded) == (crc, compressed, expanded), "local_archive_shape")
    end = data_start + compressed
    COMMON.require(end <= central_offset, "local_archive_shape")
    encoded = payload[data_start:end]
    if method == zipfile.ZIP_STORED:
        COMMON.require(compressed == expanded, "local_archive_shape")
        decoded = encoded
    else:
        decoder = zlib.decompressobj(-15)
        try:
            decoded = decoder.decompress(encoded, expanded + 1)
        except zlib.error:
            raise COMMON.Rejected("local_archive_shape") from None
        COMMON.require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "local_archive_shape")
    COMMON.require(len(decoded) == expanded and zlib.crc32(decoded) == crc, "local_archive_shape")
    if flags & 8:
        COMMON.require(end + 16 <= central_offset and payload[end:end + 4] == b"PK\x07\x08"
                       and struct.unpack_from("<3I", payload, end + 4) == (crc, compressed, expanded), "local_archive_shape")
        end += 16
    return local_offset, end


def artifact_records(path, target):
    info = path.lstat()
    COMMON.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= REPORT_LIMIT, "artifact_limit")
    # Fixed trusted artifacts are small; bound reads before JSON/ZIP allocation.
    with path.open("rb") as source:
        payload = source.read(REPORT_LIMIT + 1)
    COMMON.require(len(payload) <= REPORT_LIMIT, "artifact_limit")
    if target == "bitwarden-json":
        root = COMMON.strict_json(payload)
        COMMON.require(isinstance(root, dict) and root.get("encrypted") is False, "local_artifact_type")
        return root["items"]
    names = {b"export.attributes", b"export.data"} if target == "onepassword-1pux" else {b"Proton Pass/data.json"}
    # Preflight the fixed central-directory count before ZipFile constructs any
    # ZipInfo objects; reject comments, ZIP64, aliases and unlisted members.
    COMMON.require(len(payload) >= 22 and payload.startswith(b"PK\x03\x04") and payload[-22:-18] == b"PK\x05\x06", "local_archive_shape")
    _, disk, central_disk, disk_count, count, size, offset, comment = struct.unpack("<4s4H2IH", payload[-22:])
    COMMON.require(disk == central_disk == comment == 0 and disk_count == count == len(names)
                   and offset + size == len(payload) - 22, "local_archive_shape")
    cursor, found, spans = offset, set(), []
    for _ in range(count):
        COMMON.require(cursor + 46 <= offset + size and payload[cursor:cursor + 4] == b"PK\x01\x02", "local_archive_shape")
        name_len, extra_len, comment_len = struct.unpack_from("<3H", payload, cursor + 28)
        end = cursor + 46 + name_len + extra_len + comment_len
        COMMON.require(end <= offset + size and comment_len == 0, "local_archive_shape")
        name = payload[cursor + 46:cursor + 46 + name_len]
        COMMON.require(name in names and name not in found, "local_archive_shape")
        created, version, flags, method = struct.unpack_from("<4H", payload, cursor + 4)
        crc, compressed, expanded = struct.unpack_from("<3I", payload, cursor + 16)
        external, local_offset = struct.unpack_from("<2I", payload, cursor + 38)
        mode = external >> 16
        COMMON.require(created >> 8 in (0, 3) and version in (10, 20) and flags & ~0x0808 == 0
                       and method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                       and 0 < compressed <= REPORT_LIMIT and 0 < expanded <= REPORT_LIMIT
                       and local_offset != 0xffffffff and struct.unpack_from("<H", payload, cursor + 34)[0] == 0
                       and stat.S_IFMT(mode) in (0, stat.S_IFREG) and mode & 0o7777 in (0, 0o600)
                       and external & 0xffff in (0, 0x20), "local_archive_shape")
        extra = payload[cursor + 46 + name_len:cursor + 46 + name_len + extra_len]
        check_zip_extra(extra)
        spans.append(check_zip_local(payload, offset, name, version, flags, method, crc, compressed, expanded, extra, local_offset))
        found.add(name)
        cursor = end
    COMMON.require(cursor == offset + size and found == names, "local_archive_shape")
    next_start = 0
    for start, end in sorted(spans):
        COMMON.require(start == next_start, "local_archive_shape")
        next_start = end
    COMMON.require(next_start == offset, "local_archive_shape")
    decoded = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        COMMON.require(len(archive.infolist()) == len(names), "local_archive_shape")
        for member in archive.infolist():
            COMMON.require(member.filename.encode("ascii") in names and not member.is_dir()
                           and member.file_size <= REPORT_LIMIT and not member.flag_bits & 1
                           and member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "local_archive_shape")
            with archive.open(member) as source:
                data = source.read(REPORT_LIMIT + 1)
            COMMON.require(len(data) <= REPORT_LIMIT, "artifact_limit")
            decoded[member.filename] = COMMON.strict_json(data)
    if target == "onepassword-1pux":
        attrs = decoded["export.attributes"]
        COMMON.require(isinstance(attrs, dict) and type(attrs.get("version")) is int and attrs["version"] == 3, "local_artifact_type")
        accounts = decoded["export.data"]["accounts"]
        COMMON.require(isinstance(accounts, list) and len(accounts) == 1, "local_artifact_type")
        vaults = accounts[0]["vaults"]
        COMMON.require(isinstance(vaults, list) and len(vaults) == 1, "local_artifact_type")
        return vaults[0]["items"]
    root = decoded["Proton Pass/data.json"]
    COMMON.require(isinstance(root, dict) and root.get("version") == "1.42.0", "local_artifact_type")
    vaults = root["vaults"]
    COMMON.require(isinstance(vaults, dict) and len(vaults) == 1, "local_artifact_type")
    return next(iter(vaults.values()))["items"]


def check_artifact(path, target, expected):
    items = artifact_records(path, target)
    COMMON.require(isinstance(items, list) and len(items) == len(expected), "local_record_count")
    checks = 1
    for item, record in zip(items, expected):
        actual = observed(item, target)
        for field in ("kind", "name", "notes", "public", "fingerprint", "custom"):
            COMMON.require(actual[field] == record[field], "local_field_mismatch")
            checks += 1
        check_public(actual["public"])
        private = record["private"]
        verify_private(actual["private"], private["representation"], private["comment"])
        checks += 1
        if private["exact"] is not None:
            COMMON.require(actual["private"] == private["exact"], "local_private_text_mismatch")
            checks += 1
    return checks


def prepare(binary, root):
    COMMON.new_private_directory(root)
    for name in ("sources", "artifacts"):
        (root / name).mkdir(mode=0o700)
    records = cases()
    expected = {"schema_version": 1, "origin": "independent_rfc8032_test_vector_1", "sources": {}, "routes": {}}
    index = {"schema_version": 1, "sources": {}, "routes": []}
    extensions = dict(zip(FORMATS, (".json", ".1pux", ".zip")))
    for source in FORMATS:
        relative = Path("sources") / (source + extensions[source])
        COMMON.private_write(root / relative, fixture(source, records))
        index["sources"][source] = str(relative)
        expected["sources"][source] = copy.deepcopy(records)
        for target in FORMATS:
            if source != target:
                expected["routes"][source + "-to-" + target] = expectations(source, target, records)
    # All source bytes and literal route expectations exist before ANY candidate
    # command. The converter never constructs a fixture or expected key value.
    COMMON.private_write(root / "private-expectations.json", COMMON.encoded(expected))
    version = run_json(binary, ["version", "--json"])
    COMMON.require(version.get("program") == "pwmigrate-go" and version.get("goos") == "linux", "linux_candidate_required")
    COMMON.require(isinstance(version.get("version"), str) and re.fullmatch(r"dev|v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version["version"]), "unexpected_version")
    COMMON.require(isinstance(version.get("commit"), str) and re.fullmatch(r"unknown|[0-9a-f]{40}", version["commit"]), "unexpected_commit")
    formats = run_json(binary, ["formats", "--json"])
    entries = formats.get("formats")
    COMMON.require(isinstance(entries, list) and len(entries) == len(COMMON.FORMATS)
                   and all(isinstance(entry, dict) and isinstance(entry.get("id"), str) for entry in entries)
                   and {entry["id"] for entry in entries} == set(COMMON.FORMATS), "unexpected_formats")
    manifest = {"schema_version": 1, "version": version["version"], "commit": version["commit"],
                "fixture": "rfc8032-ed25519-test-vector-1", "source_app_export": "not_run", "provider_import": "not_run", "ssh_authentication": "not_run", "routes": []}
    for source in FORMATS:
        path = root / index["sources"][source]
        inventory = run_json(binary, ["inspect", "--input", path, "--from", source, "--json"])
        kinds = dict.fromkeys(("login", "secure_note", "card", "identity", "ssh_key", "unknown"), 0)
        kinds["ssh_key"] = len(records)
        COMMON.require(type(inventory.get("records")) is int and inventory["records"] == len(records)
                       and inventory.get("kinds") == kinds and all(type(value) is int for value in inventory["kinds"].values()), "source_record_count")
        for target in FORMATS:
            if source == target:
                continue
            route = source + "-to-" + target
            parent = root / "artifacts" / route
            parent.mkdir(mode=0o700)
            plan = run_json(binary, ["plan", "--input", path, "--from", source, "--to", target, "--json"])
            COMMON.check_plan(plan, source, target, len(records))
            artifact, profile, issues = convert(binary, path, source, target, parent, len(records))
            checks = check_artifact(artifact, target, expected["routes"][route])
            index["routes"].append({"route_id": route, "source_format": source, "target_format": target,
                                    "source_file": str(path.relative_to(root)), "artifact_file": str(artifact.relative_to(root))})
            manifest["routes"].append({"route_id": route, "profile": profile, "records": len(records),
                                       "case_ids": [record["case_id"] for record in records], "acknowledged_issues": issues,
                                       "local_field_checks": checks, "local_key_material": "passed", "provider_import": "not_run", "ssh_authentication": "not_run"})
    COMMON.require(len(manifest["routes"]) == 6, "route_count")
    COMMON.private_write(root / "private-index.json", COMMON.encoded(index))
    COMMON.private_write(root / "result-manifest.json", COMMON.encoded(manifest))
    return manifest


def main(argv=None):
    parser = SafeParser(description="Prepare only independent synthetic Ed25519 fixtures for six provider routes.")
    parser.add_argument("--binary", required=True, help="trusted built Linux candidate; no build/download is performed")
    parser.add_argument("--output", required=True, help="new directory under an existing private owned parent")
    args = parser.parse_args(argv)
    try:
        COMMON.require(sys.platform.startswith("linux"), "linux_candidate_required")
        prepare(Path(args.binary).absolute(), Path(args.output).absolute())
    except COMMON.Rejected as error:
        print("qualification_ssh_kit: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("qualification_ssh_kit: cancelled", file=sys.stderr)
        return 130
    except Exception:
        print("qualification_ssh_kit: preparation_failed", file=sys.stderr)
        return 1
    print("qualification_ssh_kit: prepared; routes=6; local_key_material=passed; provider_import=not_run; ssh_authentication=not_run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
