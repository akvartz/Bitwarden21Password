#!/usr/bin/env python3
"""Prepare only synthetic, private artifacts for user-run provider qualification.

No production adapter is imported to create a source or an expected value.
The candidate is invoked solely to inspect, plan, and convert authored fixtures.
"""

import argparse
import copy
import csv
import io
import json
import os
from pathlib import Path
import queue
import re
import stat
import subprocess
import sys
import tempfile
import threading
import zipfile


FORMATS = ("chrome-csv", "firefox-csv", "safari-csv", "bitwarden-json",
           "onepassword-1pux", "proton-pass-zip")
TARGETS = FORMATS[3:]
KINDS = {"login": 1, "secure_note": 2, "card": 3, "identity": 4}
ONEPASSWORD_KINDS = {"login": "001", "secure_note": "003", "card": "002", "identity": "004"}
PROTON_KINDS = {"login": "login", "secure_note": "note", "card": "creditCard", "identity": "identity"}
BYTE_LIMIT = 4 * 1024 * 1024
TIMEOUT = 30
KNOWN_ISSUES = {
    "experimental-import": "experimental_import",
    "fields-unsupported": "fields_unsupported",
    "fields-omitted": "fields_omitted",
    "fields-transformed": "fields_transformed",
    "fields-relocated": "fields_relocated",
    "metadata-unsupported": "metadata_unsupported",
    "intermediary-mapping": "intermediary_mapping",
    "browser-generated-title": "browser_generated_title",
    "browser-totp-profile": "browser_totp_profile",
    "provider-blank-notes": "import_notes_null",
}


class Rejected(Exception):
    """Only fixed, non-sensitive codes leave the preparation process."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "qualification_kit: invalid_arguments\n")


def require(condition, code):
    if not condition:
        raise Rejected(code)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise Rejected("invalid_json_constant")

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def private_write(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def new_private_directory(path):
    parent = path.parent
    info = parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and not info.st_mode & 0o022, "private_parent_required")
    # Reject symlink ancestors rather than resolving a supplied output path.
    for ancestor in (parent, *parent.parents):
        require(not ancestor.is_symlink(), "private_parent_required")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        raise Rejected("output_exists") from None
    require(stat.S_IMODE(path.lstat().st_mode) == 0o700, "private_directory_mode")


def cases():
    """Independent semantic literals; these are invented, unusable credentials."""
    custom = [{"name": "kit text", "value": " text, \"quoted\" ", "hidden": False},
              {"name": "kit hidden", "value": " hidden\r\nvalue ", "hidden": True}]
    login = {"case_id": "login-basic", "kind": "login", "name": "kit login",
             "notes": "kit login note", "username": "kit-user", "password": "kit-password",
             "urls": ["https://qualification.invalid/login"], "custom": custom}
    whitespace = {"case_id": "credential-whitespace", "kind": "login", "name": "kit whitespace",
                  "notes": " first\r\nsecond\nthird\r ", "username": " \tkit e\u0301\r\n ",
                  "password": " \tkit \u00e9\n\r ",
                  "urls": ["https://qualification.invalid/whitespace"], "custom": custom}
    duplicate = copy.deepcopy(login)
    duplicate["case_id"] = "duplicate-identical"
    different = copy.deepcopy(login)
    different.update(case_id="duplicate-password", password="kit-password-variant")
    return [login,
            {"case_id": "note-basic", "kind": "secure_note", "name": "kit note",
             "notes": " synthetic note\r\nsecond line ", "custom": custom},
            {"case_id": "card-basic", "kind": "card", "name": "kit card",
             "notes": "kit card note", "cardholder": " kit holder ",
             "number": "0000000000000000", "code": "000", "month": "01", "year": "2030"},
            {"case_id": "identity-basic", "kind": "identity", "name": "kit identity",
             "notes": "kit identity note", "first_name": " First ", "middle_name": " Middle ",
             "last_name": " Last ", "email": "kit@example.invalid", "phone": "0000000000",
             "company": " kit company "}, whitespace, duplicate, different]


def bitwarden_fixture(records):
    items = []
    for record in records:
        item = {"type": KINDS[record["kind"]], "name": record["name"], "notes": record["notes"]}
        if record["kind"] == "login":
            item["login"] = {"username": record["username"], "password": record["password"],
                             "uris": [{"uri": url} for url in record["urls"]]}
        elif record["kind"] == "secure_note":
            item["secureNote"] = {"type": 0}
        elif record["kind"] == "card":
            item["card"] = {"cardholderName": record["cardholder"], "number": record["number"],
                            "code": record["code"], "expMonth": record["month"], "expYear": record["year"]}
        else:
            item["identity"] = dict(zip(("firstName", "middleName", "lastName", "email", "phone", "company"),
                                        (record[key] for key in ("first_name", "middle_name", "last_name", "email", "phone", "company"))))
        if "custom" in record:
            item["fields"] = [{"name": field["name"], "value": field["value"],
                               "type": 1 if field["hidden"] else 0} for field in record["custom"]]
        items.append(item)
    return encoded({"encrypted": False, "folders": [], "items": items})


def zip_fixture(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries.items():
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(info, payload)
    return buffer.getvalue()


def section_field(identifier, value):
    return {"id": identifier, "title": identifier, "value": value}


def onepassword_fixture(records):
    items = []
    for ordinal, record in enumerate(records, 1):
        fields = []
        details = {"notesPlain": record["notes"]}
        overview = {"title": record["name"], "subtitle": "", "url": ""}
        if record["kind"] == "login":
            details["loginFields"] = [
                {"id": key, "name": key, "designation": key, "fieldType": typ, "value": record[key]}
                for key, typ in (("username", "T"), ("password", "P"))]
            overview["urls"] = [{"label": "", "url": url} for url in record["urls"]]
        elif record["kind"] == "card":
            fields = [section_field("cardholder", {"string": record["cardholder"]}),
                      section_field("ccnum", {"creditCardNumber": record["number"]}),
                      section_field("cvv", {"concealed": record["code"]}),
                      section_field("expiry", {"monthYear": 203001})]
        elif record["kind"] == "identity":
            fields = [section_field(identifier, {tag: record[key]}) for key, identifier, tag in
                      (("first_name", "firstname", "string"), ("middle_name", "initial", "string"),
                       ("last_name", "lastname", "string"), ("phone", "defphone", "phone"),
                       ("company", "company", "string"))]
            fields.append(section_field("email", {"email": {"email_address": record["email"], "provider": ""}}))
        for index, field in enumerate(record.get("custom", []), 1):
            fields.append({"id": "kit.custom." + str(index), "title": field["name"],
                           "value": {"concealed" if field["hidden"] else "string": field["value"]}})
        if fields:
            details["sections"] = [{"title": "kit fields", "name": "kit", "fields": fields}]
        items.append({"uuid": "kit-item-" + str(ordinal), "categoryUuid": ONEPASSWORD_KINDS[record["kind"]],
                      "overview": overview, "details": details, "favIndex": 0, "state": "active",
                      "createdAt": 0, "updatedAt": 0})
    data = {"accounts": [{"attrs": {"accountName": "kit", "name": "kit", "avatar": "", "email": "kit@example.invalid",
                                    "uuid": "kit-account", "domain": "qualification.invalid"},
                          "vaults": [{"attrs": {"uuid": "kit-vault", "name": "kit", "desc": "", "avatar": "", "type": "P"}, "items": items}]}]}
    return zip_fixture({"export.attributes": encoded({"version": 3, "description": "1Password Unencrypted Export", "createdAt": 0}),
                        "export.data": encoded(data)})


def proton_fixture(records):
    items = []
    for ordinal, record in enumerate(records, 1):
        content = {}
        if record["kind"] == "login":
            content = {"itemUsername": record["username"], "password": record["password"], "urls": record["urls"]}
        elif record["kind"] == "card":
            content = {"cardholderName": record["cardholder"], "number": record["number"],
                       "verificationNumber": record["code"], "expirationDate": "012030"}
        elif record["kind"] == "identity":
            content = dict(zip(("firstName", "middleName", "lastName", "email", "phoneNumber", "company"),
                               (record[key] for key in ("first_name", "middle_name", "last_name", "email", "phone", "company"))))
        items.append({"itemId": "kit-item-" + str(ordinal), "contentFormatVersion": 1,
                      "data": {"type": PROTON_KINDS[record["kind"]],
                               "metadata": {"name": record["name"], "note": record["notes"], "itemUuid": "kit-uuid-" + str(ordinal)},
                               "content": content, "extraFields": [
                                   {"fieldName": field["name"], "type": "hidden" if field["hidden"] else "text", "data": {"content": field["value"]}}
                                   for field in record.get("custom", [])]}})
    return zip_fixture({"Proton Pass/data.json": encoded({"version": "1.42.0", "vaults": {"kit-vault": {"name": "kit", "items": items}}})})


def browser_fixture(source, records):
    if source == "chrome-csv":
        headers = ["name", "url", "username", "password", "note", "kit custom"]
        rows = [[r["name"], r["urls"][0], r["username"], r["password"], r["notes"], " custom\r\nvalue "] for r in records]
    elif source == "firefox-csv":
        headers = ["url", "username", "password", "httpRealm", "formActionOrigin", "guid", "timeCreated", "timeLastUsed", "timePasswordChanged", "kit custom"]
        rows = [[r["urls"][0], r["username"], r["password"], "", "", "kit-guid-" + str(i), "0", "0", "0", " custom\r\nvalue "] for i, r in enumerate(records, 1)]
    else:
        headers = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth", "kit custom"]
        rows = [[r["name"], r["urls"][0], r["username"], r["password"], r["notes"], "otpauth://totp/kit?secret=JBSWY3DPEHPK3PXP&issuer=kit", " custom\r\nvalue "] for r in records]
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(headers)
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def expected_records(source, records):
    expected = copy.deepcopy(records)
    for ordinal, record in enumerate(expected, 1):
        record["record"] = ordinal
        if source in FORMATS[:3]:
            record["custom"] = [{"name": "kit custom", "value": " custom\r\nvalue ", "hidden": True}]
            if source == "firefox-csv":
                record["name"] = record["urls"][0]
                record.pop("notes")
            if source == "safari-csv":
                record["totp"] = "otpauth://totp/kit?secret=JBSWY3DPEHPK3PXP&issuer=kit"
    return expected


def run_json(binary, args):
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.run([str(binary), *map(str, args)], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=error_output, timeout=TIMEOUT, check=False)
    require(process.returncode == 0, "cli_command_failed")
    require(len(process.stdout) <= BYTE_LIMIT, "cli_report_limit")
    report = strict_json(process.stdout)
    require(isinstance(report, dict), "unexpected_report")
    return report


def expected_profile(source, target):
    if source == "chrome-csv" and target == "bitwarden-json":
        return "chrome-to-bitwarden-json-v1"
    if source == "bitwarden-json":
        return "bitwarden-to-" + target + "-v1"
    return source + "-to-" + target + "-v1"


def check_plan(plan, source, target, count, state="planned", emitted=False):
    require(isinstance(plan, dict), "unexpected_plan")
    require(plan.get("source") == source and plan.get("target") == target
            and plan.get("state") == state and plan.get("output_emitted") is emitted
            and plan.get("destination_import_verified") is False,
            "unexpected_plan")
    for field, value in (("total_records", count), ("selected_records", count), ("excluded_records", 0)):
        require(type(plan.get(field)) is int and plan[field] == value, "unexpected_plan")
    for name, metadata in (("fields", False), ("metadata", True)):
        fields = plan.get(name, [])
        require(isinstance(fields, list), "unexpected_disposition")
        seen = set()
        for field in fields:
            require(isinstance(field, dict), "unexpected_disposition")
            ordinal, position = field.get("record"), field.get("field")
            require(type(ordinal) is int and ((ordinal == 0) if metadata else (1 <= ordinal <= count))
                    and type(position) is int and 1 <= position <= 1_000_000,
                    "unexpected_disposition")
            require((ordinal, position) not in seen, "unexpected_disposition")
            seen.add((ordinal, position))
            require(field.get("disposition") in ("native", "relocated", "transformed", "unsupported", "omitted")
                    and isinstance(field.get("target_field"), str) and type(field.get("concealed")) is bool,
                    "unexpected_disposition")


def convert(binary, source_path, source, target, parent, count):
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen([str(binary), "convert", "--input", str(source_path), "--from", source,
                                    "--to", target, "--output-dir", str(parent), "--json"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=error_output)
        try:
            first = queue.Queue(maxsize=1)
            def read_review():
                first.put(process.stdout.readline(BYTE_LIMIT + 1))
            threading.Thread(target=read_review, daemon=True).start()
            line = first.get(timeout=TIMEOUT)
            require(0 < len(line) <= BYTE_LIMIT, "cli_review_limit")
            event = strict_json(line)
            require(isinstance(event, dict) and event.get("event") == "review", "unexpected_review")
            review = event.get("review")
            require(isinstance(review, dict), "unexpected_review")
            check_plan(review["plan"], source, target, count)
            profile = expected_profile(source, target)
            require(review.get("profile") == profile, "unexpected_profile")
            review_id = review.get("review_id", "")
            require(isinstance(review_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{16,128}", review_id), "unexpected_review_id")
            issues = review.get("issues", [])
            require(isinstance(issues, list) and 1 <= len(issues) <= 32, "unexpected_issues")
            identifiers = []
            for issue in issues:
                require(isinstance(issue, dict), "unexpected_issues")
                identifier, code = issue.get("id"), issue.get("code")
                require(isinstance(identifier, str) and isinstance(code, str), "unexpected_issues")
                allowed = KNOWN_ISSUES.get(identifier) == code
                if source == "chrome-csv" and target == "bitwarden-json":
                    allowed = allowed or (identifier == "relocate-column-6" and code == "concealed_custom_field")
                require(allowed and identifier not in identifiers, "unreviewed_issue")
                identifiers.append(identifier)
            require("experimental-import" in identifiers, "missing_experimental_issue")
            approval = "approve " + review_id + " " + " ".join(identifiers) + "\n"
            remainder, _ = process.communicate(approval.encode("ascii"), timeout=TIMEOUT)
            require(process.returncode == 0 and len(remainder) <= BYTE_LIMIT, "conversion_failed")
            completed = strict_json(remainder)
            require(isinstance(completed, dict) and completed.get("event") == "completed", "completion_required")
            receipt = completed.get("receipt")
            require(isinstance(receipt, dict), "unexpected_completion")
            outcome = receipt.get("plan", {})
            check_plan(outcome, source, target, count, state="output_validated", emitted=True)
            require(receipt.get("profile") == profile
                    and outcome.get("fields", []) == review["plan"].get("fields", [])
                    and outcome.get("metadata", []) == review["plan"].get("metadata", []), "unexpected_completion")
            directory = receipt.get("job_directory", "")
            filename = {"bitwarden-json": "bitwarden.json", "onepassword-1pux": "onepassword.1pux", "proton-pass-zip": "proton-pass.zip"}[target]
            require(isinstance(directory, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", directory)
                    and receipt.get("file_name") == filename, "unsafe_receipt")
            artifact = parent / directory / filename
            require(stat.S_ISREG(artifact.lstat().st_mode) and stat.S_IMODE(artifact.lstat().st_mode) == 0o600
                    and stat.S_IMODE(artifact.parent.lstat().st_mode) == 0o700, "artifact_permissions")
            return artifact, profile, len(issues)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=TIMEOUT)
            process.stdin.close()
            process.stdout.close()


def artifact_records(path, target):
    require(path.stat().st_size <= BYTE_LIMIT, "artifact_limit")
    if target == "bitwarden-json":
        return strict_json(path.read_bytes())["items"]
    with zipfile.ZipFile(path) as archive:
        member = "export.data" if target == "onepassword-1pux" else "Proton Pass/data.json"
        require(archive.getinfo(member).file_size <= BYTE_LIMIT, "artifact_limit")
        data = strict_json(archive.read(member))
    if target == "onepassword-1pux":
        return [item for account in data["accounts"] for vault in account["vaults"] for item in vault["items"]]
    return [item for key in sorted(data["vaults"]) for item in data["vaults"][key]["items"]]


def observed(item, target):
    """Decode a documented subset independently; absent fields remain absent."""
    result = {}
    if target == "bitwarden-json":
        require(type(item.get("type")) is int and item["type"] in KINDS.values(), "local_artifact_type")
        result.update(kind={v: k for k, v in KINDS.items()}[item["type"]], name=item["name"])
        if "notes" in item:
            result["notes"] = item["notes"]
        if result["kind"] == "login":
            for key in ("username", "password", "totp"):
                if key in item["login"]:
                    result[key] = item["login"][key]
            result["urls"] = [entry["uri"] for entry in item["login"].get("uris", [])]
        elif result["kind"] == "card":
            for old, new in (("cardholderName", "cardholder"), ("number", "number"), ("code", "code"), ("expMonth", "month"), ("expYear", "year")):
                if old in item["card"]:
                    result[new] = item["card"][old]
        elif result["kind"] == "identity":
            for old, new in (("firstName", "first_name"), ("middleName", "middle_name"), ("lastName", "last_name"), ("email", "email"), ("phone", "phone"), ("company", "company")):
                if old in item["identity"]:
                    result[new] = item["identity"][old]
        result["custom"] = []
        for field in item.get("fields", []):
            require(isinstance(field, dict) and type(field.get("type")) is int and field["type"] in (0, 1), "local_artifact_type")
            result["custom"].append({"name": field["name"], "value": field["value"], "hidden": field["type"] == 1})
    elif target == "proton-pass-zip":
        data = item["data"]
        require(isinstance(data.get("type"), str) and data["type"] in PROTON_KINDS.values(), "local_artifact_type")
        result.update(kind={v: k for k, v in PROTON_KINDS.items()}[data["type"]], name=data["metadata"]["name"])
        if "note" in data["metadata"]:
            result["notes"] = data["metadata"]["note"]
        content = data["content"]
        mapping = {"login": (("itemUsername", "username"), ("password", "password"), ("totpUri", "totp")),
                   "card": (("cardholderName", "cardholder"), ("number", "number"), ("verificationNumber", "code")),
                   "identity": (("firstName", "first_name"), ("middleName", "middle_name"), ("lastName", "last_name"), ("email", "email"), ("phoneNumber", "phone"), ("company", "company"))}
        for old, new in mapping.get(result["kind"], ()):
            if old in content:
                result[new] = content[old]
        if result["kind"] == "login":
            result["urls"] = content.get("urls", [])
        if result["kind"] == "card" and "expirationDate" in content:
            result["month"], result["year"] = content["expirationDate"][:2], content["expirationDate"][2:]
        result["custom"] = []
        for field in data.get("extraFields", []):
            require(isinstance(field, dict) and type(field.get("type")) is str and field["type"] in ("text", "hidden"), "local_artifact_type")
            result["custom"].append({"name": field["fieldName"], "value": field["data"]["content"], "hidden": field["type"] == "hidden"})
    else:
        details = item["details"]
        require(type(item.get("categoryUuid")) is str and item["categoryUuid"] in ONEPASSWORD_KINDS.values(), "local_artifact_type")
        result.update(kind={v: k for k, v in ONEPASSWORD_KINDS.items()}[item["categoryUuid"]], name=item["overview"]["title"])
        if "notesPlain" in details:
            result["notes"] = details["notesPlain"]
        for field in details.get("loginFields", []):
            if field.get("designation") in ("username", "password"):
                result[field["designation"]] = field["value"]
        if result["kind"] == "login":
            result["urls"] = [entry["url"] for entry in item["overview"].get("urls", [])]
        fields = [f for section in details.get("sections", []) for f in section.get("fields", [])]
        result["custom"] = []
        for field in fields:
            value, identifier = field["value"], field["id"]
            guarded = field.get("guarded", False)
            require(type(guarded) is bool and isinstance(value, dict) and len(value) == 1, "local_artifact_type")
            if "totp" in value:
                result["totp"] = value["totp"]
            if result["kind"] == "card":
                keys = {"cardholder": ("cardholder", "string"), "ccnum": ("number", "creditCardNumber"), "cvv": ("code", "concealed")}
                if identifier in keys:
                    key, tag = keys[identifier]
                    result[key] = value[tag]
                if identifier == "expiry" and "monthYear" in value:
                    require(type(value["monthYear"]) is int, "local_artifact_type")
                    result["month"], result["year"] = f'{value["monthYear"] % 100:02d}', str(value["monthYear"] // 100)
            if result["kind"] == "identity":
                keys = {"firstname": ("first_name", "string"), "initial": ("middle_name", "string"), "lastname": ("last_name", "string"), "defphone": ("phone", "phone"), "company": ("company", "string")}
                if identifier in keys:
                    key, tag = keys[identifier]
                    result[key] = value[tag]
                if identifier == "email" and "email" in value:
                    result["email"] = value["email"]["email_address"]
            for tag in ("string", "concealed"):
                if tag in value:
                    require(type(value[tag]) is str, "local_artifact_type")
                    result["custom"].append({"name": field["title"], "value": value[tag], "hidden": tag == "concealed" or guarded})
    return result


def route_expectations(source, target, records):
    expected = copy.deepcopy(records)
    # 1PUX's numeric YYYYMM has no lexical leading-zero month. The declared
    # Bitwarden target stores its independently decoded decimal month string.
    if source == "onepassword-1pux" and target == "bitwarden-json":
        for record in expected:
            if record["kind"] == "card":
                record["month"] = "1"
    return expected


def check_artifact(path, target, expectations):
    items = artifact_records(path, target)
    require(len(items) == len(expectations), "local_record_count")
    checks = 1
    for item, expected in zip(items, expectations):
        actual = observed(item, target)
        for field, value in expected.items():
            if field in ("case_id", "record", "custom"):
                continue
            require(actual.get(field) == value, "local_field_mismatch")
            checks += 1
        for field in expected.get("custom", []):
            require(field in actual.get("custom", []), "local_custom_mismatch")
            checks += 1
    return checks


def prepare(binary, root):
    new_private_directory(root)
    for name in ("sources", "artifacts"):
        (root / name).mkdir(mode=0o700)
    version = run_json(binary, ["version", "--json"])
    require(version.get("program") == "pwmigrate-go" and version.get("goos") == "linux", "linux_candidate_required")
    require(isinstance(version.get("version"), str) and re.fullmatch(r"dev|v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version["version"]), "unexpected_version")
    require(isinstance(version.get("commit"), str) and re.fullmatch(r"unknown|[0-9a-f]{40}", version["commit"]), "unexpected_commit")
    formats = run_json(binary, ["formats", "--json"])
    entries = formats.get("formats")
    require(isinstance(entries, list) and all(isinstance(entry, dict)
            and isinstance(entry.get("id"), str) for entry in entries), "unexpected_formats")
    require({entry["id"] for entry in entries} == set(FORMATS), "unexpected_formats")
    private_index = {"schema_version": 1, "sources": {}, "routes": []}
    expected = {"schema_version": 1, "origin": "independently_authored_synthetic_literals", "sources": {}, "routes": {}}
    manifest = {"schema_version": 1, "version": version["version"], "commit": version["commit"],
                "source_app_export": "not_run", "provider_import": "not_run", "routes": []}
    records = cases()
    browsers = [copy.deepcopy(records[index]) for index in (0, 4, 5, 6)]
    extensions = {**dict.fromkeys(FORMATS[:3], ".csv"), "bitwarden-json": ".json", "onepassword-1pux": ".1pux", "proton-pass-zip": ".zip"}
    for source in FORMATS:
        selected = browsers if source in FORMATS[:3] else records
        payload = (browser_fixture(source, selected) if source in FORMATS[:3] else
                   {"bitwarden-json": bitwarden_fixture, "onepassword-1pux": onepassword_fixture, "proton-pass-zip": proton_fixture}[source](selected))
        relative = Path("sources") / (source + extensions[source])
        private_write(root / relative, payload)
        expectations = expected_records(source, selected)
        expected["sources"][source] = expectations
        for target in TARGETS:
            if source != target:
                expected["routes"][source + "-to-" + target] = route_expectations(source, target, expectations)
        private_index["sources"][source] = str(relative)
    # Expectations are saved before invoking any inspection or conversion.
    private_write(root / "private-expectations.json", encoded(expected))
    for source in FORMATS:
        source_path = root / private_index["sources"][source]
        expectations = expected["sources"][source]
        inventory = run_json(binary, ["inspect", "--input", source_path, "--from", source, "--json"])
        require(type(inventory.get("records")) is int and inventory["records"] == len(expectations), "source_record_count")
        for target in TARGETS:
            if source == target:
                continue
            route = source + "-to-" + target
            parent = root / "artifacts" / route
            parent.mkdir(mode=0o700)
            plan = run_json(binary, ["plan", "--input", source_path, "--from", source, "--to", target, "--json"])
            check_plan(plan, source, target, len(expectations))
            artifact, profile, issues = convert(binary, source_path, source, target, parent, len(expectations))
            checks = check_artifact(artifact, target, expected["routes"][route])
            private_index["routes"].append({"route_id": route, "source_format": source, "target_format": target,
                                             "source_file": str(source_path.relative_to(root)),
                                             "artifact_file": str(artifact.relative_to(root))})
            manifest["routes"].append({"route_id": route, "profile": profile, "records": len(expectations),
                                       "case_ids": [record["case_id"] for record in expectations],
                                       "acknowledged_issues": issues, "local_field_checks": checks,
                                       "local_mapping": "passed", "provider_import": "not_run"})
    require(len(manifest["routes"]) == 15, "route_count")
    private_write(root / "private-index.json", encoded(private_index))
    private_write(root / "result-manifest.json", encoded(manifest))
    return manifest


def main(argv=None):
    parser = SafeParser(description="Create and locally check fifteen routes from authored synthetic fixtures only.")
    parser.add_argument("--binary", required=True, help="trusted built Linux candidate; no build/download is performed")
    parser.add_argument("--output", required=True, help="new directory under an existing private owned parent")
    args = parser.parse_args(argv)
    try:
        require(sys.platform.startswith("linux"), "linux_candidate_required")
        prepare(Path(args.binary).absolute(), Path(args.output).absolute())
    except Rejected as error:
        print("qualification_kit: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("qualification_kit: cancelled", file=sys.stderr)
        return 130
    except Exception:
        # The candidate and archive decoder are external-data boundaries.
        # Library exceptions must never print private paths or payloads; the
        # explicit guards above still reject malformed reviews before approval.
        print("qualification_kit: preparation_failed", file=sys.stderr)
        return 1
    print("qualification_kit: prepared; routes=15; local_mapping=passed; provider_import=not_run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
