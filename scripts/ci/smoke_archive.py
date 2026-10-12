"""Validate packaged assets and smoke-test one verified native executable.

This provides archive/native-runtime evidence only. It never reads vault exports,
imports into providers, publishes releases, or qualifies private output itself.
"""

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import zipfile
import zlib


PINNED_GO = "go1.26.9"
MAX_ARCHIVE = 32 << 20
MAX_BINARY = 128 << 20
MAX_DOCUMENT = 1 << 20
MAX_METADATA = 64 << 10
MAX_EXPANDED = MAX_BINARY + 4 * MAX_DOCUMENT + 8192
MAX_RUNTIME_OUTPUT = 64 << 10
TARGETS = [(goos, arch) for goos in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]
VERSION_PATTERN = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")


class SmokeError(Exception):
    """A fixed error code, never an asset name or subprocess diagnostic."""

    def __init__(self, code="archive_smoke_failed"):
        allowed = {"archive_smoke_arguments", "archive_smoke_assets", "archive_smoke_archive",
                   "archive_smoke_platform", "archive_smoke_runtime", "archive_smoke_failed"}
        super().__init__(code if code in allowed else "archive_smoke_failed")


def require(condition, code="archive_smoke_assets"):
    if not condition:
        raise SmokeError(code)


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(SmokeError()))


def host_target():
    goos = {"linux": "linux", "darwin": "darwin", "win32": "windows"}.get(sys.platform)
    machine = platform.machine().lower()
    if goos == "windows":
        machine = os.environ.get("PROCESSOR_ARCHITEW6432", machine).lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine)
    return goos, arch


def info(goos, goarch, commit, version):
    return {"program": "pwmigrate-go", "version": version, "commit": commit,
            "go_version": PINNED_GO, "goos": goos, "goarch": goarch}


def asset_name(goos, goarch, version):
    extension = "zip" if goos == "windows" else "tar.gz"
    return f"pwmigrate-go_{version}_{goos}_{goarch}.{extension}"


def regular_bytes(path, limit):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(stat.S_ISREG(opened.st_mode) and opened.st_nlink == 1 and
                (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        data = stream.read(limit + 1)
    require(len(data) <= limit and len(data) == before.st_size)
    return data


def members_expected(goos):
    executable = "pwmigrate-go.exe" if goos == "windows" else "pwmigrate-go"
    return {executable, "LICENSE", "README.md", "THIRD-PARTY-NOTICES.md", "BUILD-INFO.json"}


def member_limit(name):
    if name in ("pwmigrate-go", "pwmigrate-go.exe"):
        return MAX_BINARY
    return MAX_METADATA if name == "BUILD-INFO.json" else MAX_DOCUMENT


def tar_members(data):
    # Decode a bounded complete gzip stream, then accept only ordinary USTAR
    # members. PAX/GNU extension records are unnecessary for these fixed names.
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
        raw = stream.read(MAX_EXPANDED + 1)
    require(len(raw) <= MAX_EXPANDED, "archive_smoke_archive")
    members = {}
    position = 0
    def octal(value):
        value = value.strip(b"\x00 ")
        require(bool(value) and re.fullmatch(b"[0-7]+", value) is not None, "archive_smoke_archive")
        return int(value, 8)
    while position + 512 <= len(raw) and raw[position:position + 512] != bytes(512):
        require(len(members) < 5, "archive_smoke_archive")
        header = raw[position:position + 512]
        require(header[257:263] == b"ustar\x00" and header[263:265] == b"00" and
                header[156:157] in (b"0", b"\x00") and not any(header[157:257]) and
                not any(header[345:500]), "archive_smoke_archive")
        checksum = octal(header[148:156])
        require(checksum == sum(header[:148]) + 8 * 32 + sum(header[156:]), "archive_smoke_archive")
        name = header[:100].split(b"\x00", 1)[0].decode("ascii")
        require(name in members_expected("linux") and name not in members, "archive_smoke_archive")
        mode = octal(header[100:108])
        require(mode == (0o755 if name == "pwmigrate-go" else 0o644), "archive_smoke_archive")
        size = octal(header[124:136])
        require(0 < size <= member_limit(name), "archive_smoke_archive")
        position += 512
        require(size <= len(raw) - position, "archive_smoke_archive")
        members[name] = raw[position:position + size]
        padded = ((size + 511) // 512) * 512
        require(position + padded <= len(raw) and not any(raw[position + size:position + padded]), "archive_smoke_archive")
        position += padded
    require(set(members) == members_expected("linux") and raw[position:] == bytes(1024), "archive_smoke_archive")
    return members


def zip_members(data):
    # Count actual central headers before zipfile allocates per-entry objects.
    require(len(data) >= 22 and data[-22:-18] == b"PK\x05\x06", "archive_smoke_archive")
    disk, central_disk, on_disk, count, size, start, comment = struct.unpack_from("<HHHHIIH", data, len(data) - 18)
    require((disk, central_disk, on_disk, count, comment) == (0, 0, 5, 5, 0) and
            start + size == len(data) - 22, "archive_smoke_archive")
    position, actual = start, 0
    while position < start + size:
        require(actual < 5 and position + 46 <= start + size and data[position:position + 4] == b"PK\x01\x02" and
                struct.unpack_from("<H", data, position + 34)[0] == 0, "archive_smoke_archive")
        names, extras, comments = struct.unpack_from("<HHH", data, position + 28)
        position += 46 + names + extras + comments
        actual += 1
    require(actual == 5 and position == start + size, "archive_smoke_archive")
    members, spans = {}, []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(len(archive.infolist()) == 5, "archive_smoke_archive")
        for entry in archive.infolist():
            name = entry.filename
            require(name in members_expected("windows") and name not in members and
                    entry.flag_bits & ~(8 | 0x800) == 0 and entry.compress_type in (0, 8) and
                    0 < entry.file_size <= member_limit(name), "archive_smoke_archive")
            mode = entry.external_attr >> 16
            require(entry.create_system == 3 and stat.S_ISREG(mode) and
                    stat.S_IMODE(mode) == (0o755 if name == "pwmigrate-go.exe" else 0o644), "archive_smoke_archive")
            offset = entry.header_offset
            require(0 <= offset and offset + 30 <= start and data[offset:offset + 4] == b"PK\x03\x04", "archive_smoke_archive")
            flags, method = struct.unpack_from("<HH", data, offset + 6)
            crc, compressed, expanded = struct.unpack_from("<III", data, offset + 14)
            names, extras = struct.unpack_from("<HH", data, offset + 26)
            body = offset + 30 + names + extras
            end = body + entry.compress_size
            require(body <= end <= start and data[offset + 30:offset + 30 + names] == name.encode("ascii") and
                    flags == entry.flag_bits and method == entry.compress_type, "archive_smoke_archive")
            if flags & 8:
                require(crc in (0, entry.CRC) and compressed in (0, entry.compress_size) and expanded in (0, entry.file_size), "archive_smoke_archive")
                if data[end:end + 4] == b"PK\x07\x08":
                    end += 4
                require(end + 12 <= start and struct.unpack_from("<III", data, end) ==
                        (entry.CRC, entry.compress_size, entry.file_size), "archive_smoke_archive")
                end += 12
            else:
                require((crc, compressed, expanded) == (entry.CRC, entry.compress_size, entry.file_size), "archive_smoke_archive")
            payload = data[body:body + entry.compress_size]
            if method == 8:
                decoder = zlib.decompressobj(-15)
                payload = decoder.decompress(payload, member_limit(name) + 1)
                require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail, "archive_smoke_archive")
            require(len(payload) == entry.file_size and len(payload) <= member_limit(name) and
                    zlib.crc32(payload) & 0xffffffff == entry.CRC, "archive_smoke_archive")
            members[name] = payload
            spans.append((offset, end))
    cursor = 0
    for begin, end in sorted(spans):
        require(begin == cursor, "archive_smoke_archive")
        cursor = end
    require(cursor == start and set(members) == members_expected("windows"), "archive_smoke_archive")
    return members


def check_binary(data, goos, goarch):
    require(0 < len(data) <= MAX_BINARY, "archive_smoke_archive")
    if goos == "linux":
        require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "archive_smoke_archive")
        kind, machine, version = struct.unpack_from("<HHI", data, 16)
        phoff = struct.unpack_from("<Q", data, 32)[0]
        ehsize, phsize, phcount = struct.unpack_from("<HHH", data, 52)
        require(kind == 2 and machine == {"amd64": 62, "arm64": 183}[goarch] and version == 1 and
                ehsize == 64 and phsize == 56 and 0 < phcount <= 128 and
                64 <= phoff and phoff + phsize * phcount <= len(data), "archive_smoke_archive")
    elif goos == "darwin":
        require(len(data) >= 32, "archive_smoke_archive")
        magic, cpu, subtype, kind, commands, size = struct.unpack_from("<IIIIII", data)
        require(magic == 0xfeedfacf and cpu == {"amd64": 0x01000007, "arm64": 0x0100000c}[goarch] and
                kind == 2 and 0 < commands <= 256 and 32 + size <= len(data), "archive_smoke_archive")
        cursor = 32
        for _ in range(commands):
            require(cursor + 8 <= 32 + size, "archive_smoke_archive")
            command_size = struct.unpack_from("<I", data, cursor + 4)[0]
            require(command_size >= 8 and command_size % 4 == 0 and cursor + command_size <= 32 + size, "archive_smoke_archive")
            cursor += command_size
        require(cursor == 32 + size, "archive_smoke_archive")
    else:
        require(len(data) >= 64 and data[:2] == b"MZ", "archive_smoke_archive")
        offset = struct.unpack_from("<I", data, 60)[0]
        require(64 <= offset and offset + 24 <= len(data) and data[offset:offset + 4] == b"PE\x00\x00", "archive_smoke_archive")
        machine, sections = struct.unpack_from("<HH", data, offset + 4)
        optional, flags = struct.unpack_from("<HH", data, offset + 20)
        require(machine == {"amd64": 0x8664, "arm64": 0xaa64}[goarch] and 0 < sections <= 96 and
                flags & 2 != 0 and flags & 0x2000 == 0 and optional >= 112 and
                offset + 24 + optional + 40 * sections <= len(data) and
                struct.unpack_from("<H", data, offset + 24)[0] == 0x20b, "archive_smoke_archive")


def validate_assets(directory, goos, goarch, commit, version):
    root = Path(directory)
    require(not root.is_symlink() and root.is_dir())
    archives = {asset_name(os_name, arch, version) for os_name, arch in TARGETS}
    expected = archives | {"release-manifest.json", "SHA256SUMS"}
    require({entry.name for entry in root.iterdir()} == expected)
    manifest_bytes = regular_bytes(root / "release-manifest.json", MAX_DOCUMENT)
    manifest = strict_json(manifest_bytes)
    require(type(manifest) is dict and set(manifest) == {"schema_version", "version", "commit", "go_version", "artifacts"} and
            type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and
            manifest["version"] == version and manifest["commit"] == commit and manifest["go_version"] == PINNED_GO)
    entries = manifest["artifacts"]
    require(type(entries) is list and len(entries) == 6)
    inventory = {}
    for entry in entries:
        require(type(entry) is dict and set(entry) == {"name", "size", "sha256"})
        name = entry["name"]
        require(type(name) is str and name in archives and name not in inventory and type(entry["size"]) is int and
                0 < entry["size"] <= MAX_ARCHIVE and type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None)
        inventory[name] = entry
    require(set(inventory) == archives)
    sums = {}
    for line in regular_bytes(root / "SHA256SUMS", 8192).decode("ascii").splitlines(keepends=True):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)\n", line)
        require(match is not None and match[2] in archives | {"release-manifest.json"} and match[2] not in sums)
        sums[match[2]] = match[1]
    require(set(sums) == archives | {"release-manifest.json"} and
            hashlib.sha256(manifest_bytes).hexdigest() == sums["release-manifest.json"])
    selected = None
    for os_name, arch in TARGETS:
        name = asset_name(os_name, arch, version)
        raw = regular_bytes(root / name, MAX_ARCHIVE)
        require(len(raw) == inventory[name]["size"] and hashlib.sha256(raw).hexdigest() == inventory[name]["sha256"] == sums[name])
        members = zip_members(raw) if os_name == "windows" else tar_members(raw)
        require(strict_json(members["BUILD-INFO.json"]) == info(os_name, arch, commit, version))
        executable = "pwmigrate-go.exe" if os_name == "windows" else "pwmigrate-go"
        check_binary(members[executable], os_name, arch)
        if (os_name, arch) == (goos, goarch):
            selected = members[executable]
    require(selected is not None)
    return selected


def run_binary(executable, args, work):
    # Drain both pipes concurrently with strict retained-byte limits. Never
    # print subprocess diagnostics or allow unbounded communicate() buffers.
    process = subprocess.Popen([str(executable), *args], cwd=work, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers = [bytearray(), bytearray()]
    failed = threading.Event()
    def stop():
        failed.set()
        try:
            process.kill()
        except OSError:
            pass
    def drain(stream, buffer):
        try:
            while True:
                chunk = os.read(stream.fileno(), 4096)
                if not chunk:
                    return
                if len(buffer) + len(chunk) > MAX_RUNTIME_OUTPUT:
                    stop()
                    return
                buffer.extend(chunk)
        except (OSError, ValueError):
            stop()
    threads = [threading.Thread(target=drain, args=(stream, buffer), daemon=True)
               for stream, buffer in zip((process.stdout, process.stderr), buffers)]
    for thread in threads:
        thread.start()
    try:
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            stop()
            process.wait(timeout=2)
        for thread in threads:
            thread.join(timeout=2)
        require(not failed.is_set() and not any(thread.is_alive() for thread in threads), "archive_smoke_runtime")
        return process.returncode, bytes(buffers[0]), bytes(buffers[1])
    finally:
        if process.poll() is None:
            stop()
        process.stdout.close()
        process.stderr.close()


def check_formats(data, expected_support):
    report = strict_json(data)
    require(type(report) is dict and set(report) == {"formats", "output_platform_supported"} and
            type(report["output_platform_supported"]) is bool and report["output_platform_supported"] is expected_support,
            "archive_smoke_runtime")
    providers = {"bitwarden-json", "onepassword-1pux", "proton-pass-zip"}
    sources = providers | {"chrome-csv", "firefox-csv", "safari-csv"}
    require(type(report["formats"]) is list and len(report["formats"]) == 6, "archive_smoke_runtime")
    seen = set()
    for entry in report["formats"]:
        require(type(entry) is dict and set(entry) == {"id", "inspect", "plan_targets", "convert_targets", "destination_comparison", "provider_import_verified"}, "archive_smoke_runtime")
        source = entry["id"]
        require(type(source) is str and source in sources and source not in seen and entry["inspect"] is True and
                entry["destination_comparison"] is True and entry["provider_import_verified"] is False, "archive_smoke_runtime")
        seen.add(source)
        for key in ("plan_targets", "convert_targets"):
            targets = entry[key]
            require(type(targets) is list and all(type(value) is str for value in targets) and
                    len(targets) == len(set(targets)) and set(targets) == providers - {source}, "archive_smoke_runtime")
    require(seen == sources, "archive_smoke_runtime")


def smoke(directory, goos, goarch, commit, version, expect_output_supported, executor=None):
    require((goos, goarch) in TARGETS and type(expect_output_supported) is bool and
            type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit) is not None and
            type(version) is str and len(version) <= 128 and VERSION_PATTERN.fullmatch(version) is not None,
            "archive_smoke_arguments")
    prerelease = VERSION_PATTERN.fullmatch(version)[4]
    if prerelease:
        require(not any(part.isdigit() and len(part) > 1 and part[0] == "0" for part in prerelease.split(".")), "archive_smoke_arguments")
    require(host_target() == (goos, goarch), "archive_smoke_platform")
    binary = validate_assets(directory, goos, goarch, commit, version)
    executor = executor or run_binary
    with tempfile.TemporaryDirectory(prefix="pwmigrate-native-smoke-") as owned:
        os.chmod(owned, 0o700)
        executable = Path(owned) / ("pwmigrate-go.exe" if goos == "windows" else "pwmigrate-go")
        with os.fdopen(os.open(executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o700), "wb") as stream:
            stream.write(binary)
        os.chmod(executable, 0o700)
        for args in (["version", "--json"], ["help"], ["formats", "--json"]):
            status, stdout, stderr = executor(executable, args, owned)
            require(status == 0 and not stderr and len(stdout) <= MAX_RUNTIME_OUTPUT, "archive_smoke_runtime")
            if args[0] == "version":
                require(strict_json(stdout) == info(goos, goarch, commit, version), "archive_smoke_runtime")
            elif args[0] == "formats":
                check_formats(stdout, expect_output_supported)
            else:
                text = stdout.decode("utf-8")
                require(all(word in text for word in ("pwmigrate-go:", "inspect", "plan", "convert", "compare", "recovery-key", "recover", "formats", "version", "plaintext", "destination provider acceptance is unverified")), "archive_smoke_runtime")


class FixedParser(argparse.ArgumentParser):
    def error(self, message):
        raise SmokeError("archive_smoke_arguments")


def main(argv=None):
    parser = FixedParser(description="Verify six release archives and run one packaged native CLI.")
    for name in ("directory", "goos", "goarch", "commit", "version"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--expect-output-supported", choices=("true", "false"), required=True)
    try:
        arguments = vars(parser.parse_args(argv))
        arguments["expect_output_supported"] = arguments["expect_output_supported"] == "true"
        smoke(**arguments)
    except SmokeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception:
        print("archive_smoke_failed", file=sys.stderr)
        return 1
    print("archive_smoke_passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
