"""Generate synthetic independent vectors; requires existing cryptography 50.

This is test tooling, never a runtime dependency. Fixed IVs and passwords are
synthetic test data only. Primitive schedule follows the pinned public provider
sources cited in ../README.md. This is not a native Bitwarden export.
"""

import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def keys(password, salt, kdf):
    if kdf["kdfType"] == 0:
        material = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), kdf["kdfIterations"], 32)
    else:
        material = Argon2id(salt=hashlib.sha256(salt.encode()).digest(), length=32,
                           iterations=kdf["kdfIterations"], lanes=kdf["kdfParallelism"],
                           memory_cost=kdf["kdfMemory"] * 1024).derive(password.encode())
    return [HKDFExpand(algorithm=hashes.SHA256(), length=32, info=label).derive(material)
            for label in (b"enc", b"mac")]


def record(plaintext, iv, enc, mac, padded=False):
    if not padded:
        p = padding.PKCS7(128).padder()
        plaintext = p.update(plaintext) + p.finalize()
    e = Cipher(algorithms.AES(enc), modes.CBC(iv)).encryptor()
    ciphertext = e.update(plaintext) + e.finalize()
    tag = hmac.digest(mac, iv + ciphertext, "sha256")
    return "2." + "|".join(base64.b64encode(x).decode() for x in (iv, ciphertext, tag))


vectors = []
for kdf in [{"kdfType": 0, "kdfIterations": 5000},
            {"kdfType": 1, "kdfIterations": 2, "kdfMemory": 16, "kdfParallelism": 2}]:
    password = "  synthetic-🔐-password\r\n "
    salt = " UPPER-☃-synthetic-salt "
    enc, mac = keys(password, salt, kdf)
    plaintext = '{"encrypted":false,"folders":[],"items":[],"synthetic":" \\r\\n 🔐 "}'
    envelope = dict(encrypted=True, passwordProtected=True, salt=salt, **kdf)
    envelope["encKeyValidation_DO_NOT_EDIT"] = record(b"synthetic validation", bytes(range(16)), enc, mac)
    envelope["data"] = record(plaintext.encode(), bytes(range(16, 32)), enc, mac)
    bad_padding = [record(b"x" * 15 + b"\x00", bytes(range(16, 32)), enc, mac, True),
                   record(b"x" * 14 + b"\x01\x02", bytes(range(16, 32)), enc, mac, True),
                   record(b"x" * 15 + b"\x11", bytes(range(16, 32)), enc, mac, True)]
    vectors.append(dict(password=password, plaintext=plaintext, envelope=envelope,
                        badPadding=bad_padding, empty=record(b"", bytes(range(16, 32)), enc, mac),
                        invalidUTF8=record(b"\xff", bytes(range(16, 32)), enc, mac)))

Path(__file__).with_name("bitwarden-vectors.json").write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n")
