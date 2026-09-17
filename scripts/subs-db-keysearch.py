#!/usr/bin/env python3
"""Dev tool: find the AES-128-GCM key Happ uses for subs.db.

Tries candidate keys from: printable runs in the Happ binaries, the
Happ.conf "bld" blob, machine-id derivations. Verifies against the real
subscription record (nonce/ciphertext/tag from subs.db).

Run: .venv/bin/python scripts/subs-db-keysearch.py
"""

import base64
import hashlib
import re
import sqlite3
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DB = Path.home() / ".config/Happ/subs.db"
HAPP_BIN = Path("/opt/happ/bin/Happ")
HAPPD_BIN = Path("/opt/happ/bin/happd")
CONF = Path.home() / ".config/Happ.conf"
MACHINE_ID = Path("/etc/machine-id")

PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{16,80}")


def load_record():
    con = sqlite3.connect(DB)
    version, data, tag, updated = con.execute("SELECT * FROM subscriptions").fetchone()
    raw = base64.b64decode(data)
    tag = base64.b64decode(tag)
    print(f"record: version={version} updated={updated} ct={len(raw)}B tag={tag.hex()}")
    return raw, tag


def try_key(name: str, key: bytes, raw: bytes, tag: bytes) -> bool:
    if len(key) != 16:
        return False
    layouts = [
        ("nonce|ct", raw[:12], raw[12:]),
        ("ct|nonce", raw[-12:], raw[:-12]),
        ("nonce16|ct", raw[:16], raw[16:]),
    ]
    for layout, nonce, ct in layouts:
        try:
            pt = AESGCM(key).decrypt(nonce, ct + b"", tag)
        except (InvalidTag, ValueError):
            continue
        print(f"\n*** KEY FOUND: {name!r} key={key!r} layout={layout}")
        print(f"    plaintext head: {pt[:200]!r}")
        return True
    return False


def candidates():
    # printable runs from binaries (all 16-byte windows within each run)
    for binary in (HAPP_BIN, HAPPD_BIN):
        data = binary.read_bytes()
        seen = 0
        for run in PRINTABLE_RUN.finditer(data):
            run = run.group()
            for i in range(0, len(run) - 15):
                yield f"{binary.name}:{run[:24]!r}@{i}", run[i : i + 16]
            seen += 1
            if seen > 4000:
                break

    # machine-id derivations
    for mid_path in (MACHINE_ID, Path("/var/lib/dbus/machine-id")):
        try:
            mid = mid_path.read_text().strip()
        except OSError:
            continue
        yield f"md5({mid_path})", hashlib.md5(mid.encode()).digest()
        yield f"sha256({mid_path})[:16]", hashlib.sha256(mid.encode()).digest()[:16]
        yield f"md5(hex {mid_path})", hashlib.md5(bytes.fromhex(mid)).digest()

    # Happ.conf bld blob ("<b64>|<b64>" — try raw parts and hashes)
    try:
        for line in CONF.read_text().splitlines():
            if line.startswith("bld="):
                value = line.split("=", 1)[1].strip().strip('"')
                for i, part in enumerate(value.split("|")):
                    try:
                        raw_part = base64.b64decode(part)
                    except Exception:
                        continue
                    yield f"bld part{i} raw[:16]", raw_part[:16]
                    yield f"md5(bld part{i})", hashlib.md5(raw_part).digest()
                    yield f"md5(bld part{i} str)", hashlib.md5(part.encode()).digest()
    except OSError:
        pass


def main() -> None:
    raw, tag = load_record()
    tried = 0
    for name, key in candidates():
        tried += 1
        if try_key(name, key, raw, tag):
            return
        if tried % 50000 == 0:
            print(f"  ... {tried} candidates tried", flush=True)
    print(f"no key found among {tried} candidates")


if __name__ == "__main__":
    sys.exit(main())
