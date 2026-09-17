#!/usr/bin/env python3
"""Dev tool: find the subs.db AES-GCM key in the Happ GUI process memory.

v2: collects unique candidate offsets around the anchors first (dedupe +
merge overlaps), then checks them in a process pool. Much faster than the
naive per-anchor scan when anchors repeat a lot.

Usage (needs root):
  sudo .venv/bin/python scripts/subs-db-keymem.py
"""

import base64
import os
import pwd
import re
import sqlite3
import sys
from multiprocessing import Pool
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ANCHORS = [b"CREATE TABLE IF NOT EXISTS subscriptions", b"subs.db"]
RADIUS = 32_768
MAX_REGION = 1024 * 1024 * 1024

_blob = b""
_tag = b""


def _home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    return Path(pwd.getpwnam(sudo_user).pw_dir) if sudo_user else Path.home()


def _init(blob: bytes, tag: bytes) -> None:
    global _blob, _tag
    _blob, _tag = blob, tag


def _check(args) -> tuple | None:
    """Worker: try 16- and 32-byte keys at the given absolute offsets."""
    import re

    region_start, offsets = args
    try:
        with open(f"/proc/{os.environ['HAPP_PID']}/mem", "rb", buffering=0) as mem:
            mem.seek(region_start)
            # read far enough to cover the last offset + 32
            need = (offsets[-1] - region_start) + 32
            data = mem.read(need)
    except OSError:
        return None
    blob, tag = _blob, _tag
    for off in offsets:
        i = off - region_start
        key = data[i : i + 16]
        for nonce, ct in ((blob[:12], blob[12:]), (blob[-12:], blob[:-12])):
            try:
                pt = AESGCM(key).decrypt(nonce, ct + b"", tag)
                return ("AES-128", off, key, pt)
            except (InvalidTag, ValueError):
                pass
        key = data[i : i + 32]
        for nonce, ct in ((blob[:12], blob[12:]), (blob[-12:], blob[:-12])):
            try:
                pt = AESGCM(key).decrypt(nonce, ct + b"", tag)
                return ("AES-256", off, key, pt)
            except (InvalidTag, ValueError):
                pass
    return None


def main() -> None:
    import subprocess

    pid = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        subprocess.run(["pgrep", "-x", "happ"], capture_output=True, text=True).stdout.split()[0]
    )
    os.environ["HAPP_PID"] = str(pid)
    db = _home() / ".config/Happ/subs.db"
    con = sqlite3.connect(db)
    data_b64, tag_b64 = con.execute("SELECT data, tag FROM subscriptions").fetchone()
    blob, tag = base64.b64decode(data_b64), base64.b64decode(tag_b64)
    print(f"GUI pid {pid}, ciphertext {len(blob)} B, scanning...")

    # Phase 1: collect candidate offset ranges per region, deduped.
    regions: list[tuple[int, int, list[int]]] = []
    total_windows = 0
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split()
        if not (len(parts) >= 2 and parts[1].startswith("rw")):
            continue
        start, end = (int(x, 16) for x in parts[0].split("-"))
        if end - start > MAX_REGION:
            continue
        try:
            with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
                mem.seek(start)
                data = mem.read(end - start)
        except (PermissionError, OSError):
            continue
        hits = sorted(
            {m.start() for anchor in ANCHORS for m in re.finditer(re.escape(anchor), data)}
        )
        if not hits:
            continue
        # candidate offsets around all hits, deduped and merged
        wanted = set()
        for h in hits:
            wanted.update(range(max(0, h - RADIUS), min(len(data), h + RADIUS) - 16))
        offsets = sorted(wanted)
        # split into chunks so the pool can parallelize within big regions
        for i in range(0, len(offsets), 4096):
            regions.append((start, offsets[i : i + 4096]))
            total_windows += len(offsets[i : i + 4096])
    print(f"{len(regions)} work chunks, {total_windows} unique offsets")

    # Phase 2: check in parallel.
    with Pool(processes=max(2, os.cpu_count() or 4), initializer=_init, initargs=(blob, tag)) as pool:
        for result in pool.imap_unordered(_check, regions, chunksize=1):
            if result:
                kind, off, key, pt = result
                print(f"*** {kind} KEY @ {hex(off)}: {key.hex()}")
                print(pt[:400].decode("utf-8", errors="replace"))
                pool.terminate()
                return
    print("no key found")


if __name__ == "__main__":
    main()
