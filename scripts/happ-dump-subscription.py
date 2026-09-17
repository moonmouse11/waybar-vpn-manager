#!/usr/bin/env python3
"""Dev tool: extract the decrypted Happ subscription from the GUI process memory.

subs.db on disk is AES-GCM encrypted; the running GUI holds the decoded
subscription JSON in RAM. This scans its rw memory regions for JSON with a
"servers"/"remarks" structure and saves it locally.

Usage (needs root to ptrace the GUI):
  sudo python3 scripts/happ-dump-subscription.py [pid]

Output: ~/.config/happ-capture/subscription.json (mode 600)
"""

import json
import os
import pwd
import re
import sys
from pathlib import Path


def _home() -> Path:
    """Target user's home even when run via sudo."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


OUT = _home() / ".config/happ-capture/subscription.json"
MARKERS = [b'"remarks"', b'"servers"', b'"host"', "ARTΞMIDA".encode()]
MAX_REGION = 512 * 1024 * 1024


def rw_regions(pid: int):
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("rw"):
            start, end = (int(x, 16) for x in parts[0].split("-"))
            if end - start <= MAX_REGION:
                yield start, end


def read_region(pid: int, start: int, end: int) -> bytes:
    with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
        mem.seek(start)
        return mem.read(end - start)


def _scan(data: bytes, start: int, open_ch: int, close_ch: int) -> int:
    """Index just past the balanced {} / [] block starting at data[start].
    String- and escape-aware. -1 if not balanced within data."""
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(data)):
        ch = data[i]
        if in_str:
            if esc:
                esc = False
            elif ch == 0x5C:  # backslash
                esc = True
            elif ch == 0x22:  # quote
                in_str = False
            continue
        if ch == 0x22:
            in_str = True
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _brace_end(data: bytes, start: int) -> int:
    return _scan(data, start, 0x7B, 0x7D)


def _bracket_end(data: bytes, start: int) -> int:
    return _scan(data, start, 0x5B, 0x5D)


def extract_jsons(data: bytes):
    """Yield candidate JSON documents in memory.

    The decrypted subscription is pretty-printed with zero indent at the
    root, so root objects start a line as bare '{' (nested objects are
    indented). We try every zero-indent '{' / '[' near the markers.
    """
    hits = [m.start() for marker in MARKERS for m in re.finditer(re.escape(marker), data)]
    starts = set()
    for pos in hits:
        lo = max(0, pos - 8_000_000)
        for s in re.finditer(rb"\n\{\n|\n\[\n", data[lo:pos]):
            starts.add(lo + s.start() + 1)
    for start in sorted(starts):
        opener = data[start : start + 1]
        end = _brace_end(data, start) if opener == b"{" else _bracket_end(data, start)
        if end < 0:
            continue
        try:
            obj = json.loads(data[start:end].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
        yield obj


def _server_count(obj) -> int:
    if isinstance(obj, dict):
        servers = obj.get("servers")
        if isinstance(servers, list):
            return len(servers)
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        return len(obj)
    return 0


def _servers(obj) -> list:
    if isinstance(obj, dict):
        servers = obj.get("servers")
        if isinstance(servers, list):
            return servers
    if isinstance(obj, list):
        return obj
    return []


def main() -> None:
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        re.search(r"\d+", __import__("subprocess").run(
            ["pgrep", "-x", "happ"], capture_output=True, text=True
        ).stdout.split()[0]).group()
    )
    print(f"scanning GUI process {pid} ...")
    best = None
    scanned = 0
    found = 0
    for start, end in rw_regions(pid):
        try:
            data = read_region(pid, start, end)
        except (PermissionError, OSError):
            continue
        scanned += len(data)
        for obj in extract_jsons(data):
            found += 1
            count = _server_count(obj)
            size = len(json.dumps(obj))
            print(f"  candidate: {size} bytes, {count} servers")
            if count and (best is None or count > best[0]):
                best = (count, obj)
    print(f"scanned {scanned / 1024 / 1024:.0f} MiB, {found} JSON docs")
    if not best:
        sys.exit("no subscription JSON found in memory")
    count, obj = best
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(obj, ensure_ascii=False, indent=1))
    OUT.chmod(0o600)
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid:
        os.chown(OUT, int(sudo_uid), -1)
    print(f"saved {OUT} ({count} servers)")
    for s in _servers(obj)[:10]:
        print("  -", s.get("remarks") or s.get("name") or s.get("host"))


if __name__ == "__main__":
    main()
