#!/usr/bin/env python3
"""Dev tool: marker census of the Happ GUI process memory.

Scans rw regions and reports every hit of the given markers with hex context,
saving hits to /tmp/happ-mem-hits.txt for offline analysis. Use this when the
subscription JSON is not stored as one QByteArray (Qt model keeps QStrings).

Usage:
  sudo python3 scripts/happ-mem-census.py [pid]
"""

import re
import sys
from pathlib import Path

MARKERS = {
    "artemida-live": b"artemida.live",
    "sub-token": b"Mtj_TFNk4tuCcCm9",
    "server-uuid": b"18e8a24a-4d6b-4b04",
    "germany-utf8": "Germany".encode(),
    "germany-utf16": "Germany".encode("utf-16-le"),
    "estonia-utf16": "Estonia".encode("utf-16-le"),
    "remarks-json": b'"remarks"',
    "host-json": b'"host"',
    "vless": b"vless://",
    "xray-uuid-field": b'"id"',
}
MAX_REGION = 512 * 1024 * 1024
OUT = Path("/tmp/happ-mem-hits.txt")


def rw_regions(pid: int):
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("rw"):
            start, end = (int(x, 16) for x in parts[0].split("-"))
            if end - start <= MAX_REGION:
                yield start, end, parts[-1] if len(parts) >= 6 else ""


def main() -> None:
    import subprocess

    pid = int(sys.argv[1]) if len(sys.argv) > 1 else int(
        subprocess.run(["pgrep", "-x", "happ"], capture_output=True, text=True).stdout.split()[0]
    )
    print(f"scanning GUI process {pid} ...")
    hits = 0
    scanned = 0
    with OUT.open("w") as out:
        for start, end, name in rw_regions(pid):
            try:
                with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
                    mem.seek(start)
                    data = mem.read(end - start)
            except (PermissionError, OSError):
                continue
            scanned += len(data)
            for label, marker in MARKERS.items():
                for m in re.finditer(re.escape(marker), data):
                    hits += 1
                    ctx = data[max(0, m.start() - 40) : m.start() + 120]
                    out.write(f"=== {label} @ {hex(start)}+{m.start()} map={name}\n")
                    out.write(ctx.hex() + "\n")
                    out.write(repr(ctx) + "\n")
    print(f"scanned {scanned / 1024 / 1024:.0f} MiB, {hits} hits -> {OUT}")


if __name__ == "__main__":
    main()
