#!/usr/bin/env python3
"""Dev tool: extract the xray config (happd "start" frame stdin-data) from a
strace capture of happd, and save it for headless replay.

Usage:
  python3 scripts/happd-extract-config.py /tmp/happd.strace [output.json]

The output maps the Happ server name ("remarks") to the full xray config:
  {"<server name>": {...xray config...}}

Run with sudo if the strace file is root-owned.
"""

import json
import re
import sys
from pathlib import Path


def decode_strace_string(raw: str) -> bytes:
    """Decode a C-escaped string as printed by strace.

    Octal escapes are 1-3 digits ("\0" is a single NUL), plus the usual
    C shorthands (\n \t \r \f \v \a \b), \\ and \".
    """
    out = bytearray()
    simple = {"n": 10, "t": 9, "r": 13, "f": 12, "v": 11, "a": 7, "b": 8}
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch != "\\":
            out.extend(ch.encode())
            i += 1
            continue
        nxt = raw[i + 1 : i + 2]
        if nxt in "01234567":
            digits = ""
            j = i + 1
            while j < len(raw) and raw[j] in "01234567" and len(digits) < 3:
                digits += raw[j]
                j += 1
            out.append(int(digits, 8))
            i = j
        elif nxt in simple:
            out.append(simple[nxt])
            i += 2
        else:  # \\, \" and any other escaped char
            out.extend(nxt.encode())
            i += 2
    return bytes(out)


def extract_start_frames(path: Path) -> list[dict]:
    data = path.read_bytes().decode("utf-8", errors="replace")
    frames = []
    # strace read lines: read(9, "\0\0\f\361{...}", 123) = 123
    for match in re.finditer(r'read\(\d+, "((?:[^"\\]|\\.)*)"', data):
        payload = decode_strace_string(match.group(1))
        if len(payload) < 4:
            continue
        (length,) = int.from_bytes(payload[:4], "big"), 
        body = payload[4:]
        if len(body) != length:
            continue
        try:
            frame = json.loads(body)
        except json.JSONDecodeError:
            continue
        if frame.get("action") == "start" and frame.get("stdin-data"):
            frames.append(frame)
    return frames


def main() -> None:
    strace_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/happd.strace")
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    frames = extract_start_frames(strace_path)
    if not frames:
        sys.exit(f"no 'start' frames found in {strace_path}")

    configs: dict[str, dict] = {}
    server_provider: dict[str, str] = {}
    for frame in frames:
        try:
            xray_config = json.loads(frame["stdin-data"])
        except json.JSONDecodeError as e:
            print(f"skip frame {frame.get('process-id')}: bad stdin-data: {e}")
            continue
        name = xray_config.get("remarks") or frame.get("process-id") or "unknown"
        configs[name] = xray_config
        asset = (frame.get("environment") or {}).get("XRAY_LOCATION_ASSET", "")
        # /home/<user>/.local/share/Happ/routing/<subscriptionId>/<routingName>
        parts = Path(asset).parts
        if "routing" in parts:
            idx = parts.index("routing")
            if len(parts) > idx + 1:
                server_provider[name] = parts[idx + 1]
        print(f"capture: {name} (process-id={frame.get('process-id')}, "
              f"{len(frame['stdin-data'])} bytes, sub={server_provider.get(name, '?')})")

    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(configs, ensure_ascii=False, indent=2))
        out_path.chmod(0o600)
        print(f"saved -> {out_path}")
        prov_path = out_path.with_name("xray-providers.json")
        existing: dict = {}
        if prov_path.exists():
            try:
                existing = json.loads(prov_path.read_text())
            except json.JSONDecodeError:
                existing = {}
        existing.update(server_provider)
        prov_path.write_text(json.dumps(existing, ensure_ascii=False, indent=1))
        prov_path.chmod(0o600)
        print(f"providers -> {prov_path} ({len(existing)} entries)")


if __name__ == "__main__":
    main()
