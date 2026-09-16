"""Exit-IP detection with an on-disk cache.

`--status` never blocks on the network: it only reads the cache, and if the
data is stale (or belongs to a different connection) fire-and-forgets a
background `vpn_manager.py --update-ip <connection>` run.

Cache: ~/.cache/vpn-manager/exit_ip.json
"""

import json
import time
import urllib.request
from pathlib import Path

CACHE_PATH = Path.home() / ".cache" / "vpn-manager" / "exit_ip.json"
# ipwho.is gives IP + country in one request; ifconfig.me is the plain-IP fallback
API_PRIMARY = "https://ipwho.is/"
API_FALLBACK = "https://ifconfig.me/ip"
RECHECK_AFTER_ERROR = 60  # seconds, avoid hammering when the tunnel is down


def flag_emoji(country_code: str | None) -> str:
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def read_cache() -> dict | None:
    try:
        data = json.loads(CACHE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def is_fresh(cache: dict | None, connection: str, max_age: int) -> bool:
    if not cache or cache.get("error"):
        return False
    if cache.get("connection") != connection:
        return False
    return time.time() - cache.get("fetched_at", 0) < max_age


def status_line(connection: str, max_age: int) -> str | None:
    """Tooltip line like 'Exit: 144.31.166.213 🇩🇪', or None if stale/missing."""
    cache = read_cache()
    if not is_fresh(cache, connection, max_age):
        return None
    line = f"Exit: {cache['ip']}"
    flag = flag_emoji(cache.get("country_code"))
    if flag:
        line += f" {flag}"
    return line


def update(connection: str) -> None:
    """Fetch exit IP in the background. Failures are cached briefly."""
    cache = read_cache() or {}
    if (
        cache.get("connection") == connection
        and time.time() - cache.get("fetched_at", 0) < RECHECK_AFTER_ERROR
    ):
        return  # another background run handled this very recently

    entry: dict = {"connection": connection, "fetched_at": time.time()}
    try:
        entry.update(_fetch())
    except OSError as e:
        entry["error"] = str(e)[:120]

    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(entry))
        tmp.replace(CACHE_PATH)
    except OSError:
        pass


def _fetch() -> dict:
    try:
        with urllib.request.urlopen(API_PRIMARY, timeout=6) as resp:
            data = json.loads(resp.read().decode())
        if data.get("success") and data.get("ip"):
            return {"ip": data["ip"], "country_code": data.get("country_code")}
    except (OSError, ValueError):
        pass
    with urllib.request.urlopen(API_FALLBACK, timeout=6) as resp:
        return {"ip": resp.read().decode().strip(), "country_code": None}
