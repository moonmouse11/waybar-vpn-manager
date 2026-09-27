"""VPN exit/server IP reputation — flags connections whose network
registration looks Russian-linked via ipwho.is, even when physically
hosted elsewhere (a common pattern for resellers announcing IP space from
Western datacenters while being registered to a Russian entity).

Not a privacy/leak check by itself — purely a labelling aid so servers can
be told apart in the menu, discovered manually during a DNS-leak
investigation where several "Germany"-labelled Happ servers turned out to
be registered to Russian entities (.ru/.su ASN-owner domains) or to be a
bridge routing physically through Russia.

Same fire-and-forget cache pattern as happmeta's ping cache (PING_CACHE),
but keyed by connection name with a much longer TTL — ASN registration is
stable, unlike RTT.
"""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

CACHE = Path.home() / ".cache/vpn-manager/reputation.json"
MAX_AGE = 24 * 3600  # a day — registration data doesn't change hour to hour
LOOKUP_TIMEOUT = 8  # seconds, thread-guarded (urlopen's timeout excludes DNS)
API = "https://ipwho.is/"

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"


def is_suspicious(entry: dict) -> bool:
    """Russian-registered even if physically hosted elsewhere: country ==
    Russia, or the ASN owner's domain is a .ru/.su TLD."""
    if entry.get("country_code") == "RU":
        return True
    domain = (entry.get("domain") or "").lower()
    return domain.endswith(".ru") or domain.endswith(".su")


def _lookup(host: str) -> dict | None:
    """{'country_code', 'domain'} for a host's IP via ipwho.is, or None on
    any failure. Thread-guarded: urlopen's timeout does not cover the
    gethostbyname() call, which can hang far longer than LOOKUP_TIMEOUT."""
    result: dict = {}

    def _work() -> None:
        try:
            ip = socket.gethostbyname(host)
            with urllib.request.urlopen(f"{API}{ip}", timeout=6) as resp:
                data = json.loads(resp.read().decode())
        except (OSError, ValueError):
            return
        if not data.get("success"):
            return
        conn = data.get("connection") or {}
        result["country_code"] = data.get("country_code")
        result["domain"] = conn.get("domain")

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout=LOOKUP_TIMEOUT)
    return result or None


def _read() -> dict:
    try:
        data = json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def mark(name: str) -> str:
    """' ⚠RU' for a suspicious connection, '' otherwise — including a
    connection never measured yet, so the menu stays quiet before the
    first sweep completes rather than marking everything as unknown."""
    entry = _read().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > MAX_AGE:
        return ""
    return " ⚠RU" if entry.get("suspicious") else ""


def request_update() -> None:
    """Fire-and-forget background sweep if the cache is stale."""
    cache = _read()
    if time.time() - cache.get("updated_at", 0) < MAX_AGE:
        return
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-reputation"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def write_reputations(targets: list[tuple[str, str, int]]) -> None:
    """Measure and write the cache (single writer). Dedupes by host — many
    connections (e.g. Happ's rotating 'bridge' servers) share one host, so
    each unique host is looked up once and the result fanned out to every
    name that uses it."""
    by_host: dict[str, dict | None] = {}
    entries: dict[str, dict] = {}
    for name, host, _port in targets:
        if host not in by_host:
            try:
                by_host[host] = _lookup(host)
            except Exception:  # noqa: BLE001 - one bad host must not abort the sweep
                by_host[host] = None
        result = by_host[host]
        if result is None:
            continue
        entries[name] = {
            "at": time.time(),
            "suspicious": is_suspicious(result),
            "country_code": result.get("country_code"),
        }
    entries["updated_at"] = time.time()
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(entries, ensure_ascii=False))
    except OSError:
        pass
