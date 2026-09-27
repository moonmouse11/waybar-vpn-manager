"""VPN exit/server IP reputation — flags connections whose network looks
Russian-linked or datacenter/proxy-flagged, via two free, keyless sources:
ipwho.is (country + ASN-owner domain) and ip-api.com (adds `hosting` /
`proxy` / `mobile` flags — the same kind of DataCenter/Residential/Proxy
classification a paid multi-source checker like checkip.com shows, without
needing an API key).

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
IPWHO_API = "https://ipwho.is/"
# ip-api.com's free tier is HTTP-only (no key) and capped at 45 req/min —
# fine for an ip that's just a public address, no credentials involved.
IPAPI_URL = "http://ip-api.com/json/{}"
IPAPI_FIELDS = "status,country,countryCode,isp,org,as,proxy,hosting,mobile,query"
IPAPI_PACE = 1.5  # seconds between sweep calls, keeps well under the 45/min cap

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"


def _reason_tags(entry: dict) -> list[str]:
    """Which criteria this entry tripped, in display order."""
    tags = []
    domain = (entry.get("domain") or "").lower()
    if entry.get("country_code") == "RU" or domain.endswith((".ru", ".su")):
        tags.append("RU")
    if entry.get("hosting"):
        tags.append("DC")
    if entry.get("proxy"):
        tags.append("PROXY")
    return tags


def is_suspicious(entry: dict) -> bool:
    return bool(_reason_tags(entry))


def _get_json(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=6) as resp:
            return json.loads(resp.read().decode())
    except (OSError, ValueError):
        return None


def _lookup_ipapi(ip: str) -> dict:
    """{'hosting', 'proxy', 'mobile'} (bools) from ip-api.com, or {} on any
    failure — kept separate from ipwho.is so one source's outage never
    blocks the other's data."""
    data = _get_json(IPAPI_URL.format(ip) + f"?fields={IPAPI_FIELDS}")
    if not data or data.get("status") != "success":
        return {}
    return {
        "hosting": bool(data.get("hosting")),
        "proxy": bool(data.get("proxy")),
        "mobile": bool(data.get("mobile")),
        "ipapi_country": data.get("country"),
        "ipapi_isp": data.get("isp"),
        "ipapi_as": data.get("as"),
    }


def _lookup(host: str) -> dict | None:
    """{'country_code', 'domain', 'hosting', 'proxy', 'mobile', ...} for a
    host's IP, merging ipwho.is + ip-api.com, or None on total failure.
    Thread-guarded: urlopen's timeout does not cover the gethostbyname()
    call, which can hang far longer than LOOKUP_TIMEOUT."""
    result: dict = {}

    def _work() -> None:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return
        data = _get_json(f"{IPWHO_API}{ip}")
        if data and data.get("success"):
            conn = data.get("connection") or {}
            result["country_code"] = data.get("country_code")
            result["domain"] = conn.get("domain")
        result.update(_lookup_ipapi(ip))

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout=LOOKUP_TIMEOUT)
    return result or None


def lookup_self() -> dict | None:
    """Combined report for the caller's own public IP — used by the
    on-demand 'IP Info' menu action (a single ad-hoc lookup, unlike the
    background sweep this skips the cache and pacing entirely)."""
    a = _get_json(IPWHO_API) or {}
    b = _get_json(f"http://ip-api.com/json?fields={IPAPI_FIELDS}") or {}
    if not a and not b:
        return None
    conn = a.get("connection") or {}
    return {
        "ip": a.get("ip") or b.get("query"),
        "ipwho_country": a.get("country"),
        "ipwho_org": conn.get("org"),
        "ipapi_country": b.get("country"),
        "ipapi_isp": b.get("isp"),
        "ipapi_as": b.get("as"),
        "hosting": bool(b.get("hosting")),
        "proxy": bool(b.get("proxy")),
        "mobile": bool(b.get("mobile")),
    }


def _read() -> dict:
    try:
        data = json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def mark(name: str) -> str:
    """' ⚠RU/DC' for a flagged connection (only the tags that actually
    tripped), '' otherwise — including a connection never measured yet, so
    the menu stays quiet before the first sweep completes rather than
    marking everything as unknown."""
    entry = _read().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > MAX_AGE:
        return ""
    tags = entry.get("tags") or []
    return f" ⚠{'/'.join(tags)}" if tags else ""


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
    name that uses it. Paced between actual lookups (IPAPI_PACE) to stay
    under ip-api.com's free-tier rate limit — this only runs in the
    background, once a day, so the extra time doesn't matter."""
    by_host: dict[str, dict | None] = {}
    entries: dict[str, dict] = {}
    for name, host, _port in targets:
        if host not in by_host:
            try:
                by_host[host] = _lookup(host)
            except Exception:  # noqa: BLE001 - one bad host must not abort the sweep
                by_host[host] = None
            time.sleep(IPAPI_PACE)
        result = by_host[host]
        if result is None:
            continue
        entries[name] = {
            "at": time.time(),
            "suspicious": is_suspicious(result),
            "tags": _reason_tags(result),
            "country_code": result.get("country_code"),
        }
    entries["updated_at"] = time.time()
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(entries, ensure_ascii=False))
    except OSError:
        pass
