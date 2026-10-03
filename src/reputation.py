"""VPN exit/server IP reputation — flags connections against every enabled
source in ipsources.ALL_SOURCES (Russian-linked registration, datacenter/
proxy flags — see ipsources/ for the individual sources).

Not a privacy/leak check by itself — purely a labelling aid so servers can
be told apart in the menu, discovered manually during a DNS-leak
investigation where several "Germany"-labelled Happ servers turned out to
be registered to Russian entities (.ru/.su ASN-owner domains) or to be a
bridge routing physically through Russia.

Same fire-and-forget cache pattern as happmeta's ping cache (PING_CACHE),
but keyed by connection name with a much longer TTL — ASN registration is
stable, unlike RTT. write_reputations() (the daily background sweep across
every known server) only ever passes include_keyed=False — keyed/paid
sources are for the on-demand lookup_self() ("IP Info" menu action) only,
so a paid source's monthly quota is never at risk from routine menu use.
"""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import ipsources
from ipsources.base import IPFinding, fetch_json

CACHE = Path.home() / ".cache/vpn-manager/reputation.json"
MAX_AGE = 24 * 3600  # a day — registration data doesn't change hour to hour
LOOKUP_TIMEOUT = 8  # seconds, thread-guarded (urlopen's timeout excludes DNS)
IPWHO_API = "https://ipwho.is/"  # used only by _detect_own_ip()'s primary check
IPAPI_PACE = 1.5  # seconds between sweep hosts, keeps well under ip-api.com's 45/min cap

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"


def _reason_tags(entry: dict) -> list[str]:
    """Which criteria this entry tripped, in display order. Takes a plain
    dict (not an IPFinding) — this is also called directly by ipinfo.py's
    status_line() and vpn_manager._dns_leak_server_row(), each building an
    ad-hoc dict from a data source unrelated to ipsources."""
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


def combined_tags(findings: list[IPFinding]) -> list[str]:
    """Union of _reason_tags() over every finding, in first-seen order —
    reuses the single-dict rules per finding instead of duplicating them."""
    tags: list[str] = []
    for finding in findings:
        for tag in _reason_tags(vars(finding)):
            if tag not in tags:
                tags.append(tag)
    return tags


def is_flagged(findings: list[IPFinding]) -> bool:
    return bool(combined_tags(findings))


def _ipwho_bootstrap_enabled() -> bool:
    for source in ipsources.ALL_SOURCES:
        if source.key == "ipwhois":
            return source.is_enabled()
    return True


def _detect_own_ip() -> str | None:
    """Bootstrap for lookup_self(): the same ipwho.is-then-ifconfig.me
    fallback chain ipinfo.py uses for its own exit-IP cache, duplicated
    here (not imported) — ipinfo.py already imports reputation for
    is_suspicious(), so importing ipinfo back would be circular. Skips
    ipwho.is when the user disabled ipwho.is in config."""
    if _ipwho_bootstrap_enabled():
        data = fetch_json(IPWHO_API, timeout=6)
        if data and data.get("success") and data.get("ip"):
            return data["ip"]
    try:
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=6) as resp:
            return resp.read().decode().strip()
    except OSError:
        return None


def _enabled_sources(include_keyed: bool):
    return [
        s
        for s in ipsources.ALL_SOURCES
        if s.is_enabled() and (include_keyed or not s.needs_api_key)
    ]


def lookup_host(host: str, include_keyed: bool) -> list[IPFinding]:
    """Resolves host once, queries every enabled source with that one IP
    (thread-guarded exactly like the old single-source _lookup() was —
    urlopen's timeout does not cover gethostbyname(), which can hang far
    longer than LOOKUP_TIMEOUT). One source failing never breaks the
    others; a DNS failure yields no findings at all."""
    result: list[IPFinding] = []

    def _work() -> None:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return
        for source in _enabled_sources(include_keyed):
            try:
                finding = source.lookup(ip)
            except Exception:  # noqa: BLE001 - one bad source must not break the others
                finding = None
            if finding is not None:
                result.append(finding)

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout=LOOKUP_TIMEOUT)
    return list(result)


def lookup_self(include_keyed: bool = True) -> list[IPFinding]:
    """On-demand 'IP Info': detect the caller's own public IP once, then
    every enabled source (keyed included by default) against that one
    address — every source is asked about the SAME IP, rather than each
    source's own "self-detect" endpoint potentially reporting a different
    one. The source-querying phase is thread-guarded exactly like
    lookup_host()'s: this feeds a synchronous, interactive menu action, so
    up to 4 sources each with their own up-to-8s fetch_json timeout must
    never add up to more than ~LOOKUP_TIMEOUT of total wall-clock time
    (_detect_own_ip()'s own timeout chain, run before this guard starts,
    is a separate, smaller, already-bounded cost)."""
    ip = _detect_own_ip()
    if not ip:
        return []
    findings: list[IPFinding] = []

    def _work() -> None:
        for source in _enabled_sources(include_keyed):
            try:
                finding = source.lookup(ip)
            except Exception:  # noqa: BLE001 - one bad source must not break the others
                finding = None
            if finding is not None:
                findings.append(finding)

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout=LOOKUP_TIMEOUT)
    return list(findings)


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


def country_of(name: str) -> str | None:
    """Upper-case country code of a connection's server from the last sweep,
    or None if never measured. Ignores MAX_AGE on purpose: unlike the
    tags, a server's country practically never changes between sweeps."""
    entry = _read().get(name)
    if not isinstance(entry, dict):
        return None
    return (entry.get("country_code") or "").upper() or None


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
    each unique host is looked up once (free sources only —
    include_keyed=False) and the result fanned out to every name that uses
    it. Paced between hosts (IPAPI_PACE) to stay under ip-api.com's
    free-tier rate limit — this only runs in the background, once a day,
    so the extra time doesn't matter."""
    by_host: dict[str, list[IPFinding]] = {}
    entries: dict[str, dict] = {}
    for name, host, _port in targets:
        if host not in by_host:
            try:
                by_host[host] = lookup_host(host, include_keyed=False)
            except Exception:  # noqa: BLE001 - one bad host must not abort the sweep
                by_host[host] = []
            time.sleep(IPAPI_PACE)
        findings = by_host[host]
        if not findings:
            continue
        entries[name] = {
            "at": time.time(),
            "suspicious": is_flagged(findings),
            "tags": combined_tags(findings),
            "country_code": findings[0].country_code,
        }
    entries["updated_at"] = time.time()
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(entries, ensure_ascii=False))
    except OSError:
        pass
