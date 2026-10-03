"""DNS leak test — same backend (bash.ws) as dnsleaktest.com and the
`dnsleaktest` CLI (https://github.com/macvk/dnsleaktest, MIT). Reimplemented
directly rather than shelling out to that script: a probe only needs to
trigger a DNS *lookup* of a unique subdomain, not a real ping (the ICMP
reply is discarded by the shell client too — only the lookup that reaches
bash.ws's authoritative nameserver matters), so a plain
socket.getaddrinfo() does the job with no external ping/curl/jq dependency.

Protocol: GET /id for a fresh test id, resolve {1..N}.{id}.bash.ws (whichever
resolver(s) your system actually uses for it), then GET
/dnsleak/test/{id}?json for what answered — entries tagged "ip" (your
public IP), "dns" (each detected resolver), "conclusion" (bash.ws's own
verdict text).
"""

import concurrent.futures
import contextlib
import json
import re
import socket
import urllib.request

API = "bash.ws"
PROBE_COUNT = 30
PROBE_TIMEOUT = 5  # seconds, bounds the whole probe wave regardless of stragglers
REQUEST_TIMEOUT = 8  # seconds, per HTTP call

# Public anycast resolvers — their egress can sit in any country near the
# tunnel exit, so answering from one of these is never a leak on its own.
NEUTRAL_ASNS = {
    13335,  # Cloudflare (1.1.1.1)
    15169,  # Google (8.8.8.8)
    19281,  # Quad9 (9.9.9.9)
    36692,  # Cisco OpenDNS
}


def _get_test_id() -> str:
    with urllib.request.urlopen(f"https://{API}/id", timeout=REQUEST_TIMEOUT) as resp:
        return resp.read().decode().strip()


def _probe(host: str) -> None:
    with contextlib.suppress(OSError):  # a failed lookup is fine — only the attempt matters
        socket.getaddrinfo(host, None)


def _send_probes(test_id: str) -> None:
    hosts = [f"{i}.{test_id}.{API}" for i in range(1, PROBE_COUNT + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=PROBE_COUNT) as pool:
        futures = [pool.submit(_probe, h) for h in hosts]
        concurrent.futures.wait(futures, timeout=PROBE_TIMEOUT)


def _fetch_results(test_id: str) -> list[dict]:
    url = f"https://{API}/dnsleak/test/{test_id}?json"
    with urllib.request.urlopen(url, timeout=REQUEST_TIMEOUT) as resp:
        return json.loads(resp.read().decode())


def asn_number(asn: str | None) -> int | None:
    """13335 for bash.ws's 'AS13335 CloudFlare Inc', None if unparseable."""
    match = re.match(r"AS(\d+)", asn or "", re.IGNORECASE)
    return int(match.group(1)) if match else None


def server_tags(server: dict, ip_country: str, ip_asn: int | None) -> list[str]:
    """Own leak heuristic for one resolver, independent of bash.ws's verdict
    (which knows nothing about which VPN is up). A resolver is trusted when
    it's a public anycast service (NEUTRAL_ASNS) or shares the exit IP's
    ASN (the VPN provider's own DNS). Otherwise: 'ASN' — not the VPN's and
    not public; 'GEO' — sits in a different country than the exit IP. Each
    rule stays quiet when the data it needs is missing, so a sparse bash.ws
    reply never produces a false alarm."""
    asn = asn_number(server.get("asn"))
    if asn is not None and (asn in NEUTRAL_ASNS or asn == ip_asn):
        return []
    tags = []
    if asn is not None and ip_asn is not None:
        tags.append("ASN")
    country = (server.get("country") or "").upper()
    if country and ip_country and country != ip_country:
        tags.append("GEO")
    return tags


def run() -> dict | None:
    """{'ip', 'ip_country': 'DE'|'', 'ip_asn': 24940|None, 'dns_servers':
    [{'ip', 'country', 'country_name', 'asn', 'org'}], 'conclusion'} for a
    fresh test, or None
    on any network failure. ip_country is the 2-letter code bash.ws reports
    for the detected public IP itself (present in its "ip"-type entry, same
    shape as the "dns" entries) — kept separate from the bare ip string so
    the UI layer can render a flag without re-parsing the raw entry."""
    try:
        test_id = _get_test_id()
        if not test_id:
            return None
        _send_probes(test_id)
        entries = _fetch_results(test_id)
    except (OSError, ValueError):
        return None

    if not isinstance(entries, list):
        return None
    ip_entry = next((e for e in entries if e.get("type") == "ip"), None)
    dns_servers = [e for e in entries if e.get("type") == "dns"]
    conclusion = next((e.get("ip") for e in entries if e.get("type") == "conclusion"), "")
    return {
        "ip": ip_entry.get("ip") if ip_entry else None,
        "ip_country": ((ip_entry or {}).get("country") or "").upper(),
        "ip_asn": asn_number((ip_entry or {}).get("asn")),
        "dns_servers": dns_servers,
        "conclusion": conclusion or "",
    }
