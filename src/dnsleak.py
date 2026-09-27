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
import socket
import urllib.request

API = "bash.ws"
PROBE_COUNT = 30
PROBE_TIMEOUT = 5  # seconds, bounds the whole probe wave regardless of stragglers
REQUEST_TIMEOUT = 8  # seconds, per HTTP call


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


def run() -> dict | None:
    """{'ip', 'ip_country': 'DE'|'', 'dns_servers': [{'ip', 'country',
    'country_name', 'asn', 'org'}], 'conclusion'} for a fresh test, or None
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
        "dns_servers": dns_servers,
        "conclusion": conclusion or "",
    }
