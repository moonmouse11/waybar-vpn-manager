"""Happ subscription metadata: providers, per-server info, ping cache.

Providers (subscription groups) are parsed from the Happ GUI log —
subscription_log.txt pairs "Subscription #<id> starting update from: <url>"
with "<name> fetching subscription from <url>". Results are cached by the
log's mtime.

Ping is TCP connect RTT to the server's host:port, measured by a background
`vpn_manager.py --update-ping` run and cached on disk, so menus never block
on the network.
"""

import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

LOG_FILE = Path.home() / ".local/share/Happ/logs/subscription_log.txt"
ROUTING_FILE = Path.home() / ".config/Happ/routing.json"
PROVIDERS_CACHE = Path.home() / ".cache/vpn-manager/happ-providers.json"
PING_CACHE = Path.home() / ".cache/vpn-manager/happ-ping.json"
CAPTURED_PROVIDERS = Path.home() / ".config/happ-capture/xray-providers.json"
XRAY_CONFIGS = Path.home() / ".config/happ-capture/xray-configs.json"

PING_MAX_AGE = 300  # seconds
PING_TIMEOUT = 3.0

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"


# ── Providers ─────────────────────────────────────────────────────────────────


def _parse_providers() -> dict[str, str]:
    """subscription id -> display name."""
    id_url: dict[str, str] = {}
    url_name: dict[str, str] = {}
    try:
        text = LOG_FILE.read_text(errors="replace")
    except OSError:
        text = ""
    for m in re.finditer(r"Subscription #(-?\d+) starting update from: (\S+)", text):
        id_url[m.group(1)] = m.group(2)
    for m in re.finditer(r"\](?: ?\[[^\]]+\])* ?(.+?) fetching subscription from (\S+)", text):
        name = m.group(1).strip()
        if name:
            url_name[m.group(2)] = name

    providers: dict[str, str] = {}
    for sub_id, url in id_url.items():
        name = url_name.get(url)
        if not name:
            host = re.sub(r"^https?://", "", url).split("/")[0]
            name = next((n for u, n in url_name.items() if host in u), None)
        providers[sub_id] = name or f"Subscription {sub_id}"

    # Fallback / enrichment from routing.json (routing names per subscription)
    try:
        routing = json.loads(ROUTING_FILE.read_text())
        for r in routing.get("routings", []):
            sub_id = str(r.get("subscriptionId", ""))
            if sub_id and sub_id not in providers and r.get("name"):
                providers[sub_id] = r["name"]
    except (OSError, json.JSONDecodeError):
        pass
    return providers


def providers() -> dict[str, str]:
    """id -> name, cached by the log's mtime."""
    try:
        mtime = LOG_FILE.stat().st_mtime
    except OSError:
        mtime = 0
    try:
        cache = json.loads(PROVIDERS_CACHE.read_text())
        if cache.get("mtime") == mtime:
            return cache.get("providers", {})
    except (OSError, json.JSONDecodeError):
        pass
    result = _parse_providers()
    try:
        PROVIDERS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PROVIDERS_CACHE.write_text(json.dumps({"mtime": mtime, "providers": result}))
    except OSError:
        pass
    return result


def captured_providers() -> dict[str, str]:
    """server name -> subscription id (sidecar written by the capture tool)."""
    try:
        data = json.loads(CAPTURED_PROVIDERS.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


# ── Server info (protocol/host/port from captured xray configs) ──────────────


def _configs() -> dict:
    try:
        data = json.loads(XRAY_CONFIGS.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def server_params(name: str) -> dict | None:
    """{host, port, protocol, network, security} for a captured server."""
    configs = _configs()
    cfg = configs.get(name)
    if cfg is None:  # fuzzy fallback
        for key, value in configs.items():
            if name in key or key in name:
                cfg = value
                break
    if not cfg:
        return None
    try:
        outbound = next(o for o in cfg["outbounds"] if o.get("protocol") == "vless")
        vnext = outbound["settings"]["vnext"][0]
        stream = outbound.get("streamSettings", {})
        return {
            "host": vnext["address"],
            "port": vnext["port"],
            "protocol": outbound["protocol"],
            "network": stream.get("network", "tcp"),
            "security": stream.get("security", ""),
        }
    except (KeyError, IndexError, StopIteration):
        return None


# ── Ping cache ────────────────────────────────────────────────────────────────


def _read_pings() -> dict:
    try:
        data = json.loads(PING_CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def ping_ms(name: str) -> float | None:
    entry = _read_pings().get(name)
    if not entry:
        return None
    if time.time() - entry.get("at", 0) > PING_MAX_AGE:
        return None
    return entry.get("ms")


def request_ping_update() -> None:
    """Fire-and-forget background ping refresh if the cache is stale."""
    pings = _read_pings()
    if time.time() - pings.get("updated_at", 0) < PING_MAX_AGE:
        return
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-ping"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def measure_ping(host: str, port: int) -> float | None:
    """TCP connect RTT (best of 2), None on failure."""
    best = None
    for _ in range(2):
        start = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=PING_TIMEOUT):
                ms = (time.perf_counter() - start) * 1000
                best = ms if best is None else min(best, ms)
        except OSError:
            return None
    return round(best, 1) if best is not None else None


def update_pings() -> None:
    """Background entry point: refresh the ping cache for all known servers."""
    pings: dict[str, dict] = {}
    for name in _configs():
        params = server_params(name)
        if not params:
            continue
        ms = measure_ping(params["host"], params["port"])
        pings[name] = {"ms": ms, "at": time.time()}
    pings["updated_at"] = time.time()
    try:
        PING_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PING_CACHE.write_text(json.dumps(pings))
    except OSError:
        pass


# ── Menu labels ───────────────────────────────────────────────────────────────


def server_info_suffix(name: str) -> str:
    """'42 ms · vless/tcp/reality · host:port' for menu labels."""
    parts = []
    ms = ping_ms(name)
    if ms is not None:
        parts.append(f"{ms:.0f} ms")
    params = server_params(name)
    if params:
        proto = "/".join(
            p for p in (params["protocol"], params["network"], params["security"]) if p
        )
        parts.append(proto)
        parts.append(f"{params['host']}:{params['port']}")
    return " · ".join(parts)
