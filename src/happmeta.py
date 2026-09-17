"""Happ subscription metadata: providers, servers, config generation, ping.

The full server list comes from the provider's subscription endpoint, fetched
directly with the app's own headers (captured once via scripts/sub-intercept-*;
Happ answers plain curl with a stub). Subscription configs are merged into
runnable xray configs the same way the GUI does it (local inbounds + dns-in +
dns-out + local routing rules), so any server can be connected headless.

Ping is TCP connect RTT to the server's host:port, measured by a background
`vpn_manager.py --update-ping` run and cached on disk, so menus never block
on the network.
"""

import copy
import json
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

LOG_FILE = Path.home() / ".local/share/Happ/logs/subscription_log.txt"
ROUTING_FILE = Path.home() / ".config/Happ/routing.json"
PROVIDERS_CACHE = Path.home() / ".cache/vpn-manager/happ-providers.json"
PING_CACHE = Path.home() / ".cache/vpn-manager/happ-ping.json"
CAPTURED_PROVIDERS = Path.home() / ".config/happ-capture/xray-providers.json"
XRAY_CONFIGS = Path.home() / ".config/happ-capture/xray-configs.json"
HEADERS_FILE = Path.home() / ".config/happ-capture/headers.json"
SUB_CACHE_DIR = Path.home() / ".cache/vpn-manager"

PING_MAX_AGE = 300  # seconds
SUB_MAX_AGE = 3600  # seconds
PING_TIMEOUT = 3.0

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"

# Local inbounds the GUI adds to every subscription config (from a capture).
DEFAULT_INBOUNDS = [
    {
        "port": 10808,
        "protocol": "socks",
        "settings": {"auth": "noauth", "udp": True},
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": False},
        "tag": "socks",
    },
    {
        "port": 10809,
        "protocol": "http",
        "settings": {"allowTransparent": False},
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": False},
        "tag": "http",
    },
    {
        "protocol": "tun",
        "settings": {
            "autoOutboundsInterface": "auto",
            "autoSystemRoutingTable": ["0.0.0.0/0"],
            "gateway": ["172.19.0.1/30"],
            "mtu": 1500,
            "name": "happ-xray",
            "userLevel": 8,
        },
        "sniffing": {"destOverride": ["http", "tls", "quic"], "enabled": True, "routeOnly": True},
        "tag": "tun-in",
    },
]

LOCAL_ROUTING_RULES = [
    {"inboundTag": ["tun-in"], "outboundTag": "direct", "process": ["self/", "xray"]},
    {"inboundTag": ["dns-in"], "outboundTag": "direct"},
    {"inboundTag": ["tun-in"], "network": "tcp,udp", "outboundTag": "dns-out", "port": "53"},
]
CATCH_ALL_RULE = {"network": "tcp,udp", "outboundTag": "proxy"}


# ── Providers ─────────────────────────────────────────────────────────────────


def _parse_providers() -> dict[str, dict]:
    """subscription id -> {"name": str, "url": str | None}."""
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

    providers: dict[str, dict] = {}
    for sub_id, url in id_url.items():
        name = url_name.get(url)
        if not name:
            host = re.sub(r"^https?://", "", url).split("/")[0]
            name = next((n for u, n in url_name.items() if host in u), None)
        providers[sub_id] = {"name": name or f"Subscription {sub_id}", "url": url}

    # Fallback names from routing.json (routing names per subscription)
    try:
        routing = json.loads(ROUTING_FILE.read_text())
        for r in routing.get("routings", []):
            sub_id = str(r.get("subscriptionId", ""))
            if sub_id and sub_id not in providers and r.get("name"):
                providers[sub_id] = {"name": r["name"], "url": None}
    except (OSError, json.JSONDecodeError):
        pass
    return providers


def providers() -> dict[str, dict]:
    """id -> {"name", "url"}, cached by the log's mtime."""
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


# ── Subscription fetching ─────────────────────────────────────────────────────


def _headers() -> dict[str, str] | None:
    """Captured Happ request headers (see scripts/sub-intercept-*)."""
    try:
        data = json.loads(HEADERS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) and data else None


def _sub_cache_path(sub_id: str) -> Path:
    return SUB_CACHE_DIR / f"subscription-{sub_id}.json"


def fetch_subscription(sub_id: str, url: str) -> list[dict]:
    """Server configs from the provider, cached for SUB_MAX_AGE.

    Falls back to the last good cache when the fetch fails or the provider
    answers with the anti-curl stub.
    """
    cache_path = _sub_cache_path(sub_id)
    try:
        cached = json.loads(cache_path.read_text())
    except (OSError, json.JSONDecodeError):
        cached = None

    if cached and time.time() - cached.get("at", 0) < SUB_MAX_AGE:
        return cached.get("servers", [])

    headers = _headers()
    if headers:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
            if isinstance(data, list) and data and isinstance(data[0], dict):
                servers = [s for s in data if s.get("outbounds")]
                try:
                    SUB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(
                        json.dumps({"at": time.time(), "servers": servers}, ensure_ascii=False)
                    )
                except OSError:
                    pass
                return servers
        except (OSError, ValueError):
            pass

    return cached.get("servers", []) if cached else []


# ── Config merge (subscription config -> runnable xray config) ────────────────


def build_runtime_config(server_cfg: dict) -> dict:
    """Merge a subscription server config like the Happ GUI does:
    local inbounds, dns-in tag, dns-out outbound, local routing rules,
    drop the subscription's own catch-all (we append our own)."""
    cfg = copy.deepcopy(server_cfg)
    cfg["inbounds"] = copy.deepcopy(DEFAULT_INBOUNDS)

    dns = cfg.get("dns") or {}
    dns["tag"] = "dns-in"
    cfg["dns"] = dns

    outbounds = cfg.get("outbounds") or []
    if not any(o.get("protocol") == "dns" for o in outbounds):
        outbounds.append({"protocol": "dns", "tag": "dns-out"})
    cfg["outbounds"] = outbounds

    rules = list(cfg.get("routing", {}).get("rules", []))
    rules = [
        r for r in rules if not (r.get("outboundTag") == "proxy" and r.get("network") == "tcp,udp")
    ]
    cfg.setdefault("routing", {})["rules"] = [*LOCAL_ROUTING_RULES, *rules, CATCH_ALL_RULE]
    cfg["log"] = {"loglevel": "info"}
    return cfg


# ── Server registry: subscription + captured union ────────────────────────────


def _configs() -> dict:
    try:
        data = json.loads(XRAY_CONFIGS.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def all_servers() -> list[dict]:
    """[{name, provider_id, provider_name, config(subscription raw)}] —
    everything we can connect to, grouped per provider."""
    servers = []
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if not url:
            continue
        for cfg in fetch_subscription(sub_id, url):
            name = cfg.get("remarks") or "?"
            servers.append(
                {
                    "name": name,
                    "provider_id": sub_id,
                    "provider_name": prov["name"],
                    "config": cfg,
                }
            )
    # Captured servers missing from every subscription (e.g. old captures)
    known = {s["name"] for s in servers}
    for name in _configs():
        if name not in known:
            servers.append(
                {
                    "name": name,
                    "provider_id": "",
                    "provider_name": "Прочие / без провайдера",
                    "config": _configs()[name],
                }
            )
    return servers


def resolve_config(name: str) -> dict | None:
    """Runnable xray config for a server name: merged from the subscription
    when available, otherwise a captured config used as-is."""
    for server in all_servers():
        if name == server["name"] or name in server["name"] or server["name"] in name:
            if server["provider_id"]:
                return build_runtime_config(server["config"])
            return server["config"]  # captured fallback
    return _configs().get(name)


# ── Server params / labels ────────────────────────────────────────────────────


def server_params(name: str) -> dict | None:
    """{host, port, protocol, network, security} for a server."""
    cfg = resolve_config(name)
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
    except (KeyError, IndexError, StopIteration, TypeError):
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
    for server in all_servers():
        params = server_params(server["name"])
        if not params:
            continue
        ms = measure_ping(params["host"], params["port"])
        pings[server["name"]] = {"ms": ms, "at": time.time()}
    pings["updated_at"] = time.time()
    try:
        PING_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PING_CACHE.write_text(json.dumps(pings, ensure_ascii=False))
    except OSError:
        pass


def server_info_suffix(name: str) -> str:
    """'42 ms · trojan/ws' for menu labels — compact, the standard
    vless/tcp/reality tuple is omitted (it is the common case)."""
    parts = []
    ms = ping_ms(name)
    if ms is not None:
        parts.append(f"{ms:.0f} ms")
    params = server_params(name)
    if params:
        proto = (params["protocol"], params["network"], params["security"])
        if proto != ("vless", "tcp", "reality"):
            parts.append("/".join(p for p in proto if p))
    return " · ".join(parts)
