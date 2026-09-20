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

import base64
import copy
import hashlib
import json
import os
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.request
from datetime import datetime
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
SUBS_REFRESH_RETRY = 60  # seconds, avoid spawning a worker per status tick when the tunnel is down
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
    id_pos: dict[str, int] = {}  # last 'starting update from' position per id
    added_urls: list[tuple[int, str]] = []  # (position, url), log order
    url_name: dict[str, str] = {}
    try:
        text = LOG_FILE.read_text(errors="replace")
    except OSError:
        text = ""
    for m in re.finditer(r"Subscription #(-?\d+) starting update from: (\S+)", text):
        id_url[m.group(1)] = m.group(2)
        id_pos[m.group(1)] = m.start()
    # Newly added subscriptions log no id line — only this. The numeric id is
    # not available unencrypted (subs.db is AES-GCM), so synthesize a stable
    # id from the url; a later real id line for the same url always wins.
    for m in re.finditer(r"Subscription being added: (\S+)", text):
        added_urls.append((m.start(), m.group(1)))
    for m in re.finditer(r"\](?: ?\[[^\]]+\])* ?(.+?) fetching subscription from (\S+)", text):
        name = m.group(1).strip()
        if name:
            url_name[m.group(2)] = name

    def _resolve_name(url: str, fallback: str) -> str:
        name = url_name.get(url)
        if not name:
            host = re.sub(r"^https?://", "", url).split("/")[0]
            name = next((n for u, n in url_name.items() if host in u), None)
        return name or fallback

    host_ids: dict[str, list[str]] = {}
    for sub_id, url in id_url.items():
        host = re.sub(r"^https?://", "", url).split("/")[0]
        host_ids.setdefault(host, []).append(sub_id)

    def _path_prefix_len(a: str, b: str) -> int:
        """Shared prefix length of url paths (scheme+host stripped) —
        /cart/TOKEN1 vs /cart/TOKEN2 share more than /a vs /cart/... ."""
        ra = re.sub(r"^https?://[^/]+", "", a)
        rb = re.sub(r"^https?://[^/]+", "", b)
        n = 0
        for ca, cb in zip(ra, rb):
            if ca != cb:
                break
            n += 1
        return n

    synth: dict[str, str] = {}  # host -> url (last wins)
    for pos, url in added_urls:
        if url in id_url.values():
            continue
        host = re.sub(r"^https?://", "", url).split("/")[0]
        ids = host_ids.get(host)
        if ids:
            # Re-added with a fresh token for a host Happ already updates
            # under real id(s). Happ's own newest log line is ground truth:
            # an added line older than the host's latest real update line is
            # stale and must not regress (or duplicate) the provider.
            newest_real = max(id_pos[i] for i in ids)
            if pos < newest_real:
                continue
            # Path-aware pick: the id whose current url shares the longest
            # path prefix with the added url — a sibling subscription on the
            # same host must not swallow another's rotated token.
            real_id = max(ids, key=lambda i: _path_prefix_len(id_url[i], url))
            id_url[real_id] = url
            continue
        synth[host] = url

    providers: dict[str, dict] = {}
    for sub_id, url in id_url.items():
        providers[sub_id] = {"name": _resolve_name(url, f"Subscription {sub_id}"), "url": url}
    for host, url in synth.items():
        sub_id = "h" + hashlib.sha1(url.encode()).hexdigest()[:10]
        providers[sub_id] = {"name": _resolve_name(url, host), "url": url}

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


PROVIDERS_CACHE_VERSION = 2  # bump when _parse_providers learns new log shapes


def providers() -> dict[str, dict]:
    """id -> {"name", "url"}, cached by the log's mtime."""
    try:
        mtime = LOG_FILE.stat().st_mtime
    except OSError:
        mtime = 0
    try:
        cache = json.loads(PROVIDERS_CACHE.read_text())
        if cache.get("version") == PROVIDERS_CACHE_VERSION and cache.get("mtime") == mtime:
            return cache.get("providers", {})
    except (OSError, json.JSONDecodeError):
        pass
    result = _parse_providers()
    try:
        PROVIDERS_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PROVIDERS_CACHE.write_text(
            json.dumps(
                {"version": PROVIDERS_CACHE_VERSION, "mtime": mtime, "providers": result}
            )
        )
        os.chmod(PROVIDERS_CACHE, 0o600)  # subscription URLs carry access tokens
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

    # Fresh only for THIS url: after a token rotation the record may hold a
    # fresh cache fetched with the old url. Records without "url" predate
    # this scheme and are treated as matching (no mass refetch).
    if (
        isinstance(cached, dict)
        and cached.get("url", url) == url
        and time.time() - cached.get("at", 0) < SUB_MAX_AGE
    ):
        return cached.get("servers", [])

    headers = _headers()
    if headers:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
                info = _parse_sub_info(resp)  # headers only readable while open
            if isinstance(data, list) and data and isinstance(data[0], dict):
                servers = [s for s in data if s.get("outbounds")]
                record = {"at": time.time(), "url": url, "servers": servers}
                if info is not None:
                    record["info"] = info
                elif isinstance(cached, dict) and cached.get("url") == url:
                    # panel answered without headers — keep the previous info
                    if isinstance(cached.get("info"), dict):
                        record["info"] = cached["info"]
                try:
                    SUB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
                    cache_path.write_text(
                        json.dumps(record, ensure_ascii=False)
                    )
                    os.chmod(cache_path, 0o600)  # configs carry UUIDs and reality keys
                except OSError:
                    pass
                return servers
        except (OSError, ValueError):
            pass

    return cached.get("servers", []) if isinstance(cached, dict) else []


def _parse_sub_info(resp) -> dict | None:
    """Panel card info from response headers: traffic, expiry, display title.

    'Subscription-Userinfo: upload=0; download=…; total=0; expire=…'
    (total=0 means unlimited; expire is a unix epoch) and 'Profile-Title'
    (some panels base64-encode it with a 'base64:' prefix). Returns None when
    no field parsed; individual fields stay None when missing or malformed.
    """
    info: dict = {"upload": None, "download": None, "total": None, "expire": None, "title": None}
    headers = getattr(resp, "headers", None)
    if headers is None:
        return None
    raw = headers.get("Subscription-Userinfo")
    if raw:
        for part in raw.split(";"):
            key, _, val = part.strip().partition("=")
            if key in ("upload", "download", "total", "expire"):
                try:
                    info[key] = int(val)
                except ValueError:
                    pass  # tolerate malformed values, keep None
    title = headers.get("Profile-Title")
    if title:
        title = title.strip()
        if title.startswith("base64:"):
            try:
                title = base64.b64decode(title[len("base64:"):]).decode("utf-8", errors="replace")
            except (ValueError, TypeError):
                title = None
        info["title"] = title or None
    return info if any(v is not None for v in info.values()) else None


def subscription_info(sub_id: str) -> dict | None:
    """Cache-only panel info (traffic/expiry/title) for a provider's
    subscription; None when absent (older caches lack the "info" record)."""
    try:
        cached = json.loads(_sub_cache_path(sub_id).read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(cached, dict):
        return None
    info = cached.get("info")
    return info if isinstance(info, dict) else None


def fmt_traffic(bytes_: int | None) -> str:
    """1973660012446 -> '1838 GB' (Happ's GB is 2^30 bytes); None -> '?'."""
    if not isinstance(bytes_, (int, float)) or isinstance(bytes_, bool) or bytes_ < 0:
        return "?"
    gb = bytes_ / 2**30
    if gb >= 100:
        return f"{gb:.0f} GB"
    small = f"{gb:.1f}"
    return f"{small[:-2]} GB" if small.endswith(".0") else f"{small} GB"


def fmt_limit(total: int | None) -> str:
    """Traffic limit: 0 or None means unlimited."""
    if not isinstance(total, (int, float)) or isinstance(total, bool) or total == 0:
        return "∞"
    return fmt_traffic(total)


def fmt_expire(epoch: int | None) -> str:
    """1797232846 -> '14.12.2026'; None -> '?'."""
    if not isinstance(epoch, (int, float)) or isinstance(epoch, bool):
        return "?"
    try:
        return datetime.fromtimestamp(epoch).strftime("%d.%m.%Y")
    except (OverflowError, OSError, ValueError):
        return "?"


def fetch_subscription_cached(sub_id: str) -> list[dict]:
    """Cache-only read: fresh or stale servers, never touches the network.
    Used on the waybar --status path so a 3 s tick never blocks on I/O."""
    try:
        cached = json.loads(_sub_cache_path(sub_id).read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return cached.get("servers", []) if isinstance(cached, dict) else []


def _sub_cache_fresh(sub_id: str, url: str) -> bool:
    try:
        cached = json.loads(_sub_cache_path(sub_id).read_text())
        return (
            isinstance(cached, dict)
            and cached.get("url", url) == url  # legacy records without url match
            and time.time() - cached.get("at", 0) < SUB_MAX_AGE
        )
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        return False


def _subs_refresh_path() -> Path:
    return SUB_CACHE_DIR / "subs-refresh.json"


def _subs_refresh_in_progress() -> bool:
    """True while a refresh attempt started recently — running or just failed.
    Keeps the 3 s status tick from piling up --update-subs workers."""
    try:
        state = json.loads(_subs_refresh_path().read_text())
        return time.time() - state.get("at", 0) < SUBS_REFRESH_RETRY
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        return False


def _stamp_subs_refresh() -> None:
    try:
        SUB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        _subs_refresh_path().write_text(json.dumps({"at": time.time()}))
    except OSError:
        pass


def request_subscription_update() -> None:
    """Fire-and-forget background subscription refresh if any cache is stale."""
    if _subs_refresh_in_progress():
        return
    for sub_id, prov in providers().items():
        if prov.get("url") and not _sub_cache_fresh(sub_id, prov["url"]):
            try:
                subprocess.Popen(
                    [sys.executable, str(MANAGER), "--update-subs"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError:
                pass  # a spawn failure must never break --status
            return


def update_subscriptions() -> None:
    """Background entry point: refresh every subscription cache."""
    # stamped first, even when fetches fail below: single-flight for the tick
    _stamp_subs_refresh()
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if url:
            try:
                fetch_subscription(sub_id, url)
            except (OSError, AttributeError, ValueError):
                pass  # one failing provider must not stop the others


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


def all_servers(allow_fetch: bool = True) -> list[dict]:
    """[{name, provider_id, provider_name, config(subscription raw)}] —
    everything we can connect to, grouped per provider.

    With allow_fetch=False the subscription caches are read as-is (fresh or
    stale) and the network is never touched — the waybar --status path.
    """
    servers = []
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if not url:
            continue
        cfgs = fetch_subscription(sub_id, url) if allow_fetch else fetch_subscription_cached(sub_id)
        for cfg in cfgs:
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


def match_server(name: str, servers: list[dict]) -> dict | None:
    """The server a name refers to: exact match, or the unique substring
    match (GUI names from Happ.conf can lack the emoji prefix). None when
    ambiguous or missing — a prefix must never select the wrong server."""
    exact = [s for s in servers if name == s["name"]]
    if exact:
        return exact[0]
    subs = [s for s in servers if name in s["name"] or s["name"] in name]
    return subs[0] if len(subs) == 1 else None


def resolve_config(name: str) -> dict | None:
    """Runnable xray config for a server name: merged from the subscription
    when available, otherwise a captured config used as-is."""
    servers = all_servers()
    server = match_server(name, servers)
    if server is not None:
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
        # vless preferred; trojan/shadowsocks fall back to the first real
        # server outbound so every protocol keeps its ping + label info
        outbound = next(
            (o for o in cfg["outbounds"] if o.get("protocol") == "vless"),
            None,
        ) or next(
            (o for o in cfg["outbounds"] if o.get("protocol") not in ("dns", "freedom")),
            None,
        )
        if outbound is None:
            return None
        settings = outbound.get("settings", {})
        if "vnext" in settings:  # vless / vmess
            target = settings["vnext"][0]
        elif "servers" in settings:  # trojan / shadowsocks
            target = settings["servers"][0]
        else:
            return None
        stream = outbound.get("streamSettings", {})
        return {
            "host": target["address"],
            "port": target["port"],
            "protocol": outbound["protocol"],
            "network": stream.get("network", "tcp"),
            "security": stream.get("security", ""),
        }
    except (KeyError, IndexError, TypeError):
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


def provider_ping_summary(names: list[str]) -> str | None:
    """'✓ reachable/total · ⌀median ms' for a provider's servers — cache only.

    The ✓ mirrors the Happ GUI availability metaphor. reachable counts
    servers with a fresh ping (same freshness rule as ping_ms); the median
    runs over those pings. None when no server has fresh data (e.g. the
    first minutes after install)."""
    pings = _read_pings()
    now = time.time()
    fresh_ms = []
    for name in names:
        entry = pings.get(name)
        if not isinstance(entry, dict) or now - entry.get("at", 0) > PING_MAX_AGE:
            continue
        if entry.get("ms") is not None:
            fresh_ms.append(entry["ms"])
    if not fresh_ms:
        return None
    return f"✓ {len(fresh_ms)}/{len(names)} · ⌀{round(statistics.median(fresh_ms))}ms"


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
    """Background entry point: refresh the ping cache for Happ servers.
    vpn_manager's --update-ping combines these with the other providers'
    ping_targets() into a single write_pings() call (one cache writer)."""
    write_pings(ping_targets())


def ping_targets() -> list[tuple[str, str, int]]:
    """(name, host, port) for every known Happ server."""
    targets = []
    for server in all_servers():
        params = server_params(server["name"])
        if params:
            targets.append((server["name"], params["host"], params["port"]))
    return targets


def write_pings(targets: list[tuple[str, str, int]]) -> None:
    """Measure and write the ping cache (single writer, fixed format)."""
    pings: dict[str, dict] = {}
    for name, host, port in targets:
        try:
            ms = measure_ping(host, port)
        except (OSError, OverflowError, ValueError, TypeError):
            ms = None  # one bad target must not abort the whole sweep
        pings[name] = {"ms": ms, "at": time.time()}
    pings["updated_at"] = time.time()
    try:
        PING_CACHE.parent.mkdir(parents=True, exist_ok=True)
        PING_CACHE.write_text(json.dumps(pings, ensure_ascii=False))
    except OSError:
        pass


def _fresh_ping_entry(name: str) -> dict | None:
    """Fresh ping-cache entry for a server, or None when stale/absent."""
    entry = _read_pings().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > PING_MAX_AGE:
        return None
    return entry


def ping_mark(name: str) -> str:
    """'✓ 42 ms' / '✗' / '' — the Happ GUI availability metaphor for any
    connection name in the shared ping cache (Happ, WireGuard, OpenVPN)."""
    entry = _fresh_ping_entry(name)
    if entry is None:
        return ""
    if entry.get("ms") is None:
        return "✗"
    return f"✓ {entry['ms']:.0f} ms"


def server_info_suffix(name: str) -> str:
    """'✓ 42 ms · trojan/ws' for menu labels — ping_mark plus xray protocol
    info. The standard vless/tcp/reality tuple is omitted (it is the common
    case); a server never measured stays unmarked so the label does not get
    noisy."""
    mark = ping_mark(name)
    if not mark or mark == "✗":
        return mark
    parts = [mark]
    params = server_params(name)
    if params:
        proto = (params["protocol"], params["network"], params["security"])
        if proto != ("vless", "tcp", "reality"):
            parts.append("/".join(p for p in proto if p))
    return " · ".join(parts)
