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
import contextlib
import copy
import hashlib
import ipaddress
import json
import re
import socket
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

import fsutil

LOG_FILE = Path.home() / ".local/share/Happ/logs/subscription_log.txt"
ROUTING_FILE = Path.home() / ".config/Happ/routing.json"
PROVIDERS_CACHE = Path.home() / ".cache/vpn-manager/happ-providers.json"
PING_CACHE = Path.home() / ".cache/vpn-manager/happ-ping.json"
CAPTURED_PROVIDERS = Path.home() / ".config/happ-capture/xray-providers.json"
XRAY_CONFIGS = Path.home() / ".config/happ-capture/xray-configs.json"
HEADERS_FILE = Path.home() / ".config/happ-capture/headers.json"
SUB_CACHE_DIR = Path.home() / ".cache/vpn-manager"

PING_MAX_AGE = 1800  # seconds — also the sweep cadence; 5 min of TCP
# connects to every server every cycle likely tripped server-side rate
# limits (the ARTEMIDA IP ban), and menu marks tolerate 30 min of staleness
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

# SO_MARK put on xray's proxy outbounds (+ its own resolver, dns-direct);
# scripts/happ-killswitch accepts exactly this mark, so the killswitch lets
# the tunnel's own traffic out without guessing server IPs (balancers, UDP
# transports, domain addresses) — and when xray is down nothing carries it.
KILLSWITCH_MARK = 0x6B73  # "ks"
NON_PROXY_PROTOCOLS = ("freedom", "blackhole", "dns")

# xray's built-in resolver answers every app A/AAAA lookup (tun:53 ->
# dns-out -> handleIPQuery), tagged "dns-in". That tag deliberately has no
# rule of its own: lookups fall through to the same rules as app traffic
# (tunnel/balancer, or a subscription's split-tunnel "direct"). It used to
# go straight to dns-direct — every lookup left the real NIC from the real
# IP. Only the server's own hostnames may resolve outside the tunnel (the
# tunnel can't carry the lookup that finds it): a dedicated resolver entry,
# restricted to exactly those names and tagged DNS_BOOTSTRAP_TAG, goes to
# dns-direct — killswitch-marked, so blocking split-tunnel "direct" can't
# break the tunnel itself. (A DNS server's own "tag" is honoured by xray's
# routing on 26.3.27-26.9.30, verified against the real binaries.)
DNS_BOOTSTRAP_TAG = "dns-bootstrap"
DNS_BOOTSTRAP_FALLBACK = "https://1.1.1.1/dns-query"

LOCAL_ROUTING_RULES = [
    {"inboundTag": ["tun-in"], "outboundTag": "direct", "process": ["self/", "xray"]},
    {"inboundTag": [DNS_BOOTSTRAP_TAG], "outboundTag": "dns-direct"},
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
    # Atomic group around the repeated "[...]" prefix: once it has consumed
    # N bracket groups it commits to that count instead of retrying N-1,
    # N-2, ... against the trailing ".+?" when "fetching subscription from"
    # isn't found — that retry was O(n^2)-ish backtracking on a log file
    # that only grows, so a big log could stall the 3 s --status tick.
    for m in re.finditer(r"\](?>(?: ?\[[^\]]+\])*) ?(.+?) fetching subscription from (\S+)", text):
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
        for ca, cb in zip(ra, rb, strict=False):
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
    # subscription URLs carry access tokens — fsutil writes 0600
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(
            PROVIDERS_CACHE,
            {"version": PROVIDERS_CACHE_VERSION, "mtime": mtime, "providers": result},
        )
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
    # sub_id is usually a log-derived digit string or a sha1 hash (both
    # already safe), but a routing.json "subscriptionId" fallback is not
    # validated on the way in — strip anything but word chars/hyphen so a
    # crafted id (e.g. containing "../") can't escape SUB_CACHE_DIR.
    safe_id = re.sub(r"[^\w-]", "_", sub_id)
    return SUB_CACHE_DIR / f"subscription-{safe_id}.json"


def fetch_subscription(sub_id: str, url: str, force: bool = False) -> list[dict]:
    """Server configs from the provider, cached for SUB_MAX_AGE.

    Falls back to the last good cache when the fetch fails or the provider
    answers with the anti-curl stub. force=True skips the fresh-cache early
    return (the Refresh All menu action); the default keeps the SUB_MAX_AGE
    gate the --status path relies on.
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
        not force
        and isinstance(cached, dict)
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
                elif (
                    isinstance(cached, dict)
                    and cached.get("url") == url
                    and isinstance(cached.get("info"), dict)
                ):
                    # panel answered without headers — keep the previous info
                    record["info"] = cached["info"]
                # configs carry UUIDs and reality keys — fsutil writes 0600
                with contextlib.suppress(OSError):
                    fsutil.write_json_atomic(cache_path, record, ensure_ascii=False)
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
                with contextlib.suppress(ValueError):
                    info[key] = int(val)  # tolerate malformed values, keep None
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
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(_subs_refresh_path(), {"at": time.time()})


def request_subscription_update() -> None:
    """Fire-and-forget background subscription refresh if any cache is stale."""
    if _subs_refresh_in_progress():
        return
    for sub_id, prov in providers().items():
        if prov.get("url") and not _sub_cache_fresh(sub_id, prov["url"]):
            with contextlib.suppress(OSError):  # a spawn failure must never break --status
                subprocess.Popen(
                    [sys.executable, str(MANAGER), "--update-subs"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            return


def update_subscriptions(force: bool = False) -> None:
    """Background entry point: refresh every subscription cache.
    force=True (Refresh All's --update-subs-force) re-fetches even caches
    younger than SUB_MAX_AGE; the default --update-subs run keeps the gate."""
    # stamped first, even when fetches fail below: single-flight for the tick
    _stamp_subs_refresh()
    for sub_id, prov in providers().items():
        url = prov.get("url")
        if url:
            with contextlib.suppress(OSError, AttributeError, ValueError):
                # one failing provider must not stop the others
                fetch_subscription(sub_id, url, force=force)


# ── Config merge (subscription config -> runnable xray config) ────────────────


def build_runtime_config(server_cfg: dict, tunnel_dns: bool = True) -> dict:
    """Merge a subscription server config like the Happ GUI does:
    local inbounds, dns-in tag, dns-out outbound, local routing rules,
    drop the subscription's own catch-all (we append our own).

    tunnel_dns (config.json "dns_mode": "tunnel"): pin dns-in to the
    subscription's own catch-all, ahead of its rules — otherwise a rule like
    ARTΞMIDA's {"ip": ["1.1.1.1", ...], "ruleTag": "DNS_DIRECT",
    "outboundTag": "direct"} sends every lookup out the real NIC. Costs the
    provider's split DNS (e.g. Yandex for .ru via geoip:ru) — it then
    resolves through the tunnel too; the traffic itself still splits."""
    cfg = copy.deepcopy(server_cfg)
    cfg["inbounds"] = copy.deepcopy(DEFAULT_INBOUNDS)

    dns = cfg.get("dns") or {}
    dns["tag"] = "dns-in"
    hosts = [h for h, _port in server_endpoints_of(server_cfg) if not _is_ip(h)]
    if hosts:
        bootstrap = {
            "address": _bootstrap_resolver(dns.get("servers") or []),
            "domains": [f"full:{h}" for h in hosts],
            "skipFallback": True,  # nothing else may fall back onto it
            "tag": DNS_BOOTSTRAP_TAG,
        }
        dns["servers"] = [bootstrap, *(dns.get("servers") or [])]
    cfg["dns"] = dns

    outbounds = cfg.get("outbounds") or []
    proxies = [o for o in outbounds if o.get("protocol") not in NON_PROXY_PROTOCOLS]
    for outbound in proxies:
        _set_mark(outbound)
    outbounds.append(_set_mark({"protocol": "freedom", "tag": "dns-direct"}))
    dns_outbound = next((o for o in outbounds if o.get("protocol") == "dns"), None)
    if dns_outbound is None:
        dns_outbound = {"protocol": "dns", "tag": "dns-out"}
        outbounds.append(dns_outbound)
    # Only covers what dns-out forwards itself: non-A/AAAA queries, which
    # xray rejects by default (nonIPQuery) — A/AAAA go to the built-in
    # resolver, routed via "dns-in" (see DNS_BOOTSTRAP_TAG). Kept so a
    # subscription that enables nonIPQuery forwarding still tunnels it.
    # Balancer configs have no "proxy" tag — chain through their first real
    # proxy outbound rather than a tag that resolves to nothing.
    # sockopt.dialerProxy, not the old proxySettings.transportLayer: xray
    # 26.x (Happ 4.5.2) refuses to start on any outbound with proxySettings.
    tags = [o.get("tag") for o in proxies if o.get("tag")]
    if tags:
        via = "proxy" if "proxy" in tags else tags[0]
        sockopt = dns_outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
        sockopt.setdefault("dialerProxy", via)
    cfg["outbounds"] = outbounds

    rules = list(cfg.get("routing", {}).get("rules", []))
    rules = [
        r for r in rules if not (r.get("outboundTag") == "proxy" and r.get("network") == "tcp,udp")
    ]
    dns_rules = []
    if tunnel_dns:
        dns_rules = [{"inboundTag": ["dns-in"], **_tunnel_target(rules, outbounds)}]
    cfg.setdefault("routing", {})["rules"] = [
        *LOCAL_ROUTING_RULES,
        *dns_rules,
        *rules,
        CATCH_ALL_RULE,
    ]
    cfg["log"] = {"loglevel": "info"}
    return cfg


_CATCH_ALL_KEYS = {"type", "network", "ruleTag", "outboundTag", "balancerTag"}
_TARGET_KEYS = ("balancerTag", "outboundTag")


def _tunnel_target(rules: list[dict], outbounds: list[dict]) -> dict:
    """Where app traffic goes by default: the subscription's last pure
    catch-all rule (no matchers but network — an inboundTag-restricted one
    like {"inboundTag": ["socks", "http"]} never sees dns-in/tun-in), else
    our CATCH_ALL_RULE. Never a freedom outbound: a direct-by-default
    (whitelist-style) subscription would take DNS out the real NIC with
    it — the first real proxy outbound carries DNS instead."""
    target = {"outboundTag": CATCH_ALL_RULE["outboundTag"]}
    for rule in rules:
        if set(rule) <= _CATCH_ALL_KEYS and any(k in rule for k in _TARGET_KEYS):
            target = {k: rule[k] for k in _TARGET_KEYS if k in rule}
    freedom = {o.get("tag") for o in outbounds if o.get("protocol") == "freedom"}
    if target.get("outboundTag") in freedom:
        proxy = next(
            (o["tag"] for o in outbounds
             if o.get("tag") and o.get("protocol") not in NON_PROXY_PROTOCOLS),
            None,
        )
        if proxy:
            return {"outboundTag": proxy}
    return target


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _bootstrap_resolver(servers: list) -> str:
    """The subscription's first resolver usable for bootstrap: unrestricted
    (no "domains" list — those answer only their own names) and addressed
    by IP, plain or DoH (a hostname resolver would itself need a lookup
    before the tunnel exists). Otherwise DNS_BOOTSTRAP_FALLBACK."""
    for server in servers:
        if isinstance(server, dict):
            if server.get("domains"):
                continue
            address = server.get("address")
        else:
            address = server
        if not isinstance(address, str):
            continue
        host = urllib.parse.urlsplit(address).hostname if "://" in address else address
        if host and _is_ip(host):
            return address
    return DNS_BOOTSTRAP_FALLBACK


def _set_mark(outbound: dict) -> dict:
    sockopt = outbound.setdefault("streamSettings", {}).setdefault("sockopt", {})
    sockopt["mark"] = KILLSWITCH_MARK
    return outbound


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
    # Captured servers missing from every subscription (e.g. old captures).
    # Matched by address (host, port), not name: a subscription can rename
    # or rotate a server onto a new address under the same display name,
    # which would otherwise leave the old capture looking like a distinct,
    # provider-less duplicate of a server that's actually still around
    # (see CLAUDE.md's "Other / no provider" notes) — a capture whose
    # own address can't be parsed falls back to the name-only check so it
    # is never wrongly hidden.
    known_names = {s["name"] for s in servers}
    known_targets = {
        target for s in servers if (target := _outbound_target(s["config"])) is not None
    }
    for name, cfg in _configs().items():
        if name in known_names:
            continue
        target = _outbound_target(cfg)
        if target is not None and target in known_targets:
            continue
        servers.append(
            {
                "name": name,
                "provider_id": "",
                "provider_name": "Other / no provider",
                "config": cfg,
            }
        )
    return servers


def match_server(name: str, servers: list[dict], provider_id: str | None = None) -> dict | None:
    """The server a name refers to: exact match, or the unique substring
    match (GUI names from Happ.conf can lack the emoji prefix). None when
    ambiguous or missing — a prefix must never select the wrong server.

    Names are only unique within one subscription, so a known provider_id
    narrows the search to that subscription first; when it has no such
    server (subscription removed or re-keyed since) the name alone decides,
    as before."""
    if provider_id:
        own = [s for s in servers if s["provider_id"] == provider_id]
        if own and (found := match_server(name, own)) is not None:
            return found
    exact = [s for s in servers if name == s["name"]]
    if exact:
        return exact[0]
    subs = [s for s in servers if name in s["name"] or s["name"] in name]
    return subs[0] if len(subs) == 1 else None


def resolve_config(
    name: str,
    allow_fetch: bool = True,
    provider_id: str | None = None,
    tunnel_dns: bool = True,
) -> dict | None:
    """Runnable xray config for a server name: merged from the subscription
    when available, otherwise a captured config used as-is."""
    servers = all_servers(allow_fetch=allow_fetch)
    server = match_server(name, servers, provider_id)
    if server is not None:
        if server["provider_id"]:
            return build_runtime_config(server["config"], tunnel_dns=tunnel_dns)
        return server["config"]  # captured fallback
    return _configs().get(name)


# ── Server params / labels ────────────────────────────────────────────────────


def _real_outbound(cfg: dict) -> dict | None:
    """The server outbound (vless preferred; trojan/shadowsocks fall back to
    the first non-dns/freedom outbound), or None."""
    outbounds = cfg.get("outbounds") or []
    return next((o for o in outbounds if o.get("protocol") == "vless"), None) or next(
        (o for o in outbounds if o.get("protocol") not in NON_PROXY_PROTOCOLS), None
    )


def _outbound_target(cfg: dict) -> tuple[str, int] | None:
    """(host, port) of a raw xray config's real server outbound, or None —
    the address identity that actually distinguishes one server from
    another, independent of its display name (see all_servers())."""
    outbound = _real_outbound(cfg)
    if outbound is None:
        return None
    try:
        settings = outbound.get("settings", {})
        if "vnext" in settings:  # vless / vmess
            target = settings["vnext"][0]
        elif "servers" in settings:  # trojan / shadowsocks
            target = settings["servers"][0]
        elif "address" in settings:  # hysteria and other flat-settings outbounds
            target = settings
        else:
            return None
        return (target["address"], target["port"])
    except (KeyError, IndexError, TypeError):
        return None


def subscription_targets() -> list[tuple[str, str, int]]:
    """(provider name, host, port) of every subscription URL — the killswitch
    must let these through: the plugin fetches subscriptions through xray,
    and Happ's routing often sends a Russian-hosted subscription host
    `direct`, which the killswitch otherwise blocks (subscriptions then
    can't refresh, and a cleared cache leaves the Happ menu empty)."""
    targets = []
    for prov in providers().values():
        url = urllib.parse.urlsplit(prov.get("url") or "")
        if url.hostname:
            targets.append((prov["name"], url.hostname, url.port or 443))
    return targets


def server_endpoints_of(cfg: dict) -> list[tuple[str, int]]:
    """(host, port) of EVERY proxy outbound — a balancer config fans out
    over several servers and xray may dial any of them, so a killswitch
    whitelist built from _outbound_target()'s first match alone would cut
    the tunnel the moment the balancer picks another member."""
    endpoints = []
    for outbound in cfg.get("outbounds") or []:
        if outbound.get("protocol") in NON_PROXY_PROTOCOLS:
            continue
        target = _outbound_target({"outbounds": [outbound]})
        if target is not None and target not in endpoints:
            endpoints.append(target)
    return endpoints


def server_endpoints(
    name: str, allow_fetch: bool = True, provider_id: str | None = None
) -> list[tuple[str, int]]:
    cfg = resolve_config(name, allow_fetch=allow_fetch, provider_id=provider_id)
    return server_endpoints_of(cfg) if cfg else []


def server_params(
    name: str, allow_fetch: bool = True, provider_id: str | None = None
) -> dict | None:
    """{host, port, protocol, network, security} for a server."""
    cfg = resolve_config(name, allow_fetch=allow_fetch, provider_id=provider_id)
    if not cfg:
        return None
    outbound = _real_outbound(cfg)
    if outbound is None:
        return None
    target = _outbound_target(cfg)
    if target is None:
        return None
    stream = outbound.get("streamSettings", {})
    try:
        return {
            "host": target[0],
            "port": target[1],
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
    with contextlib.suppress(OSError):
        fsutil.write_json_atomic(PING_CACHE, pings, ensure_ascii=False)


def _fresh_ping_entry(name: str) -> dict | None:
    """Fresh ping-cache entry for a server, or None when stale/absent."""
    entry = _read_pings().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > PING_MAX_AGE:
        return None
    return entry


def ping_mark(name: str) -> str:
    """'✓ 42 ms' / '⛔' / '' — the Happ GUI availability metaphor for any
    connection name in the shared ping cache (Happ, WireGuard, OpenVPN)."""
    entry = _fresh_ping_entry(name)
    if entry is None:
        return ""
    if entry.get("ms") is None:
        return "⛔"
    return f"✓ {entry['ms']:.0f} ms"


def protocol_label(cfg: dict) -> str:
    """'vless/tcp/reality', 'hysteria/tls', 'trojan/ws/tls' — the server
    outbound's protocol/transport/security, '' when there is none. A
    transport that just repeats the protocol name (hysteria) is dropped."""
    outbound = _real_outbound(cfg)
    if outbound is None or not outbound.get("protocol"):
        return ""
    stream = outbound.get("streamSettings") or {}
    protocol = outbound["protocol"]
    network = stream.get("network", "tcp")
    parts = [protocol, "" if network == protocol else network, stream.get("security", "")]
    return "/".join(p for p in parts if p)


def server_info_suffix(name: str, protocol: str = "") -> str:
    """'✓ 42 ms · vless/tcp/reality' for menu labels — ping_mark plus the
    protocol (precomputed by the caller via protocol_label() from configs it
    already holds: resolving per server here would re-read every
    subscription cache per row and could fetch a stale one synchronously)."""
    return " · ".join(p for p in (ping_mark(name), protocol) if p)
