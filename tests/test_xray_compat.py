"""Every xray config this plugin generates must load on real upstream xray.

Happ bundles upstream xray unmodified, and an xray release that rejects our
config fails headless connect — xray 26.9.x (Happ 4.5.2) dropped outbound
"proxySettings", which build_runtime_config() used for dns-out. The
mocked unit tests can't catch that; only the real binary can.

Binaries come from XRAY_COMPAT_DIR (<dir>/<version>/xray, geo data in
<dir>/assets) — baked into the `make test-docker` image, see
Dockerfile.test. Skipped wherever none are installed (host venv, the
plain CI matrix). Runs `xray run -test` only: parses the config, never
opens a socket or a TUN device.
"""

import copy
import os
import subprocess
from pathlib import Path

import pytest

import happmeta
import providers.keys as keys
from providers import happ

XRAY_DIR = Path(os.environ.get("XRAY_COMPAT_DIR", "/opt/xray"))
ASSETS = XRAY_DIR / "assets"
VERSIONS = sorted(p.parent.name for p in XRAY_DIR.glob("*/xray"))
# Captured at import, before conftest's autouse fixtures replace
# subprocess.run (_no_real_sysctl) and subprocess.Popen
# (_no_real_reputation_subprocess) — those patches land on the shared
# `subprocess` module, so without restoring them every xray call here
# "succeeds" (run -> fake rc 0) or crashes (Popen -> None) without running.
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen

pytestmark = pytest.mark.skipif(
    not VERSIONS, reason=f"no xray binaries in {XRAY_DIR} (run `make test-docker`)"
)

UUID = "3874802c-d7fb-43e3-aeed-d4413fe444b2"
# any 32 bytes, base64url: xray only checks the Reality key's length
REALITY_PBK = "ApVuC4IK79SExa9iSKtDZUsNm6B8eXyYpPpXrjDoIAc"

# Subscription server shapes seen from real Happ providers (addresses and
# credentials are dummies). Routing references geoip/geosite like the real
# ones do, so the shared asset dir is exercised too.
_VLESS_REALITY_XHTTP = {
    "remarks": "🇩🇪 Germany",
    "outbounds": [
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": "de.example.com",
                        "port": 443,
                        "users": [{"id": UUID, "encryption": "none"}],
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "cdn.example.com",
                    "publicKey": REALITY_PBK,
                    "shortId": "ab12",
                    "fingerprint": "chrome",
                },
                "xhttpSettings": {"path": "/x", "mode": "auto"},
            },
        },
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ],
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct"},
            {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
            {"type": "field", "network": "tcp,udp", "outboundTag": "proxy"},
        ],
    },
}

_VLESS_WITH_OWN_DNS_OUTBOUND = {
    "remarks": "🇳🇱 Netherlands",
    "outbounds": [
        {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {
                "vnext": [
                    {
                        "address": "203.0.113.7",
                        "port": 8443,
                        "users": [{"id": UUID, "encryption": "none", "flow": "xtls-rprx-vision"}],
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName": "www.example.org",
                    "publicKey": REALITY_PBK,
                    "fingerprint": "firefox",
                },
            },
        },
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "freedom", "tag": "direct"},
    ],
}

_HYSTERIA_BALANCER = {
    "remarks": "DE+",
    "outbounds": [
        {
            "protocol": "hysteria",
            "tag": "DE-1",
            "settings": {"address": "198.51.100.10", "port": 36106, "version": 2},
            "streamSettings": {"network": "hysteria", "security": "tls"},
        },
        {
            "protocol": "hysteria",
            "tag": "DE-2",
            "settings": {"address": "de2.example.com", "port": 443, "version": 2},
            "streamSettings": {"network": "hysteria", "sockopt": {"tcpFastOpen": True}},
        },
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ],
    "routing": {
        "balancers": [{"tag": "auto", "selector": ["DE-1", "DE-2"]}],
        "rules": [{"balancerTag": "auto", "network": "tcp,udp", "type": "field"}],
    },
}

def _vless(tag: str, address: str, flow: str = "xtls-rprx-vision") -> dict:
    """vless+tcp+reality — the most common outbound across real subscriptions."""
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": address,
                    "port": 443,
                    "users": [{"id": UUID, "encryption": "none", "flow": flow}],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "tcpSettings": {},
            "security": "reality",
            "realitySettings": {
                "serverName": "www.example.org",
                "publicKey": REALITY_PBK,
                "shortId": "ab12",
                "fingerprint": "firefox",
            },
        },
    }


def _hysteria_masked(tag: str, address: str) -> dict:
    """hysteria2 over h3/TLS with a salamander UDP mask and QUIC tuning — the
    shape real subscriptions ship (finalmask/quicParams values are theirs)."""
    return {
        "tag": tag,
        "protocol": "hysteria",
        "settings": {"address": address, "port": 443, "version": 2},
        "streamSettings": {
            "network": "hysteria",
            "hysteriaSettings": {"version": 2, "auth": "dummy-auth"},
            "security": "tls",
            "tlsSettings": {"serverName": address, "fingerprint": "chrome", "alpn": ["h3"]},
            "finalmask": {
                "udp": [{"type": "salamander", "settings": {"password": "dummy-obfs"}}],
                "quicParams": {
                    "bbrProfile": "standard",
                    "congestion": "bbr",
                    "maxIdleTimeout": 30,
                    "keepAlivePeriod": 10,
                    "maxStreamReceiveWindow": 8388608,
                    "initStreamReceiveWindow": 8388608,
                    "maxConnectionReceiveWindow": 20971520,
                    "initConnectionReceiveWindow": 20971520,
                },
            },
        },
    }


# leastPing balancer over masked hysteria members, fed by burstObservatory
_HYSTERIA_MASKED_LEASTPING = {
    "remarks": "🇫🇮 Finland Hy2",
    "outbounds": [
        _hysteria_masked("candidate-1", "fi1.example.com"),
        _hysteria_masked("candidate-2", "fi2.example.com"),
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
    ],
    "burstObservatory": {
        "subjectSelector": ["candidate-"],
        "pingConfig": {
            "destination": "https://www.example.com/generate_204",
            "connectivity": "",
            "interval": "8s",
            "timeout": "3s",
            "sampling": 2,
        },
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "balancers": [
            {
                "tag": "AUTO",
                "selector": ["candidate-"],
                "strategy": {"type": "leastPing"},
                "fallbackTag": "candidate-1",
            }
        ],
        "rules": [
            {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"},
            {"type": "field", "inboundTag": ["socks", "http"], "balancerTag": "AUTO"},
        ],
    },
}

# Whitelist-bridge chain: an entry balancer falls back through loopback
# outbounds into per-bridge balancers (the "to-*"/"lb-to-*"/"bal-*"
# wiring is verbatim from a real subscription), observatory-driven. The
# real one writes leastPing as balancer "settings": {"type": ...}, a key
# xray silently ignores; "strategy" here so the strategy actually parses. Also
# ships its own dns-out and a *balancer* tagged "direct" next to the
# "direct" freedom outbound — both seen in the wild.
_LOOPBACK_CHAIN = {
    "remarks": "🇷🇺 Whitelist bypass",
    "outbounds": [
        _vless("candidate", "entry.example.com"),
        _vless("wl-a", "bridge-a.example.com"),
        _vless("wl-b", "bridge-b.example.com"),
        _hysteria_masked("candidate-2", "hy.example.com"),
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "block"},
        {"protocol": "dns", "tag": "dns-out"},
        {"protocol": "loopback", "tag": "to-a", "settings": {"inboundTag": "lb-to-a"}},
        {"protocol": "loopback", "tag": "to-proxy", "settings": {"inboundTag": "lb-to-proxy"}},
    ],
    "observatory": {
        "subjectSelector": ["candidate"],
        "probeUrl": "https://www.example.com/generate_204",
        "probeInterval": "5m",
        "enableConcurrency": True,
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "balancers": [
            {
                "tag": "ENTRY-PROXY",
                "selector": ["candidate"],
                "strategy": {"type": "leastPing"},
                "fallbackTag": "to-a",
            },
            {"tag": "direct", "selector": ["direct"], "fallbackTag": "to-proxy"},
            {"tag": "bal-a", "selector": ["wl-a"], "fallbackTag": "wl-b"},
        ],
        "rules": [
            {"type": "field", "network": "udp", "port": "443", "outboundTag": "block"},
            {"type": "field", "inboundTag": ["lb-to-a"], "balancerTag": "bal-a"},
            {"type": "field", "inboundTag": ["lb-to-proxy"], "balancerTag": "ENTRY-PROXY"},
            {"type": "field", "ip": ["geoip:ru"], "balancerTag": "direct"},
            {"type": "field", "inboundTag": ["http", "socks"], "balancerTag": "ENTRY-PROXY"},
        ],
    },
}

# vless+xhttp over plain TLS, packet-up with tuning "extra" — note the
# vmess-style leftovers (security/alterId/email, flow: null) some panels emit
_VLESS_XHTTP_TLS_PACKET_UP = {
    "remarks": "🇳🇱 NL xhttp",
    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": "nl.example.com",
                        "port": 443,
                        "users": [
                            {
                                "id": UUID,
                                "security": "auto",
                                "encryption": "none",
                                "email": "t@t.tt",
                                "alterId": 0,
                                "flow": None,
                            }
                        ],
                    }
                ]
            },
            "streamSettings": {
                "network": "xhttp",
                "security": "tls",
                "tlsSettings": {
                    "serverName": "nl.example.com",
                    "allowInsecure": False,
                    "fingerprint": "firefox",
                    "alpn": ["h2", "http/1.1"],
                    "show": False,
                },
                "xhttpSettings": {
                    "mode": "packet-up",
                    "path": "/xh",
                    "host": "nl.example.com",
                    "extra": {
                        "scMaxEachPostBytes": 1000000,
                        "scMaxConcurrentPosts": 100,
                        "scMinPostsIntervalMs": 30,
                        "xPaddingBytes": "100-1000",
                        "noGRPCHeader": False,
                    },
                },
            },
        },
        {"protocol": "freedom", "tag": "direct"},
    ],
}

# Not (yet) in any of the user's subscriptions — guards against a provider
# switching to them.
_VMESS_WS_TLS = {
    "remarks": "vmess ws",
    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "vmess",
            "settings": {
                "vnext": [
                    {
                        "address": "vm.example.com",
                        "port": 443,
                        "users": [{"id": UUID, "alterId": 0, "security": "auto"}],
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {"serverName": "vm.example.com"},
                "wsSettings": {"path": "/ws", "host": "vm.example.com"},
            },
        },
        {"protocol": "freedom", "tag": "direct"},
    ],
}

_TROJAN_TCP_TLS = {
    "remarks": "trojan",
    "outbounds": [
        {
            "tag": "proxy",
            "protocol": "trojan",
            "settings": {
                "servers": [{"address": "tj.example.com", "port": 443, "password": "dummy"}]
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": "tj.example.com", "alpn": ["h2", "http/1.1"]},
            },
        },
        {"protocol": "freedom", "tag": "direct"},
    ],
}

HAPP_SERVERS = {
    "vless-reality-xhttp": _VLESS_REALITY_XHTTP,
    "vless-own-dns-outbound": _VLESS_WITH_OWN_DNS_OUTBOUND,
    "hysteria-balancer": _HYSTERIA_BALANCER,
    "hysteria-masked-leastping": _HYSTERIA_MASKED_LEASTPING,
    "loopback-chain": _LOOPBACK_CHAIN,
    "vless-xhttp-tls-packet-up": _VLESS_XHTTP_TLS_PACKET_UP,
    "vmess-ws-tls": _VMESS_WS_TLS,
    "trojan-tcp-tls": _TROJAN_TCP_TLS,
}

KEY_URLS = {
    "ss-aes-256-gcm": "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#ss",
    # 2022-blake3-aes-256-gcm with a 32-byte base64 key (bytes 0..31)
    "ss-2022": (
        "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206"
        "QUFFQ0F3UUZCZ2NJQ1FvTERBME9EeEFSRWhNVUZSWVhHQmthR3h3ZEhoOD0@ss.example.com:8388#ss22"
    ),
    "vless-plain-tcp": f"vless://{UUID}@203.0.113.9:2222#plain",
    "vless-reality-grpc": (
        f"vless://{UUID}@x.example.com:443?security=reality&pbk={REALITY_PBK}&sid=ab12"
        "&sni=cdn.example.com&fp=firefox&type=grpc&serviceName=SVC#rg"
    ),
    "vless-reality-vision": (
        f"vless://{UUID}@x.example.com:443?security=reality&pbk={REALITY_PBK}"
        "&sni=cdn.example.com&fp=chrome&flow=xtls-rprx-vision#rv"
    ),
}


@pytest.fixture(params=VERSIONS)
def xray(request, monkeypatch):
    """Point happ.xray_config_error() — the keeper's own preflight — at one
    upstream release, so the test exercises the real production check."""
    binary = XRAY_DIR / request.param / "xray"
    assert os.access(binary, os.X_OK), binary
    monkeypatch.setattr(happ, "XRAY_BIN", binary)
    # real subprocess for this test only: it runs nothing but `xray run -test`
    monkeypatch.setattr(subprocess, "run", _REAL_RUN)
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)
    return request.param


def _config_error(cfg: dict) -> str | None:
    return happ.xray_config_error(cfg, ASSETS if ASSETS.is_dir() else None)


def test_harness_actually_runs_xray(xray):
    # xray_config_error() returns None when the binary can't run at all —
    # without this negative control a broken image would pass everything
    bogus = {"outbounds": [{"protocol": "no-such-protocol", "tag": "proxy"}]}
    assert _config_error(bogus)


@pytest.mark.parametrize("server", HAPP_SERVERS.values(), ids=HAPP_SERVERS.keys())
def test_happ_runtime_config_loads(xray, server):
    cfg = happmeta.build_runtime_config(copy.deepcopy(server))
    assert _config_error(cfg) is None


@pytest.mark.parametrize("url", KEY_URLS.values(), ids=KEY_URLS.keys())
def test_keys_config_loads(xray, url):
    cfg = keys._build_xray_config(keys.parse_key(url))
    assert _config_error(cfg) is None
