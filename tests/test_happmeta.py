import json
import time

import happmeta


def _fake_providers(monkeypatch, tmp_path, providers):
    """providers() stubbed away from the real Happ log."""
    monkeypatch.setattr(happmeta, "PROVIDERS_CACHE", tmp_path / "prov-cache.json")
    monkeypatch.setattr(happmeta, "_parse_providers", lambda: providers)
    mtime = tmp_path / "log-marker"
    mtime.write_text("x")
    monkeypatch.setattr(happmeta, "LOG_FILE", mtime)


def test_parse_providers(tmp_path, monkeypatch):
    providers = {
        "479911144": {"name": "🌺 ARTΞMIDA VPN", "url": "https://xskx.a.live/abc"},
        "-1370901690": {"name": "oplVPN_bot", "url": None},
    }
    _fake_providers(monkeypatch, tmp_path, providers)
    assert happmeta.providers() == providers


def test_build_runtime_config_merges_like_gui():
    server_cfg = {
        "remarks": "test",
        "dns": {"servers": ["1.1.1.1"], "queryStrategy": "UseIPv4"},
        "inbounds": [{"port": 10808, "protocol": "socks"}],
        "outbounds": [
            {"protocol": "vless", "tag": "proxy"},
            {"protocol": "freedom", "tag": "direct"},
        ],
        "routing": {
            "rules": [
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
                {"network": "tcp,udp", "outboundTag": "proxy"},  # sub catch-all, must drop
            ]
        },
    }
    cfg = happmeta.build_runtime_config(server_cfg)
    assert [i["protocol"] for i in cfg["inbounds"]] == ["socks", "http", "tun"]
    assert cfg["dns"]["tag"] == "dns-in"
    tags = [o["tag"] for o in cfg["outbounds"]]
    assert "dns-out" in tags and len(tags) == 3
    rules = cfg["routing"]["rules"]
    assert rules[0]["process"] == ["self/", "xray"]
    assert rules[-1] == {"network": "tcp,udp", "outboundTag": "proxy"}
    catch_alls = [r for r in rules if r.get("outboundTag") == "proxy" and r.get("network")]
    assert len(catch_alls) == 1
    assert any(r.get("protocol") == ["bittorrent"] for r in rules)


def test_all_servers_groups_by_provider(tmp_path, monkeypatch):
    sub_server = {
        "remarks": "🇦🇹 Austria",
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "at.example.com", "port": 8443}]},
                "streamSettings": {"network": "tcp", "security": "reality"},
            }
        ],
    }
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "ProvA", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [sub_server])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    servers = happmeta.all_servers()
    assert len(servers) == 1
    assert servers[0]["provider_name"] == "ProvA"
    assert servers[0]["name"] == "🇦🇹 Austria"


def test_resolve_config_prefers_subscription(tmp_path, monkeypatch):
    sub_server = {"remarks": "S", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [sub_server])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    cfg = happmeta.resolve_config("S")
    assert cfg["inbounds"][2]["protocol"] == "tun"  # merged
    assert cfg["remarks"] == "S"


def test_resolve_config_captured_fallback(tmp_path, monkeypatch):
    captured = {"🇪🇪 Estonia": {"remarks": "ee", "inbounds": []}}
    configs = tmp_path / "xray-configs.json"
    configs.write_text(json.dumps(captured))
    _fake_providers(monkeypatch, tmp_path, {})
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)
    assert happmeta.resolve_config("Estonia") == captured["🇪🇪 Estonia"]


def test_server_params_and_ping_cache(tmp_path, monkeypatch):
    server = {
        "remarks": "ee",
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "est.example.com", "port": 8443}]},
                "streamSettings": {"network": "tcp", "security": "reality"},
            }
        ],
    }
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [server])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")

    params = happmeta.server_params("ee")
    assert params["host"] == "est.example.com"
    assert params["network"] == "tcp"

    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    assert happmeta.ping_ms("ee") is None
    ping_file.write_text(json.dumps({"ee": {"ms": 42.0, "at": time.time()}}))
    assert happmeta.ping_ms("ee") == 42.0
    assert "42 ms" in happmeta.server_info_suffix("ee")
    # standard vless/tcp/reality tuple is omitted; host is not shown (too long)
    assert "vless" not in happmeta.server_info_suffix("ee")
    assert "example.com" not in happmeta.server_info_suffix("ee")


def test_ping_cache_expiry(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    ping_file.write_text(json.dumps({"x": {"ms": 42.0, "at": time.time() - 999}}))
    assert happmeta.ping_ms("x") is None


def test_update_pings(tmp_path, monkeypatch):
    server = {
        "remarks": "srv",
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "127.0.0.1", "port": 9}]},
                "streamSettings": {},
            }
        ],
    }
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [server])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    monkeypatch.setattr(happmeta, "measure_ping", lambda host, port: 1.5)
    happmeta.update_pings()
    data = json.loads(ping_file.read_text())
    assert data["srv"]["ms"] == 1.5
    assert "updated_at" in data
