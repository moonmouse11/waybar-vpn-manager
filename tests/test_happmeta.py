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


def test_parse_providers_reads_real_log(tmp_path, monkeypatch):
    """The real regexes run against a fixture log (no stubbing of the parser):
    url format, name-by-host fallback, routing.json name fallback."""
    log = tmp_path / "subscription_log.txt"
    log.write_text(
        "[05.08.2026 12:53:51] [UPDATE][INFO] "
        "Subscription #479911144 starting update from: https://xskx.a.live/abc\n"
        "[05.08.2026 12:53:52] [UPDATE][INFO] "
        "🌺 ARTΞMIDA VPN fetching subscription from xskx.a.live\n"
        "[05.08.2026 12:53:53] [UPDATE][INFO] "
        "Subscription #7 starting update from: https://sub.com/123\n"
        "[05.08.2026 12:53:54] [UPDATE][INFO] "
        "MyProv fetching subscription from sub.com\n"
    )
    routing = tmp_path / "routing.json"
    routing.write_text(
        json.dumps({"routings": [{"subscriptionId": 42, "name": "LegacyRouting"}]})
    )
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "ROUTING_FILE", routing)

    providers = happmeta._parse_providers()
    # name found via host fallback: the named url is the bare host of the url
    assert providers["479911144"] == {
        "name": "🌺 ARTΞMIDA VPN",
        "url": "https://xskx.a.live/abc",
    }
    # same host fallback, name attached later in the log
    assert providers["7"] == {"name": "MyProv", "url": "https://sub.com/123"}
    # known id without a log url: name only, from routing.json
    assert providers["42"] == {"name": "LegacyRouting", "url": None}


def test_server_params_trojan_fallback(tmp_path, monkeypatch):
    """Trojan (non-vless) servers must still get host/port for ping+labels."""
    trojan = {
        "remarks": "tr",
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {
                "protocol": "trojan",
                "settings": {"servers": [{"address": "tr.example.com", "port": 443}]},
                "streamSettings": {"network": "ws", "security": "tls"},
            },
        ],
    }
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [trojan])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")

    params = happmeta.server_params("tr")
    assert params["host"] == "tr.example.com"
    assert params["port"] == 443
    assert params["protocol"] == "trojan"
    assert params["network"] == "ws"
    assert "/".join((params["protocol"], params["network"], params["security"])) in (
        happmeta.server_info_suffix("tr")
    )


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


def test_resolve_config_exact_beats_prefix(tmp_path, monkeypatch):
    # P0 regression: "Germany" must not win over "Germany 4" by substring.
    germany = {"remarks": "Germany", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    germany4 = {"remarks": "Germany 4", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [germany, germany4])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    assert happmeta.resolve_config("Germany 4")["remarks"] == "Germany 4"
    assert happmeta.resolve_config("Germany")["remarks"] == "Germany"


def test_resolve_config_ambiguous_prefix_returns_none(tmp_path, monkeypatch):
    # An emoji-less name matching two servers is ambiguous: refuse to guess.
    g1 = {"remarks": "🇩🇪 Germany 1", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    g11 = {"remarks": "🇩🇪 Germany 11", "outbounds": [{"protocol": "vless", "tag": "proxy"}]}
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [g1, g11])
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    assert happmeta.resolve_config("Germany 1") is None


def test_resolve_config_captured_fallback(tmp_path, monkeypatch):
    captured = {"🇪🇪 Estonia": {"remarks": "ee", "inbounds": []}}
    configs = tmp_path / "xray-configs.json"
    configs.write_text(json.dumps(captured))
    _fake_providers(monkeypatch, tmp_path, {})
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)
    assert happmeta.resolve_config("Estonia") == captured["🇪🇪 Estonia"]


def test_all_servers_status_path_never_fetches(tmp_path, monkeypatch):
    sub_server = {"remarks": "S", "outbounds": [{"protocol": "vless"}]}
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})

    def boom(sub_id, url):
        raise AssertionError("status path touched the network")

    monkeypatch.setattr(happmeta, "fetch_subscription", boom)
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)

    # no cache yet: empty list, no network
    assert happmeta.all_servers(allow_fetch=False) == []
    # stale cache: served as-is, still no network
    (tmp_path / "subscription-1.json").write_text(
        json.dumps({"at": time.time() - 99999, "servers": [sub_server]})
    )
    servers = happmeta.all_servers(allow_fetch=False)
    assert [s["name"] for s in servers] == ["S"]


def test_request_subscription_update_spawns_when_stale(tmp_path, monkeypatch):
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    spawned = []
    monkeypatch.setattr(happmeta.subprocess, "Popen", lambda cmd, **kw: spawned.append(cmd))
    happmeta.request_subscription_update()  # no cache at all -> stale
    assert spawned and "--update-subs" in spawned[0]


def test_request_subscription_update_single_flight(tmp_path, monkeypatch):
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    # a refresh attempt started a moment ago (worker running or just failed)
    (tmp_path / "subs-refresh.json").write_text(json.dumps({"at": time.time()}))
    spawned = []
    monkeypatch.setattr(happmeta.subprocess, "Popen", lambda cmd, **kw: spawned.append(cmd))
    happmeta.request_subscription_update()  # stale cache, but no second spawn
    assert not spawned


def test_request_subscription_update_spawns_after_retry_window(tmp_path, monkeypatch):
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    (tmp_path / "subs-refresh.json").write_text(
        json.dumps({"at": time.time() - happmeta.SUBS_REFRESH_RETRY - 1})
    )
    spawned = []
    monkeypatch.setattr(happmeta.subprocess, "Popen", lambda cmd, **kw: spawned.append(cmd))
    happmeta.request_subscription_update()
    assert spawned and "--update-subs" in spawned[0]


def test_update_subscriptions_stamps_marker_even_on_failure(tmp_path, monkeypatch):
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)

    def boom(sub_id, url):
        raise OSError("network down")

    monkeypatch.setattr(happmeta, "fetch_subscription", boom)
    happmeta.update_subscriptions()  # must not raise, must still stamp
    state = json.loads((tmp_path / "subs-refresh.json").read_text())
    assert time.time() - state["at"] < 5
    assert happmeta._subs_refresh_in_progress()


def test_fetch_subscription_cache_is_private(tmp_path, monkeypatch):
    import os

    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    headers_file = tmp_path / "headers.json"
    headers_file.write_text(json.dumps({"User-Agent": "Happ/1.0"}))
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)

    class FakeResp:
        def read(self):
            return json.dumps([{"remarks": "S", "outbounds": [{}]}]).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(happmeta.urllib.request, "urlopen", lambda req, timeout: FakeResp())
    servers = happmeta.fetch_subscription("1", "https://x/1")
    assert [s["remarks"] for s in servers] == ["S"]
    assert (os.stat(tmp_path / "subscription-1.json").st_mode & 0o777) == 0o600


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


def test_fetch_subscription_non_dict_cache_returns_empty(tmp_path, monkeypatch):
    """A truthy non-dict JSON cache (e.g. "1") must not crash the menu path
    with AttributeError when the fetch fails and the stale-cache tail runs."""
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    cache_path = tmp_path / "subscription-1.json"
    cache_path.write_text("1")
    headers_file = tmp_path / "headers.json"
    headers_file.write_text('{"User-Agent": "Happ/1.0"}')
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)
    monkeypatch.setattr(
        happmeta.urllib.request,
        "urlopen",
        lambda req, timeout: (_ for _ in ()).throw(OSError("network down")),
    )
    assert happmeta.fetch_subscription("1", "https://x/1") == []
