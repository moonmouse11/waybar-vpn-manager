import email.message
import hashlib
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


def _added_providers(tmp_path, monkeypatch, log_text):
    log = tmp_path / "subscription_log.txt"
    log.write_text(log_text)
    routing = tmp_path / "routing.json"
    routing.write_text(json.dumps({"routings": []}))
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "ROUTING_FILE", routing)
    return happmeta._parse_providers()


def test_parse_providers_added_subscription(tmp_path, monkeypatch):
    """Newly added subscriptions log `Subscription being added: <url>` with no
    id line — they must appear with a stable synthesized id and resolved name."""
    log_text = (
        "[20.09.2026 02:15:22] Subscription being added: "
        "https://shop.wirecat.link/cart/TOKEN\n"
        "[20.09.2026 02:15:22] [UPDATE][INFO] "
        "WireCat fetching subscription from shop.wirecat.link\n"
    )
    providers = _added_providers(tmp_path, monkeypatch, log_text)
    (sub_id,) = [i for i, p in providers.items() if "wirecat" in p["url"]]
    assert sub_id == "h" + hashlib.sha1(
        b"https://shop.wirecat.link/cart/TOKEN"
    ).hexdigest()[:10]
    assert providers[sub_id] == {
        "name": "WireCat",
        "url": "https://shop.wirecat.link/cart/TOKEN",
    }
    # deterministic across runs/parses (on-disk cache stays valid)
    assert _added_providers(tmp_path, monkeypatch, log_text) == providers


def test_parse_providers_added_url_dedupes_real_id(tmp_path, monkeypatch):
    """A url with both a real id line and a `being added` line yields one
    provider keyed by the real id."""
    providers = _added_providers(
        tmp_path,
        monkeypatch,
        "[20.09.2026 02:15:12] Subscription #42 starting update from: https://sub.com/123\n"
        "[20.09.2026 02:15:12] Subscription being added: https://sub.com/123\n",
    )
    assert providers == {"42": {"name": "Subscription 42", "url": "https://sub.com/123"}}


def test_parse_providers_readded_url_updates_real_id(tmp_path, monkeypatch):
    """A provider re-added with a fresh token for a host that already has a
    real id keeps the stable id and adopts the newest url — no duplicate
    provider group."""
    providers = _added_providers(
        tmp_path,
        monkeypatch,
        "[18.09.2026 01:48:27] Subscription #7 starting update from: https://a.com/t1\n"
        "[20.09.2026 02:15:22] Subscription being added: https://a.com/t2\n",
    )
    assert providers == {"7": {"name": "Subscription 7", "url": "https://a.com/t2"}}


def test_parse_providers_readded_picks_path_matching_id(tmp_path, monkeypatch):
    """Two real ids on one host + a re-added url: the id whose current url
    shares the longest path prefix adopts it — a sibling subscription on the
    same host must not swallow another's rotated token."""
    providers = _added_providers(
        tmp_path,
        monkeypatch,
        "[18.09.2026 01:00:00] Subscription #1 starting update from: https://host.com/a\n"
        "[18.09.2026 01:00:01] Subscription #2 starting update from: https://host.com/b\n"
        "[20.09.2026 02:15:22] Subscription being added: https://host.com/b2\n",
    )
    assert providers == {
        "1": {"name": "Subscription 1", "url": "https://host.com/a"},
        "2": {"name": "Subscription 2", "url": "https://host.com/b2"},
    }


def test_parse_providers_stale_added_line_ignored(tmp_path, monkeypatch):
    """An added line OLDER than the host's newest real update line is stale:
    the real url must survive and no synthesized provider appears for it."""
    providers = _added_providers(
        tmp_path,
        monkeypatch,
        "[18.09.2026 01:48:27] Subscription #7 starting update from: https://a.com/t1\n"
        "[19.09.2026 02:00:00] Subscription being added: https://a.com/t2\n"
        "[20.09.2026 02:15:12] Subscription #7 starting update from: https://a.com/t3\n",
    )
    assert providers == {"7": {"name": "Subscription 7", "url": "https://a.com/t3"}}


def test_parse_providers_added_without_name_uses_host(tmp_path, monkeypatch):
    """Added url with no matching `fetching subscription from` line: the host
    is the display name."""
    providers = _added_providers(
        tmp_path,
        monkeypatch,
        "[20.09.2026 02:18:49] Subscription being added: https://sub.kushmakers.org/new/TOK\n",
    )
    (sub_id,) = providers.keys()
    assert sub_id == "h" + hashlib.sha1(
        b"https://sub.kushmakers.org/new/TOK"
    ).hexdigest()[:10]
    assert providers[sub_id] == {
        "name": "sub.kushmakers.org",
        "url": "https://sub.kushmakers.org/new/TOK",
    }


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
    # the protocol part renders next to the ✓ availability mark
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    ping_file.write_text(json.dumps({"tr": {"ms": 42.0, "at": time.time()}}))
    suffix = happmeta.server_info_suffix("tr")
    assert suffix.startswith("✓ ")
    assert "/".join((params["protocol"], params["network"], params["security"])) in suffix


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
    assert happmeta.server_info_suffix("ee").startswith("✓ ")
    # standard vless/tcp/reality tuple is omitted; host is not shown (too long)
    assert "vless" not in happmeta.server_info_suffix("ee")
    assert "example.com" not in happmeta.server_info_suffix("ee")


def test_server_info_suffix_availability(tmp_path, monkeypatch):
    """Happ GUI metaphor: ✓ reachable, ✗ fresh failure, unmarked when unknown."""
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    now = time.time()
    ping_file.write_text(
        json.dumps(
            {
                "up": {"ms": 42.0, "at": now},
                "down": {"ms": None, "at": now},  # measured but unreachable
                "stale": {"ms": 1.0, "at": now - 9999},
            }
        )
    )
    monkeypatch.setattr(happmeta, "server_params", lambda name: None)
    assert happmeta.server_info_suffix("up") == "✓ 42 ms"
    assert happmeta.server_info_suffix("down") == "✗"
    assert happmeta.server_info_suffix("stale") == ""
    assert happmeta.server_info_suffix("absent") == ""


def test_ping_cache_expiry(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    ping_file.write_text(json.dumps({"x": {"ms": 42.0, "at": time.time() - 9999}}))
    assert happmeta.ping_ms("x") is None


def test_provider_ping_summary(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    now = time.time()
    ping_file.write_text(
        json.dumps(
            {
                "fresh10": {"ms": 10.0, "at": now},
                "fresh20": {"ms": 20.0, "at": now},
                "fresh30": {"ms": 30.0, "at": now},
                "stale": {"ms": 5.0, "at": now - 9999},
                "null_ms": {"ms": None, "at": now},  # measured but unreachable
            }
        )
    )
    # median over the three fresh pings; stale/absent/null entries don't count
    assert happmeta.provider_ping_summary(["fresh10", "fresh20", "fresh30"]) == "✓ 3/3 · ⌀20ms"
    assert happmeta.provider_ping_summary(["fresh10", "fresh20", "stale", "absent"]) == (
        "✓ 2/4 · ⌀15ms"
    )
    # a server answered with ms=None: reachable count excludes it
    assert happmeta.provider_ping_summary(["null_ms"]) is None
    # nothing fresh at all -> no suffix
    assert happmeta.provider_ping_summary(["stale", "absent"]) is None


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


def test_fetch_subscription_cache_url_revalidation(tmp_path, monkeypatch):
    """After a token rotation a fresh cache record fetched with the old url
    must be treated as stale (refetch); legacy records without "url" still
    count as fresh."""
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    headers_file = tmp_path / "headers.json"
    headers_file.write_text(json.dumps({"User-Agent": "Happ/1.0"}))
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)

    class FakeResp:
        def __init__(self, remark):
            self._remark = remark

        def read(self):
            return json.dumps(
                [{"remarks": self._remark, "outbounds": [{}]}]
            ).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    # fresh record, mismatched url -> refetch happens, new servers returned
    (tmp_path / "subscription-1.json").write_text(
        json.dumps(
            {"at": time.time(), "url": "https://x/old", "servers": [{"remarks": "old"}]}
        )
    )
    monkeypatch.setattr(
        happmeta.urllib.request, "urlopen", lambda req, timeout: FakeResp("new")
    )
    servers = happmeta.fetch_subscription("1", "https://x/new")
    assert [s["remarks"] for s in servers] == ["new"]

    # legacy record without "url" -> still fresh, no refetch (urlopen unused)
    (tmp_path / "subscription-2.json").write_text(
        json.dumps({"at": time.time(), "servers": [{"remarks": "legacy"}]})
    )
    monkeypatch.setattr(
        happmeta.urllib.request,
        "urlopen",
        lambda req, timeout: (_ for _ in ()).throw(AssertionError("refetched legacy")),
    )
    servers = happmeta.fetch_subscription("2", "https://x/new")
    assert [s["remarks"] for s in servers] == ["legacy"]


def test_fetch_subscription_keeps_info_on_headerless_refresh(tmp_path, monkeypatch):
    """A successful refresh whose panel omits the info headers must not
    delete the previously cached info."""
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    headers_file = tmp_path / "headers.json"
    headers_file.write_text(json.dumps({"User-Agent": "Happ/1.0"}))
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)

    info = {"download": 1973660012446, "total": 0, "expire": 1797232846, "title": "t"}
    (tmp_path / "subscription-1.json").write_text(
        json.dumps(
            {
                "at": time.time() - 9999,  # stale, forces refetch
                "url": "https://x/sub",
                "servers": [{"remarks": "old"}],
                "info": info,
            }
        )
    )

    class FakeResp:
        def read(self):
            return json.dumps([{"remarks": "new", "outbounds": [{}]}]).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        happmeta.urllib.request, "urlopen", lambda req, timeout: FakeResp()
    )
    happmeta.fetch_subscription("1", "https://x/sub")
    kept = happmeta.subscription_info("1")
    assert kept == info


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


# ── Panel card info (traffic / expiry / title from response headers) ──────────


class _InfoResp:
    """Fake urlopen response with real-ish headers."""

    def __init__(self, headers: email.message.Message):
        self.headers = headers

    def read(self):
        return json.dumps([{"remarks": "S", "outbounds": [{}]}]).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _patch_fetch_env(tmp_path, monkeypatch, headers):
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    headers_file = tmp_path / "headers.json"
    headers_file.write_text('{"User-Agent": "Happ/1.0"}')
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)
    monkeypatch.setattr(
        happmeta.urllib.request, "urlopen", lambda req, timeout: _InfoResp(headers)
    )


def test_fetch_subscription_stores_parsed_info(tmp_path, monkeypatch):
    """Both panel headers are captured: userinfo key=value parsed, base64
    profile-title decoded; subscription_info reads them back from cache."""
    headers = email.message.Message()
    headers["Subscription-Userinfo"] = (
        "upload=0; download=1973660012446; total=0; expire=1797232846"
    )
    headers["Profile-Title"] = "base64:b3BsVlBOX2JvdA=="
    _patch_fetch_env(tmp_path, monkeypatch, headers)

    servers = happmeta.fetch_subscription("7", "https://x/1")
    assert [s["remarks"] for s in servers] == ["S"]
    assert happmeta.subscription_info("7") == {
        "upload": 0,
        "download": 1973660012446,
        "total": 0,
        "expire": 1797232846,
        "title": "oplVPN_bot",
    }


def test_fetch_subscription_tolerates_malformed_info(tmp_path, monkeypatch):
    """Garbage values drop to None, valid siblings survive, nothing raises."""
    headers = email.message.Message()
    headers["Subscription-Userinfo"] = "upload=abc; download=5; expire;"
    _patch_fetch_env(tmp_path, monkeypatch, headers)

    happmeta.fetch_subscription("7", "https://x/1")
    info = happmeta.subscription_info("7")
    assert info["upload"] is None
    assert info["download"] == 5
    assert info["expire"] is None
    assert info["title"] is None


def test_fetch_subscription_without_info_headers(tmp_path, monkeypatch):
    """No panel headers -> no 'info' record; subscription_info -> None."""
    _patch_fetch_env(tmp_path, monkeypatch, email.message.Message())
    happmeta.fetch_subscription("7", "https://x/1")
    record = json.loads((tmp_path / "subscription-7.json").read_text())
    assert "info" not in record
    assert happmeta.subscription_info("7") is None


def test_subscription_info_absent_and_malformed(tmp_path, monkeypatch):
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    assert happmeta.subscription_info("nope") is None  # no cache file at all
    (tmp_path / "subscription-1.json").write_text(
        json.dumps({"at": 1, "servers": [], "info": "not-a-dict"})
    )
    assert happmeta.subscription_info("1") is None


def test_fmt_traffic_limit_expire():
    assert happmeta.fmt_traffic(1973660012446) == "1838 GB"
    assert happmeta.fmt_traffic(None) == "?"
    assert happmeta.fmt_traffic("garbage") == "?"
    assert happmeta.fmt_traffic(-5) == "?"  # garbage counter from a panel
    assert happmeta.fmt_traffic(2**30 // 2) == "0.5 GB"
    assert happmeta.fmt_limit(0) == "∞"  # 0 means unlimited
    assert happmeta.fmt_limit(None) == "∞"
    assert happmeta.fmt_limit(2**40) == "1024 GB"
    assert happmeta.fmt_expire(1797232846) == "14.12.2026"
    assert happmeta.fmt_expire(None) == "?"
    assert happmeta.fmt_expire(10**30) == "?"  # out of range must not raise
