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
    assert happmeta.protocol_label(trojan) == "trojan/ws/tls"
    assert happmeta.server_info_suffix("tr", "trojan/ws/tls") == "✓ 42 ms · trojan/ws/tls"


def test_protocol_label_variants():
    assert happmeta.protocol_label(_HYSTERIA_BALANCER) == "hysteria/tls"  # no hysteria/hysteria
    vless = {
        "outbounds": [
            {
                "protocol": "vless",
                "streamSettings": {"network": "tcp", "security": "reality"},
            }
        ]
    }
    assert happmeta.protocol_label(vless) == "vless/tcp/reality"  # the common case is shown too
    assert happmeta.protocol_label({"outbounds": [{"protocol": "freedom"}]}) == ""


def test_server_info_suffix_shows_protocol_without_ping(tmp_path, monkeypatch):
    monkeypatch.setattr(happmeta, "PING_CACHE", tmp_path / "none.json")
    assert happmeta.server_info_suffix("never-pinged", "hysteria/tls") == "hysteria/tls"


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
    assert "dns-out" in tags and "dns-direct" in tags and len(tags) == 4
    rules = cfg["routing"]["rules"]
    assert rules[0]["process"] == ["self/", "xray"]
    assert rules[-1] == {"network": "tcp,udp", "outboundTag": "proxy"}
    catch_alls = [r for r in rules if r.get("outboundTag") == "proxy" and r.get("network")]
    assert len(catch_alls) == 1
    assert any(r.get("protocol") == ["bittorrent"] for r in rules)


def test_build_runtime_config_tunnels_dns_out_through_proxy():
    """dns-in -> direct is needed to bootstrap the proxy outbound's own
    resolution, but that meant app-level DNS queries (tun-in -> dns-out ->
    dns-in -> direct) leaked out the real network. dns-out must chain its
    transport through "proxy" instead."""
    server_cfg = {
        "remarks": "test",
        "outbounds": [{"protocol": "vless", "tag": "proxy"}],
    }
    cfg = happmeta.build_runtime_config(server_cfg)
    dns_out = next(o for o in cfg["outbounds"] if o["tag"] == "dns-out")
    assert dns_out["streamSettings"]["sockopt"]["dialerProxy"] == "proxy"
    assert "proxySettings" not in dns_out  # removed in xray 26.x: refuses to start

    # a subscription that already ships its own dns outbound must also be
    # chained, not left leaking
    server_cfg2 = {
        "remarks": "test2",
        "outbounds": [
            {"protocol": "vless", "tag": "proxy"},
            {"protocol": "dns", "tag": "dns-out"},
        ],
    }
    cfg2 = happmeta.build_runtime_config(server_cfg2)
    dns_out2 = next(o for o in cfg2["outbounds"] if o["tag"] == "dns-out")
    assert dns_out2["streamSettings"]["sockopt"]["dialerProxy"] == "proxy"
    assert "proxySettings" not in dns_out2  # removed in xray 26.x: refuses to start


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


def _vless_outbound(host, port):
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port}]},
        "streamSettings": {"network": "tcp", "security": "reality"},
    }


def test_all_servers_hides_captured_dupe_at_same_address(tmp_path, monkeypatch):
    """A subscription can rename/re-decorate a server's remarks while the
    underlying server stays put — the stale capture under the OLD name must
    not appear as a spurious 'no provider' duplicate of the very same
    server, now correctly listed under its subscription. Matched by
    (host, port), not name, since renames change the name by definition."""
    sub_server = {
        "remarks": "🇩🇪 Germany 4 - Gemini",
        "outbounds": [_vless_outbound("1.2.3.4", 8443)],
    }
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "ProvA", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [sub_server])

    captured = {
        # same address as the subscription entry, old undecorated name -> hide
        "Germany 4 - Gemini": {"outbounds": [_vless_outbound("1.2.3.4", 8443)]},
        # different address entirely -> a genuinely separate server, keep
        "Some Other Live Server": {"outbounds": [_vless_outbound("5.6.7.8", 8443)]},
    }
    configs = tmp_path / "xray-configs.json"
    configs.write_text(json.dumps(captured, ensure_ascii=False))
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)

    servers = happmeta.all_servers()
    names = {s["name"] for s in servers}
    assert names == {"🇩🇪 Germany 4 - Gemini", "Some Other Live Server"}
    misc = [s for s in servers if s["provider_name"] == "Other / no provider"]
    assert [s["name"] for s in misc] == ["Some Other Live Server"]


def test_all_servers_keeps_captured_entry_with_unparseable_address(tmp_path, monkeypatch):
    """A capture whose own outbound can't be parsed must fall back to the
    name-only check rather than being silently (and wrongly) hidden."""
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "ProvA", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "fetch_subscription", lambda sub_id, url: [])
    configs = tmp_path / "xray-configs.json"
    configs.write_text(json.dumps({"Weird": {"outbounds": []}}))
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)

    servers = happmeta.all_servers()
    assert [s["name"] for s in servers] == ["Weird"]


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

    def boom(sub_id, url, force=False):
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


def _fresh_sub_cache(tmp_path, monkeypatch):
    """A younger-than-SUB_MAX_AGE cache + captured headers, urlopen recorded."""
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    (tmp_path / "subscription-1.json").write_text(
        json.dumps(
            {
                "at": time.time(),
                "url": "https://x/1",
                "servers": [{"remarks": "Cached", "outbounds": [{}]}],
            }
        )
    )
    headers_file = tmp_path / "headers.json"
    headers_file.write_text(json.dumps({"User-Agent": "Happ/1.0"}))
    monkeypatch.setattr(happmeta, "HEADERS_FILE", headers_file)

    calls = []

    class FakeResp:
        def read(self):
            return json.dumps([{"remarks": "Fetched", "outbounds": [{}]}]).encode()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        happmeta.urllib.request,
        "urlopen",
        lambda req, timeout: calls.append(req) or FakeResp(),
    )
    return calls


def test_fetch_subscription_fresh_cache_skips_network_by_default(tmp_path, monkeypatch):
    calls = _fresh_sub_cache(tmp_path, monkeypatch)
    servers = happmeta.fetch_subscription("1", "https://x/1")
    assert [s["remarks"] for s in servers] == ["Cached"]
    assert calls == []  # SUB_MAX_AGE gate respected


def test_fetch_subscription_force_refetches_fresh_cache(tmp_path, monkeypatch):
    calls = _fresh_sub_cache(tmp_path, monkeypatch)
    servers = happmeta.fetch_subscription("1", "https://x/1", force=True)
    assert [s["remarks"] for s in servers] == ["Fetched"]
    assert len(calls) == 1  # fresh cache re-fetched under the forced path


def test_update_subscriptions_threads_force_through(tmp_path, monkeypatch):
    _fake_providers(monkeypatch, tmp_path, {"1": {"name": "P", "url": "https://x/1"}})
    monkeypatch.setattr(happmeta, "SUB_CACHE_DIR", tmp_path)
    seen = []
    monkeypatch.setattr(
        happmeta,
        "fetch_subscription",
        lambda sub_id, url, force=False: seen.append(force) or [],
    )
    happmeta.update_subscriptions(force=True)
    assert seen == [True]
    seen.clear()
    happmeta.update_subscriptions()
    assert seen == [False]  # default keeps the staleness gate


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
    assert happmeta.server_info_suffix("down") == "⛔"
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


_CLASH = [
    {"name": "🇩🇪 Germany", "provider_id": "1", "provider_name": "P1", "config": {"remarks": "a"}},
    {"name": "🇩🇪 Germany", "provider_id": "2", "provider_name": "P2", "config": {"remarks": "b"}},
]


def test_match_server_picks_requested_provider_on_name_clash():
    assert happmeta.match_server("🇩🇪 Germany", _CLASH, provider_id="2") is _CLASH[1]
    assert happmeta.match_server("🇩🇪 Germany", _CLASH, provider_id="1") is _CLASH[0]


def test_match_server_without_provider_keeps_first_match():
    assert happmeta.match_server("🇩🇪 Germany", _CLASH) is _CLASH[0]


def test_match_server_unknown_provider_falls_back_to_name():
    # a subscription can vanish/re-key after connecting — still find the server
    assert happmeta.match_server("🇩🇪 Germany", _CLASH, provider_id="gone") is _CLASH[0]


def test_resolve_config_uses_requested_provider(tmp_path, monkeypatch):
    a = {"remarks": "S", "outbounds": [{"protocol": "vless", "tag": "proxy", "x": "a"}]}
    b = {"remarks": "S", "outbounds": [{"protocol": "vless", "tag": "proxy", "x": "b"}]}
    _fake_providers(
        monkeypatch,
        tmp_path,
        {"1": {"name": "P1", "url": "https://x/1"}, "2": {"name": "P2", "url": "https://x/2"}},
    )
    monkeypatch.setattr(
        happmeta, "fetch_subscription", lambda sub_id, url: [a] if sub_id == "1" else [b]
    )
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", tmp_path / "none.json")
    cfg = happmeta.resolve_config("S", provider_id="2")
    assert any(o.get("x") == "b" for o in cfg["outbounds"])


_HYSTERIA_BALANCER = {
    "remarks": "DE+",
    "outbounds": [
        {
            "protocol": "hysteria",
            "tag": "DE-1",
            "settings": {"address": "185.137.233.132", "port": 36106, "version": 2},
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


def test_outbound_target_understands_flat_settings_address():
    # hysteria (and other newer outbounds) keep address/port at settings' top level
    assert happmeta._outbound_target(_HYSTERIA_BALANCER) == ("185.137.233.132", 36106)


def test_server_endpoints_lists_every_balancer_member():
    assert happmeta.server_endpoints_of(_HYSTERIA_BALANCER) == [
        ("185.137.233.132", 36106),
        ("de2.example.com", 443),
    ]


def test_build_runtime_config_marks_only_proxy_outbounds_for_killswitch():
    cfg = happmeta.build_runtime_config(_HYSTERIA_BALANCER)
    by_tag = {o["tag"]: o for o in cfg["outbounds"]}
    mark = happmeta.KILLSWITCH_MARK
    assert by_tag["DE-1"]["streamSettings"]["sockopt"]["mark"] == mark
    # an existing sockopt keeps its other keys
    assert by_tag["DE-2"]["streamSettings"]["sockopt"] == {"tcpFastOpen": True, "mark": mark}
    # split-tunnel "direct" stays unmarked: the killswitch blocks it by design
    assert "mark" not in by_tag["direct"].get("streamSettings", {}).get("sockopt", {})
    assert "streamSettings" not in by_tag["block"]
    # bootstrapping a domain-based server address gets a marked freedom
    # outbound so the killswitch can't break it
    assert by_tag["dns-direct"]["protocol"] == "freedom"
    assert by_tag["dns-direct"]["streamSettings"]["sockopt"]["mark"] == mark
    rule = next(r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "dns-direct")
    assert rule["inboundTag"] == [happmeta.DNS_BOOTSTRAP_TAG]


def test_build_runtime_config_chains_dns_out_through_existing_proxy_tag():
    # balancer configs have no "proxy" tag — chaining through it would point
    # at nothing; use the first real proxy outbound instead
    cfg = happmeta.build_runtime_config(_HYSTERIA_BALANCER)
    dns_out = next(o for o in cfg["outbounds"] if o["tag"] == "dns-out")
    assert dns_out["streamSettings"]["sockopt"]["dialerProxy"] == "DE-1"
    assert "proxySettings" not in dns_out  # removed in xray 26.x: refuses to start


def test_subscription_targets_from_provider_urls(tmp_path, monkeypatch):
    _fake_providers(
        monkeypatch,
        tmp_path,
        {
            "1": {"name": "P1", "url": "https://sub.example.ru/u/TOKEN"},
            "2": {"name": "P2", "url": "https://sub.example.com:8443/x"},
            "3": {"name": "Captured", "url": None},
        },
    )
    assert happmeta.subscription_targets() == [
        ("P1", "sub.example.ru", 443),
        ("P2", "sub.example.com", 8443),
    ]


def _dns_rules(cfg):
    return [r for r in cfg["routing"]["rules"] if r.get("outboundTag") == "dns-direct"]


def test_app_dns_is_never_routed_direct():
    """xray's resolver used to go dns-in -> dns-direct: every app lookup
    (tun:53 -> dns-out -> built-in DNS) left via the real NIC from the real
    IP — DNS leak test showed a Russian Cloudflare node behind a DE exit.
    dns-in must fall through to the same rules as app traffic (tunnel or
    balancer); only the bootstrap tag may go direct."""
    cfg = happmeta.build_runtime_config(_HYSTERIA_BALANCER)
    assert cfg["dns"]["tag"] == "dns-in"
    assert not any("dns-in" in (r.get("inboundTag") or []) for r in cfg["routing"]["rules"])
    assert all(r["inboundTag"] == [happmeta.DNS_BOOTSTRAP_TAG] for r in _dns_rules(cfg))


def test_domain_server_addresses_bootstrap_direct_via_tagged_resolver():
    server_cfg = {
        **_HYSTERIA_BALANCER,  # DE-1 is an IP, DE-2 is de2.example.com
        "dns": {"servers": ["https://1.1.1.1/dns-query", "8.8.8.8"], "queryStrategy": "UseIPv4"},
    }
    cfg = happmeta.build_runtime_config(server_cfg)
    boot = cfg["dns"]["servers"][0]
    assert boot["tag"] == happmeta.DNS_BOOTSTRAP_TAG
    assert boot["domains"] == ["full:de2.example.com"]  # never the IP member
    assert boot["skipFallback"] is True  # other names must not fall back to it
    assert boot["address"] == "https://1.1.1.1/dns-query"  # subscription's own resolver
    assert cfg["dns"]["servers"][1:] == ["https://1.1.1.1/dns-query", "8.8.8.8"]
    assert cfg["dns"]["queryStrategy"] == "UseIPv4"
    # the bootstrap rule precedes every subscription rule
    rules = cfg["routing"]["rules"]
    assert rules.index(_dns_rules(cfg)[0]) < len(happmeta.LOCAL_ROUTING_RULES)


def test_ip_only_servers_need_no_bootstrap_resolver():
    server_cfg = {
        "remarks": "ip",
        "outbounds": [{"protocol": "hysteria", "tag": "proxy",
                       "settings": {"address": "198.51.100.1", "port": 443, "version": 2}}],
        "dns": {"servers": ["8.8.8.8"]},
    }
    cfg = happmeta.build_runtime_config(server_cfg)
    assert cfg["dns"]["servers"] == ["8.8.8.8"]


def test_bootstrap_resolver_skips_domain_restricted_and_hostname_resolvers():
    server_cfg = {
        **_HYSTERIA_BALANCER,
        "dns": {
            "servers": [
                {"address": "https://77.88.8.8/dns-query", "domains": ["regexp:.*\\.ru$"]},
                "https://dns.google/dns-query",  # needs resolving itself
                {"address": "1.0.0.1", "port": 53},
            ]
        },
    }
    boot = happmeta.build_runtime_config(server_cfg)["dns"]["servers"][0]
    assert boot["address"] == "1.0.0.1"


def test_bootstrap_resolver_falls_back_when_subscription_has_none():
    boot = happmeta.build_runtime_config(_HYSTERIA_BALANCER)["dns"]["servers"][0]
    assert boot["address"] == happmeta.DNS_BOOTSTRAP_FALLBACK
