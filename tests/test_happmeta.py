import json
import time

import happmeta


def test_parse_providers(tmp_path, monkeypatch):
    log = tmp_path / "subscription_log.txt"
    log.write_text(
        "[d] Subscription #479911144 starting update from: https://xskx.a.live/abc\n"
        "[d] [UPDATE][INFO] 🌺 ARTΞMIDA VPN fetching subscription from xskx.a.live/abc\n"
        "[d] Subscription #-1370901690 starting update from: https://sub.op.link/xyz\n"
        "[d] [UPDATE][INFO] oplVPN_bot fetching subscription from sub.op.link/xyz\n"
    )
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "ROUTING_FILE", tmp_path / "none.json")
    monkeypatch.setattr(happmeta, "PROVIDERS_CACHE", tmp_path / "cache.json")
    providers = happmeta.providers()
    assert providers["479911144"] == "🌺 ARTΞMIDA VPN"
    assert providers["-1370901690"] == "oplVPN_bot"
    # cached on second call
    assert happmeta.providers() == providers


def test_providers_fallback_to_routing_names(tmp_path, monkeypatch):
    log = tmp_path / "empty.txt"
    log.write_text("")
    routing = tmp_path / "routing.json"
    routing.write_text(json.dumps({"routings": [{"name": "MyRouting", "subscriptionId": 42}]}))
    monkeypatch.setattr(happmeta, "LOG_FILE", log)
    monkeypatch.setattr(happmeta, "ROUTING_FILE", routing)
    monkeypatch.setattr(happmeta, "PROVIDERS_CACHE", tmp_path / "cache.json")
    assert happmeta.providers() == {"42": "MyRouting"}


def test_server_params_and_ping_cache(tmp_path, monkeypatch):
    configs = tmp_path / "xray-configs.json"
    configs.write_text(
        json.dumps(
            {
                "🇪🇪 Estonia": {
                    "remarks": "ee",
                    "outbounds": [
                        {"protocol": "freedom", "tag": "direct"},
                        {
                            "protocol": "vless",
                            "settings": {"vnext": [{"address": "est.example.com", "port": 8443}]},
                            "streamSettings": {"network": "tcp", "security": "reality"},
                        },
                    ],
                }
            }
        )
    )
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)
    params = happmeta.server_params("Estonia")  # fuzzy
    assert params["host"] == "est.example.com"
    assert params["port"] == 8443
    assert params["network"] == "tcp"
    assert params["security"] == "reality"

    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    assert happmeta.ping_ms("🇪🇪 Estonia") is None
    ping_file.write_text(json.dumps({"🇪🇪 Estonia": {"ms": 42.0, "at": time.time()}}))
    assert happmeta.ping_ms("🇪🇪 Estonia") == 42.0
    assert "42 ms" in happmeta.server_info_suffix("🇪🇪 Estonia")
    assert "vless/tcp/reality" in happmeta.server_info_suffix("🇪🇪 Estonia")
    assert "est.example.com:8443" in happmeta.server_info_suffix("🇪🇪 Estonia")


def test_ping_cache_expiry(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    ping_file.write_text(json.dumps({"x": {"ms": 42.0, "at": time.time() - 999}}))
    assert happmeta.ping_ms("x") is None


def test_update_pings(tmp_path, monkeypatch):
    configs = tmp_path / "xray-configs.json"
    configs.write_text(
        json.dumps(
            {
                "srv": {
                    "outbounds": [
                        {
                            "protocol": "vless",
                            "settings": {"vnext": [{"address": "127.0.0.1", "port": 9}]},
                            "streamSettings": {},
                        }
                    ]
                }
            }
        )
    )
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "XRAY_CONFIGS", configs)
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    monkeypatch.setattr(happmeta, "measure_ping", lambda host, port: 1.5)
    happmeta.update_pings()
    data = json.loads(ping_file.read_text())
    assert data["srv"]["ms"] == 1.5
    assert "updated_at" in data
