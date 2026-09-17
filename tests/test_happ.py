import json

from providers import happ


def _server(name):
    return {
        "remarks": name,
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "h", "port": 1}]},
                "streamSettings": {"network": "tcp", "security": "reality"},
            },
        ],
    }


def _patch_env(monkeypatch, tmp_path, servers, interfaces, processes, last, keeper_status):
    """Stub happmeta so no network/files are touched."""
    import happmeta

    monkeypatch.setattr(happmeta, "all_servers", lambda: servers)
    monkeypatch.setattr(happmeta, "resolve_config", lambda name: _server(name) if name else None)
    monkeypatch.setattr(happ, "_happ_interfaces", lambda: interfaces)
    monkeypatch.setattr(happ, "_daemon_running_processes", lambda: processes)
    monkeypatch.setattr(happ, "_last_server_name", lambda: last)
    state = tmp_path / "keeper.json"
    if keeper_status is not None:
        state.write_text(json.dumps(keeper_status))
    monkeypatch.setattr(happ, "KEEPER_STATE", state)


def test_connections_lists_subscription_servers(tmp_path, monkeypatch):
    servers = [
        {"name": "🇦🇹 Austria", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇫🇮 Finland", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    _patch_env(monkeypatch, tmp_path, servers, [], [], None, None)
    conns = happ.HappProvider().connections()
    assert [c.name for c in conns] == ["🇦🇹 Austria", "🇫🇮 Finland"]
    assert not any(c.active for c in conns)


def test_connections_marks_active_from_keeper(tmp_path, monkeypatch):
    servers = [
        {"name": "🇩🇪 Germany 1", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇩🇪 Germany 4", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    keeper = {"status": "connected", "server": "🇩🇪 Germany 4"}
    _patch_env(monkeypatch, tmp_path, servers, ["happ-xray"], ["xray-core"], "x", keeper)
    conns = happ.HappProvider().connections()
    active = [c.name for c in conns if c.active]
    assert active == ["🇩🇪 Germany 4"]
    assert conns[1].interface == "happ-xray"


def test_connections_empty_falls_back_to_last(tmp_path, monkeypatch):
    _patch_env(monkeypatch, tmp_path, [], [], [], "⭐Germany 9⭐", None)
    conns = happ.HappProvider().connections()
    assert len(conns) == 1 and conns[0].name == "⭐Germany 9⭐"


def test_tun_interface_name():
    cfg = {
        "inbounds": [
            {"protocol": "socks", "settings": {}},
            {"protocol": "tun", "settings": {"name": "happ-xray"}},
        ]
    }
    assert happ._tun_interface_name(cfg) == "happ-xray"
    assert happ._tun_interface_name({"inbounds": [{"protocol": "socks"}]}) is None
