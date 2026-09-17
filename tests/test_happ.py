import json

from providers import happ


def test_captured_config_exact_and_fuzzy(tmp_path, monkeypatch):
    configs = {
        "🇩🇪⭐Germany 4⭐ - Gemini 🤖": {"remarks": "g4", "inbounds": []},
        "🇪🇪⭐Estonia🎮": {"remarks": "ee"},
    }
    capture = tmp_path / "xray-configs.json"
    capture.write_text(json.dumps(configs))
    monkeypatch.setattr(happ, "CAPTURED_CONFIGS", capture)

    # exact (with flag prefix)
    assert (
        happ._captured_config("🇩🇪⭐Germany 4⭐ - Gemini 🤖")
        == configs["🇩🇪⭐Germany 4⭐ - Gemini 🤖"]
    )
    # fuzzy: GUI remembers the name without the flag prefix
    assert (
        happ._captured_config("⭐Germany 4⭐ - Gemini 🤖") == configs["🇩🇪⭐Germany 4⭐ - Gemini 🤖"]
    )
    assert happ._captured_config("Estonia") == configs["🇪🇪⭐Estonia🎮"]
    # misses
    assert happ._captured_config("France") is None
    assert happ._captured_config(None) is None


def test_captured_config_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(happ, "CAPTURED_CONFIGS", tmp_path / "nope.json")
    assert happ._captured_config("anything") is None


def test_tun_interface_name():
    cfg = {
        "inbounds": [
            {"protocol": "socks", "settings": {}},
            {"protocol": "tun", "settings": {"name": "happ-xray"}},
        ]
    }
    assert happ._tun_interface_name(cfg) == "happ-xray"
    assert happ._tun_interface_name({"inbounds": [{"protocol": "socks"}]}) is None


def _patch_happ_state(monkeypatch, tmp_path, captured, interfaces, processes, last, keeper_status):
    capture = tmp_path / "capture.json"
    capture.write_text(json.dumps(captured))
    monkeypatch.setattr(happ, "CAPTURED_CONFIGS", capture)
    monkeypatch.setattr(happ, "_happ_interfaces", lambda: interfaces)
    monkeypatch.setattr(happ, "_daemon_running_processes", lambda: processes)
    monkeypatch.setattr(happ, "_last_server_name", lambda: last)
    state = tmp_path / "keeper.json"
    if keeper_status is not None:
        state.write_text(json.dumps(keeper_status))
    monkeypatch.setattr(happ, "KEEPER_STATE", state)


def test_connections_lists_captured_servers(tmp_path, monkeypatch):
    captured = {
        "🇩🇪 Germany 1": {"remarks": "g1"},
        "🇪🇪 Estonia": {"remarks": "ee"},
    }
    _patch_happ_state(monkeypatch, tmp_path, captured, [], [], "🇫🇮 Finland", None)
    conns = happ.HappProvider().connections()
    names = [c.name for c in conns]
    assert names == ["🇩🇪 Germany 1", "🇪🇪 Estonia", "🇫🇮 Finland"]  # last server appended
    assert not any(c.active for c in conns)


def test_connections_marks_active_from_keeper(tmp_path, monkeypatch):
    captured = {
        "🇩🇪 Germany 1": {"remarks": "g1"},
        "🇩🇪 Germany 4": {"remarks": "g4"},
    }
    keeper = {"status": "connected", "server": "🇩🇪 Germany 4"}
    _patch_happ_state(
        monkeypatch, tmp_path, captured, ["happ-xray"], ["xray-core"], "🇩🇪 Germany 1", keeper
    )
    conns = happ.HappProvider().connections()
    active = [c.name for c in conns if c.active]
    assert active == ["🇩🇪 Germany 4"]
    assert conns[1].interface == "happ-xray"


def test_connections_no_capture_falls_back_to_last(tmp_path, monkeypatch):
    _patch_happ_state(monkeypatch, tmp_path, {}, [], [], "⭐Germany 9⭐", None)
    conns = happ.HappProvider().connections()
    assert len(conns) == 1 and conns[0].name == "⭐Germany 9⭐" and not conns[0].active
