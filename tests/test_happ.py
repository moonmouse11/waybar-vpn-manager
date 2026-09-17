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
