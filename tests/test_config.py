import config
from config import Config, load_config, save_config


def test_defaults_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = load_config()
    assert cfg.killswitch_mode == "off"
    assert cfg.exit_ip_enabled is True
    assert cfg.exit_ip_max_age == 600
    assert cfg.provider_visible("Anything")


def test_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = Config(providers={"outline": False}, killswitch_mode="happ")
    save_config(cfg)
    loaded = load_config()
    assert loaded.providers == {"outline": False}
    assert loaded.killswitch_mode == "happ"


def test_invalid_json_ignored(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text("{not json")
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().killswitch_mode == "off"


def test_partial_and_type_safety(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"killswitch_mode": "nonsense", "exit_ip": {"max_age_seconds": 5, "enabled": 0}}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.killswitch_mode == "off"  # invalid value ignored
    assert cfg.exit_ip_max_age == 60  # clamped to minimum
    assert cfg.exit_ip_enabled is False


def test_show_empty_providers_roundtrip(tmp_path, monkeypatch):
    from config import Config, load_config, save_config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().show_empty_providers is False  # default: hidden

    cfg = Config()
    cfg.show_empty_providers = True
    save_config(cfg)
    assert load_config().show_empty_providers is True


def test_happ_gui_fallback_roundtrip(tmp_path, monkeypatch):
    from config import Config, load_config, save_config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    assert load_config().happ_gui_fallback is False  # default: no GUI window

    cfg = Config()
    cfg.happ_gui_fallback = True
    save_config(cfg)
    assert load_config().happ_gui_fallback is True
