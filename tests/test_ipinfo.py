import json
import time

import ipinfo


def test_flag_emoji():
    assert ipinfo.flag_emoji("DE") == "🇩🇪"
    assert ipinfo.flag_emoji("us") == "🇺🇸"
    assert ipinfo.flag_emoji(None) == ""
    assert ipinfo.flag_emoji("D") == ""


def test_is_fresh():
    now = time.time()
    assert ipinfo.is_fresh({"fetched_at": now, "connection": "a"}, "a", 600)
    assert not ipinfo.is_fresh({"fetched_at": now - 700, "connection": "a"}, "a", 600)
    assert not ipinfo.is_fresh({"fetched_at": now, "connection": "a"}, "b", 600)
    assert not ipinfo.is_fresh({"fetched_at": now, "connection": "a", "error": "x"}, "a", 600)
    assert not ipinfo.is_fresh(None, "a", 600)


def test_status_line(tmp_path, monkeypatch):
    p = tmp_path / "cache.json"
    monkeypatch.setattr(ipinfo, "CACHE_PATH", p)
    assert ipinfo.status_line("a", 600) is None
    entry = {"connection": "a", "fetched_at": time.time(), "ip": "1.2.3.4", "country_code": "DE"}
    p.write_text(json.dumps(entry))
    assert ipinfo.status_line("a", 600) == "Exit: 1.2.3.4 🇩🇪"
    assert ipinfo.status_line("b", 600) is None


def test_update_caches_and_throttles(tmp_path, monkeypatch):
    p = tmp_path / "cache.json"
    monkeypatch.setattr(ipinfo, "CACHE_PATH", p)
    monkeypatch.setattr(ipinfo, "_fetch", lambda: {"ip": "9.9.9.9", "country_code": "FI"})
    ipinfo.update("conn")
    assert json.loads(p.read_text())["ip"] == "9.9.9.9"

    def boom():
        raise AssertionError("second update within throttle window must not re-fetch")

    monkeypatch.setattr(ipinfo, "_fetch", boom)
    ipinfo.update("conn")


def test_update_failure_cached(tmp_path, monkeypatch):
    p = tmp_path / "cache.json"
    monkeypatch.setattr(ipinfo, "CACHE_PATH", p)

    def fail():
        raise OSError("no route")

    monkeypatch.setattr(ipinfo, "_fetch", fail)
    ipinfo.update("conn")
    entry = json.loads(p.read_text())
    assert entry["error"] == "no route"
    assert ipinfo.status_line("conn", 600) is None
