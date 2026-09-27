import json
import time

import reputation


def test_is_suspicious_country_ru():
    assert reputation.is_suspicious({"country_code": "RU", "domain": "example.com"})


def test_is_suspicious_domain_tld():
    assert reputation.is_suspicious({"country_code": "DE", "domain": "dhost.su"})
    assert reputation.is_suspicious({"country_code": "DE", "domain": "baxet.ru"})


def test_is_suspicious_clean():
    assert not reputation.is_suspicious({"country_code": "DE", "domain": "play2go.cloud"})
    assert not reputation.is_suspicious({"country_code": "DE", "domain": None})
    assert not reputation.is_suspicious({})


def test_mark_missing_or_stale_is_silent(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    assert reputation.mark("nl") == ""

    p.write_text(
        json.dumps({"nl": {"at": time.time() - reputation.MAX_AGE - 1, "suspicious": True}})
    )
    assert reputation.mark("nl") == ""


def test_mark_fresh_suspicious_and_clean(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    p.write_text(
        json.dumps(
            {
                "bad": {"at": time.time(), "suspicious": True},
                "good": {"at": time.time(), "suspicious": False},
            }
        )
    )
    assert reputation.mark("bad") == " ⚠RU"
    assert reputation.mark("good") == ""


def test_write_reputations_dedupes_by_host(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    calls = []

    def fake_lookup(host):
        calls.append(host)
        return {"country_code": "RU", "domain": "x.ru"} if host == "bad.example" else {
            "country_code": "DE",
            "domain": "clean.example.com",
        }

    monkeypatch.setattr(reputation, "_lookup", fake_lookup)
    targets = [
        ("server-a", "bad.example", 443),
        ("server-b", "bad.example", 443),  # same host as server-a — must not re-lookup
        ("server-c", "good.example", 443),
    ]
    reputation.write_reputations(targets)

    assert calls == ["bad.example", "good.example"]  # one lookup per unique host
    data = json.loads(p.read_text())
    assert data["server-a"]["suspicious"] is True
    assert data["server-b"]["suspicious"] is True
    assert data["server-c"]["suspicious"] is False
    assert "updated_at" in data


def test_write_reputations_skips_failed_lookup_without_aborting(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)

    def fake_lookup(host):
        if host == "dead.example":
            return None
        return {"country_code": "DE", "domain": "clean.example.com"}

    monkeypatch.setattr(reputation, "_lookup", fake_lookup)
    targets = [("dead", "dead.example", 443), ("alive", "alive.example", 443)]
    reputation.write_reputations(targets)

    data = json.loads(p.read_text())
    assert "dead" not in data
    assert data["alive"]["suspicious"] is False


def test_request_update_throttles(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    p.write_text(json.dumps({"updated_at": time.time()}))

    def boom(*a, **k):
        raise AssertionError("must not spawn while cache is fresh")

    monkeypatch.setattr(reputation.subprocess, "Popen", boom)
    reputation.request_update()  # no raise


def test_request_update_spawns_when_stale(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    p.write_text(json.dumps({"updated_at": time.time() - reputation.MAX_AGE - 1}))

    calls = []
    monkeypatch.setattr(
        reputation.subprocess, "Popen", lambda cmd, **k: calls.append(cmd) or None
    )
    reputation.request_update()
    assert calls and "--update-reputation" in calls[0]
