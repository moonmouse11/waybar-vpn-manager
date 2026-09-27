import json
import time

import reputation


def test_is_suspicious_country_ru():
    assert reputation.is_suspicious({"country_code": "RU", "domain": "example.com"})


def test_is_suspicious_domain_tld():
    assert reputation.is_suspicious({"country_code": "DE", "domain": "dhost.su"})
    assert reputation.is_suspicious({"country_code": "DE", "domain": "baxet.ru"})


def test_is_suspicious_hosting_or_proxy():
    assert reputation.is_suspicious({"country_code": "DE", "hosting": True})
    assert reputation.is_suspicious({"country_code": "FR", "proxy": True})


def test_is_suspicious_clean():
    assert not reputation.is_suspicious({"country_code": "DE", "domain": "play2go.cloud"})
    assert not reputation.is_suspicious({"country_code": "DE", "domain": None})
    assert not reputation.is_suspicious({})
    assert not reputation.is_suspicious({"country_code": "DE", "hosting": False, "proxy": False})


def test_reason_tags_order_and_combination():
    assert reputation._reason_tags({"country_code": "RU"}) == ["RU"]
    assert reputation._reason_tags({"hosting": True}) == ["DC"]
    assert reputation._reason_tags({"proxy": True}) == ["PROXY"]
    assert reputation._reason_tags(
        {"country_code": "RU", "hosting": True, "proxy": True}
    ) == ["RU", "DC", "PROXY"]
    assert reputation._reason_tags({}) == []


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
                "bad": {"at": time.time(), "suspicious": True, "tags": ["RU"]},
                "hosted": {"at": time.time(), "suspicious": True, "tags": ["DC", "PROXY"]},
                "good": {"at": time.time(), "suspicious": False, "tags": []},
            }
        )
    )
    assert reputation.mark("bad") == " ⚠RU"
    assert reputation.mark("hosted") == " ⚠DC/PROXY"
    assert reputation.mark("good") == ""


def test_write_reputations_dedupes_by_host(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    monkeypatch.setattr(reputation, "IPAPI_PACE", 0)  # don't actually sleep in tests
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
    monkeypatch.setattr(reputation, "IPAPI_PACE", 0)

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


class _Resp:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_lookup_ipapi_extracts_flags(monkeypatch):
    monkeypatch.setattr(
        reputation.urllib.request,
        "urlopen",
        lambda url, timeout=6: _Resp(
            {"status": "success", "hosting": True, "proxy": False, "mobile": False, "country": "DE"}
        ),
    )
    result = reputation._lookup_ipapi("1.2.3.4")
    assert result["hosting"] is True
    assert result["proxy"] is False


def test_lookup_ipapi_returns_empty_on_failure(monkeypatch):
    def boom(url, timeout=6):
        raise OSError("no route")

    monkeypatch.setattr(reputation.urllib.request, "urlopen", boom)
    assert reputation._lookup_ipapi("1.2.3.4") == {}


def test_lookup_merges_ipwho_and_ipapi(monkeypatch):
    monkeypatch.setattr(reputation.socket, "gethostbyname", lambda host: "1.2.3.4")

    def fake_get_json(url):
        if "ipwho" in url:
            return {
                "success": True,
                "country_code": "DE",
                "connection": {"domain": "example.com"},
            }
        return {"status": "success", "hosting": True, "proxy": False, "mobile": False}

    monkeypatch.setattr(reputation, "_get_json", fake_get_json)
    result = reputation._lookup("some.host")
    assert result["country_code"] == "DE"
    assert result["domain"] == "example.com"
    assert result["hosting"] is True


def test_lookup_self_combines_both_sources(monkeypatch):
    def fake_get_json(url):
        if "ipwho" in url:
            return {"ip": "1.2.3.4", "country": "Germany", "connection": {"org": "Acme"}}
        return {
            "status": "success",
            "country": "France",
            "isp": "Acme ISP",
            "as": "AS1 Acme",
            "hosting": True,
            "proxy": False,
            "mobile": False,
            "query": "1.2.3.4",
        }

    monkeypatch.setattr(reputation, "_get_json", fake_get_json)
    result = reputation.lookup_self()
    assert result["ip"] == "1.2.3.4"
    assert result["ipwho_country"] == "Germany"
    assert result["ipapi_country"] == "France"
    assert result["hosting"] is True


def test_lookup_self_returns_none_when_both_sources_fail(monkeypatch):
    monkeypatch.setattr(reputation, "_get_json", lambda url: None)
    assert reputation.lookup_self() is None


def test_write_reputations_paces_between_lookups(tmp_path, monkeypatch):
    """Stay under ip-api.com's free-tier rate limit during the sweep."""
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    monkeypatch.setattr(reputation, "IPAPI_PACE", 42)
    monkeypatch.setattr(reputation, "_lookup", lambda host: {"country_code": "DE"})
    slept = []
    monkeypatch.setattr(reputation.time, "sleep", lambda s: slept.append(s))
    reputation.write_reputations([("a", "host-a", 443), ("b", "host-b", 443)])
    assert slept == [42, 42]  # once per unique host looked up


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
