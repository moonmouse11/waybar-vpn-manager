import json
import time

import config
import reputation
from ipsources.base import IPFinding


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
    monkeypatch.setattr(reputation.subprocess, "Popen", lambda cmd, **k: calls.append(cmd))
    reputation.request_update()
    assert calls and "--update-reputation" in calls[0]


def test_combined_tags_unions_across_findings():
    findings = [
        IPFinding(source="A", country_code="DE"),
        IPFinding(source="B", country_code="RU"),
        IPFinding(source="C", hosting=True),
    ]
    assert reputation.combined_tags(findings) == ["RU", "DC"]


def test_combined_tags_empty_for_no_findings():
    assert reputation.combined_tags([]) == []


def test_is_flagged():
    assert reputation.is_flagged([IPFinding(source="A", proxy=True)])
    assert not reputation.is_flagged([IPFinding(source="A")])
    assert not reputation.is_flagged([])


class _FakeSource:
    """Stands in for an ipsources.ALL_SOURCES entry in these tests."""

    def __init__(self, name, needs_api_key=False, enabled=True, result=None, raises=False):
        self.name = name
        self.needs_api_key = needs_api_key
        self._enabled = enabled
        self._result = result
        self._raises = raises

    def is_enabled(self):
        return self._enabled

    def lookup(self, ip):
        if self._raises:
            raise RuntimeError("source blew up")
        return self._result


def test_lookup_host_resolves_once_and_queries_every_enabled_source(monkeypatch):
    resolved = []
    monkeypatch.setattr(
        reputation.socket, "gethostbyname", lambda h: resolved.append(h) or "1.2.3.4"
    )
    free = _FakeSource("Free", result=IPFinding(source="Free", ip="1.2.3.4", country_code="DE"))
    keyed = _FakeSource("Keyed", needs_api_key=True, result=IPFinding(source="Keyed", ip="1.2.3.4"))
    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [free, keyed])

    findings = reputation.lookup_host("some.host", include_keyed=True)

    assert resolved == ["some.host"]
    assert {f.source for f in findings} == {"Free", "Keyed"}


def test_lookup_host_excludes_keyed_when_asked(monkeypatch):
    monkeypatch.setattr(reputation.socket, "gethostbyname", lambda h: "1.2.3.4")
    free = _FakeSource("Free", result=IPFinding(source="Free", ip="1.2.3.4"))
    keyed = _FakeSource("Keyed", needs_api_key=True, result=IPFinding(source="Keyed", ip="1.2.3.4"))
    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [free, keyed])

    findings = reputation.lookup_host("some.host", include_keyed=False)
    assert [f.source for f in findings] == ["Free"]


def test_lookup_host_skips_disabled_sources(monkeypatch):
    monkeypatch.setattr(reputation.socket, "gethostbyname", lambda h: "1.2.3.4")
    disabled = _FakeSource("Off", enabled=False, result=IPFinding(source="Off"))
    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [disabled])
    assert reputation.lookup_host("some.host", include_keyed=True) == []


def test_lookup_host_one_bad_source_does_not_break_others(monkeypatch):
    monkeypatch.setattr(reputation.socket, "gethostbyname", lambda h: "1.2.3.4")
    ok = _FakeSource("OK", result=IPFinding(source="OK", ip="1.2.3.4"))
    bad = _FakeSource("Bad", raises=True)
    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [bad, ok])
    findings = reputation.lookup_host("some.host", include_keyed=True)
    assert [f.source for f in findings] == ["OK"]


def test_lookup_host_dns_failure_returns_empty(monkeypatch):
    def boom(h):
        raise OSError("no such host")

    monkeypatch.setattr(reputation.socket, "gethostbyname", boom)
    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [_FakeSource("X")])
    assert reputation.lookup_host("dead.host", include_keyed=True) == []


def test_lookup_self_uses_detected_ip_for_every_source(monkeypatch):
    monkeypatch.setattr(reputation, "_detect_own_ip", lambda: "9.9.9.9")
    seen_ips = []

    class Recording(_FakeSource):
        def lookup(self, ip):
            seen_ips.append(ip)
            return IPFinding(source=self.name, ip=ip)

    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [Recording("A"), Recording("B")])
    findings = reputation.lookup_self()
    assert seen_ips == ["9.9.9.9", "9.9.9.9"]
    assert len(findings) == 2


def test_lookup_self_returns_empty_when_ip_undetectable(monkeypatch):
    monkeypatch.setattr(reputation, "_detect_own_ip", lambda: None)
    assert reputation.lookup_self() == []


def test_lookup_self_bounds_total_time_when_a_source_hangs(monkeypatch):
    """A hung source must not make the interactive 'IP Info' action block
    past LOOKUP_TIMEOUT — same thread + join(timeout=...) guard as
    lookup_host() already uses."""
    monkeypatch.setattr(reputation, "_detect_own_ip", lambda: "9.9.9.9")
    monkeypatch.setattr(reputation, "LOOKUP_TIMEOUT", 0.05)

    class Slow(_FakeSource):
        def lookup(self, ip):
            time.sleep(5)
            return IPFinding(source=self.name, ip=ip)

    monkeypatch.setattr(reputation.ipsources, "ALL_SOURCES", [Slow("Slow")])
    start = time.monotonic()
    findings = reputation.lookup_self()
    elapsed = time.monotonic() - start

    assert elapsed < 1  # bounded by LOOKUP_TIMEOUT, not by the source's 5s sleep
    assert findings == []  # the hung source never got to append its finding in time


def test_detect_own_ip_primary_source(monkeypatch):
    # _detect_own_ip() now delegates to ipsources.base.fetch_json instead of
    # a private, duplicated _get_json helper.
    monkeypatch.setattr(
        reputation, "fetch_json", lambda url, timeout=6: {"success": True, "ip": "1.2.3.4"}
    )
    assert reputation._detect_own_ip() == "1.2.3.4"


def test_detect_own_ip_skips_ipwho_when_source_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = config.Config()
    cfg.ip_sources["ipwhois"] = {"enabled": False}
    config.save_config(cfg)

    calls = []

    def fake_fetch(url, timeout=6):
        calls.append(url)
        return None

    monkeypatch.setattr(reputation, "fetch_json", fake_fetch)

    class _Resp:
        def read(self):
            return b"5.6.7.8\n"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(reputation.urllib.request, "urlopen", lambda url, timeout=6: _Resp())
    assert reputation._detect_own_ip() == "5.6.7.8"
    assert reputation.IPWHO_API not in calls


def test_detect_own_ip_falls_back_on_primary_failure(monkeypatch):
    monkeypatch.setattr(reputation, "fetch_json", lambda url, timeout=6: None)

    class _Resp:
        def read(self):
            return b"5.6.7.8\n"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(reputation.urllib.request, "urlopen", lambda url, timeout=6: _Resp())
    assert reputation._detect_own_ip() == "5.6.7.8"


def test_write_reputations_dedupes_by_host(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    monkeypatch.setattr(reputation, "IPAPI_PACE", 0)
    calls = []

    def fake_lookup_host(host, include_keyed):
        calls.append((host, include_keyed))
        if host == "bad.example":
            return [IPFinding(source="X", country_code="RU", domain="x.ru")]
        return [IPFinding(source="X", country_code="DE")]

    monkeypatch.setattr(reputation, "lookup_host", fake_lookup_host)
    targets = [
        ("server-a", "bad.example", 443),
        ("server-b", "bad.example", 443),  # same host as server-a — must not re-lookup
        ("server-c", "good.example", 443),
    ]
    reputation.write_reputations(targets)

    assert calls == [("bad.example", False), ("good.example", False)]  # free sources only
    data = json.loads(p.read_text())
    assert data["server-a"]["suspicious"] is True
    assert data["server-b"]["suspicious"] is True
    assert data["server-c"]["suspicious"] is False
    assert data["server-a"]["tags"] == ["RU"]
    assert "updated_at" in data


def test_write_reputations_skips_host_with_no_findings(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    monkeypatch.setattr(reputation, "IPAPI_PACE", 0)

    def fake_lookup_host(host, include_keyed):
        return [] if host == "dead.example" else [IPFinding(source="X", country_code="DE")]

    monkeypatch.setattr(reputation, "lookup_host", fake_lookup_host)
    targets = [("dead", "dead.example", 443), ("alive", "alive.example", 443)]
    reputation.write_reputations(targets)

    data = json.loads(p.read_text())
    assert "dead" not in data
    assert data["alive"]["suspicious"] is False


def test_write_reputations_paces_between_lookups(tmp_path, monkeypatch):
    """Stay under ip-api.com's free-tier rate limit during the sweep."""
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    monkeypatch.setattr(reputation, "IPAPI_PACE", 42)
    monkeypatch.setattr(
        reputation, "lookup_host", lambda host, include_keyed: [IPFinding(source="X")]
    )
    slept = []
    monkeypatch.setattr(reputation.time, "sleep", lambda s: slept.append(s))
    reputation.write_reputations([("a", "host-a", 443), ("b", "host-b", 443)])
    assert slept == [42, 42]  # once per unique host looked up


def test_country_of_reads_cached_server_country(tmp_path, monkeypatch):
    p = tmp_path / "reputation.json"
    monkeypatch.setattr(reputation, "CACHE", p)
    assert reputation.country_of("de1") is None  # no cache yet
    p.write_text(
        json.dumps(
            {
                # stale is fine — a server's country doesn't move like its tags might
                "de1": {"at": time.time() - reputation.MAX_AGE - 1, "country_code": "de"},
                "nocc": {"at": time.time(), "country_code": None},
                "updated_at": time.time(),
            }
        )
    )
    assert reputation.country_of("de1") == "DE"
    assert reputation.country_of("nocc") is None
    assert reputation.country_of("updated_at") is None
    assert reputation.country_of("missing") is None
