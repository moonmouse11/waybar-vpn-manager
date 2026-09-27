import ipsources.base as base
from ipsources.ipapi import IpApiSource
from ipsources.ipwhois import IpWhoIsSource


class _Resp:
    def __init__(self, payload):
        self._payload = __import__("json").dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_fetch_json_happy_path(monkeypatch):
    monkeypatch.setattr(
        base.urllib.request, "urlopen", lambda req, timeout=8: _Resp({"ok": True})
    )
    assert base.fetch_json("https://example.com") == {"ok": True}


def test_fetch_json_returns_none_on_failure(monkeypatch):
    def boom(req, timeout=8):
        raise OSError("no route")

    monkeypatch.setattr(base.urllib.request, "urlopen", boom)
    assert base.fetch_json("https://example.com") is None


def test_fetch_json_passes_headers(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=8):
        captured["headers"] = req.headers
        return _Resp({"ok": True})

    monkeypatch.setattr(base.urllib.request, "urlopen", fake_urlopen)
    base.fetch_json("https://example.com", headers={"Key": "abc123"})
    # urllib.request.Request title-cases header names
    assert captured["headers"] == {"Key": "abc123"}


class _FakeKeylessSource(base.IPInfoSource):
    key = "fake"
    name = "Fake"

    def lookup(self, ip):
        return None


def test_keyless_source_enabled_by_default(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    assert _FakeKeylessSource().is_enabled() is True


def test_keyless_source_can_be_disabled(monkeypatch, tmp_path):
    import config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = config.Config()
    cfg.ip_sources["fake"] = {"enabled": False}
    config.save_config(cfg)
    assert _FakeKeylessSource().is_enabled() is False


class _FakeKeyedSource(base.IPInfoSource):
    key = "fakekeyed"
    name = "FakeKeyed"
    needs_api_key = True

    def lookup(self, ip):
        return None


def test_keyed_source_disabled_without_key(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    assert _FakeKeyedSource().is_enabled() is False


def test_keyed_source_enabled_once_key_present(monkeypatch, tmp_path):
    import config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = config.Config()
    cfg.ip_sources["fakekeyed"] = {"api_key": "secret"}
    config.save_config(cfg)
    source = _FakeKeyedSource()
    assert source.is_enabled() is True
    assert source._api_key() == "secret"


def test_ipwhois_lookup_happy_path(monkeypatch):
    monkeypatch.setattr(
        base,
        "fetch_json",
        lambda url, **kw: {
            "success": True,
            "country_code": "DE",
            "country": "Germany",
            "connection": {"org": "jogcorp", "domain": "jogcorp.org"},
        },
    )
    finding = IpWhoIsSource().lookup("1.2.3.4")
    assert finding.source == "ipwho.is"
    assert finding.ip == "1.2.3.4"
    assert finding.country_code == "DE"
    assert finding.org == "jogcorp"
    assert finding.domain == "jogcorp.org"


def test_ipwhois_lookup_returns_none_on_failure(monkeypatch):
    monkeypatch.setattr(base, "fetch_json", lambda url, **kw: None)
    assert IpWhoIsSource().lookup("1.2.3.4") is None


def test_ipwhois_lookup_returns_none_when_unsuccessful(monkeypatch):
    monkeypatch.setattr(base, "fetch_json", lambda url, **kw: {"success": False})
    assert IpWhoIsSource().lookup("1.2.3.4") is None


def test_ipapi_lookup_happy_path(monkeypatch):
    monkeypatch.setattr(
        base,
        "fetch_json",
        lambda url, **kw: {
            "status": "success",
            "countryCode": "US",
            "country": "United States",
            "isp": "Google LLC",
            "hosting": True,
            "proxy": False,
            "mobile": False,
        },
    )
    finding = IpApiSource().lookup("1.2.3.4")
    assert finding.source == "ip-api.com"
    assert finding.country_code == "US"
    assert finding.org == "Google LLC"
    assert finding.hosting is True
    assert finding.proxy is False


def test_ipapi_lookup_returns_none_when_status_not_success(monkeypatch):
    monkeypatch.setattr(base, "fetch_json", lambda url, **kw: {"status": "fail"})
    assert IpApiSource().lookup("1.2.3.4") is None
