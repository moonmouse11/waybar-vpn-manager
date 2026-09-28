# Pluggable IP-Intelligence Sources & Tools Menu — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn `reputation.py`'s two hardcoded IP-lookup sources into a pluggable registry (adding keyed sources like AbuseIPDB/IPQualityScore is "write one file"), fold the growing pile of diagnostic menu rows into one `🛠 Tools` submenu with four new entries, and let `config.json` (by hand or via an install-time / in-menu wizard) control which providers/tools/sources are active.

**Architecture:** New `src/ipsources/` package mirrors the existing `src/providers/` ABC+registry pattern. `src/reputation.py` stops calling `ipwho.is`/`ip-api.com` directly and becomes a thin orchestrator over `ipsources.ALL_SOURCES`. `src/config.py` gains `ip_sources`/`tools_visible` fields following its existing dataclass+load/save style. `src/vpn_manager.py` gets a `TOOLS` registry list (same shape idea) driving both the new `tools_menu()` and a shared configuration wizard (`Prompter` ABC with a terminal and a walker implementation) reachable from `--configure` (install-time) and `⚙ Settings` (in-menu).

**Tech Stack:** Python 3.13, stdlib only (`urllib.request`, `dataclasses`, `abc`, `json`, `threading`) — no new dependencies. Tests via pytest, run through `make test-docker` (network-isolated container, see `Dockerfile.test`).

**Spec:** `docs/superpowers/specs/2026-09-28-pluggable-ip-sources-and-tools-design.md`

## Global Constraints

- No new pip/pacman dependencies — every new module uses only what's already imported elsewhere in this project (`urllib.request` for HTTP, no `requests`).
- Every network call gets wrapped so a failure returns `None`/`[]`/`{}` rather than raising — one bad source/host must never abort a sweep or crash a menu action (existing project-wide convention, see `write_reputations()`'s current `except Exception` around one host).
- Every new/changed function that touches the network must be exercisable in tests via monkeypatching a *pure Python* seam (a function, not `subprocess`/`socket` directly wherever a higher-level seam already exists) — matches how `test_reputation.py` already mocks `_get_json`/`_lookup` rather than `urllib.request.urlopen` for the higher-level tests.
- Keyed sources (`needs_api_key = True`) are enabled by having a non-empty `api_key` in config — no separate `enabled` boolean for those (an "enabled but keyless" state must be impossible).
- Keyed/paid sources are used only by `ip_info_menu()`'s on-demand lookup; `write_reputations()` (the daily background sweep) must only ever pass `include_keyed=False`.
- Every `make test-docker` run must stay green after every task (run it at the end of every task, not just at the end of the plan).
- Russian-language user-facing strings (`notify(...)` messages, wizard prompts) match the existing convention already used throughout `vpn_manager.py` (e.g. `"Проверка запущена, это займёт несколько секунд…"`) — new strings follow that voice, not English.

---

## Task 1: `ipsources` package foundation — base + two free sources

**Files:**
- Create: `src/ipsources/__init__.py` (empty for now — registry added in Task 2)
- Create: `src/ipsources/base.py`
- Create: `src/ipsources/ipwhois.py`
- Create: `src/ipsources/ipapi.py`
- Test: `tests/test_ipsources.py`

**Interfaces:**
- Consumes: nothing (new package)
- Produces:
  - `ipsources.base.fetch_json(url: str, headers: dict | None = None, timeout: int = 8) -> dict | None`
  - `ipsources.base.IPFinding` (dataclass): `source: str`, `ip: str | None`, `country_code: str | None`, `country_name: str | None`, `org: str | None`, `domain: str | None`, `hosting: bool | None`, `proxy: bool | None`, `mobile: bool | None`, `abuse_score: int | None`, `raw: dict`
  - `ipsources.base.IPInfoSource` (ABC): class attrs `key: str`, `name: str`, `needs_api_key: bool = False`; methods `_api_key(self) -> str | None`, `is_enabled(self) -> bool`; abstract `lookup(self, ip: str) -> IPFinding | None`
  - `ipsources.ipwhois.IpWhoIsSource` (`key="ipwhois"`, `name="ipwho.is"`)
  - `ipsources.ipapi.IpApiSource` (`key="ipapi"`, `name="ip-api.com"`)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ipsources.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker` (or, faster while iterating: `cd /repo && python3 -m pytest tests/test_ipsources.py -v` inside the container — `make test-docker-build` once first if the image is stale)
Expected: FAIL — `ModuleNotFoundError: No module named 'ipsources'`

- [ ] **Step 3: Write the implementation**

```python
# src/ipsources/__init__.py
```
(empty — Task 2 adds `ALL_SOURCES` here)

```python
# src/ipsources/base.py
"""IPInfoSource ABC + IPFinding — one interface, multiple IP-intelligence
backends, mirroring providers/base.py's VPNProvider ABC + ALL_PROVIDERS
registry (providers/__init__.py) for the VPN-backend side of this project.
"""

import json
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import config


def fetch_json(url: str, headers: dict | None = None, timeout: int = 8) -> dict | None:
    """GET url, parse JSON, or None on any failure (network, bad JSON,
    non-2xx). Shared by every concrete source so each one's lookup() stays
    a plain "build a URL, read the response" function."""
    try:
        req = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (OSError, ValueError):
        return None


@dataclass
class IPFinding:
    source: str  # display name, e.g. "AbuseIPDB"
    ip: str | None = None  # the address this finding is actually about
    country_code: str | None = None
    country_name: str | None = None
    org: str | None = None
    domain: str | None = None  # ASN-owner domain, when the source has one
    hosting: bool | None = None
    proxy: bool | None = None
    mobile: bool | None = None
    abuse_score: int | None = None  # 0-100, AbuseIPDB-style; others leave None
    raw: dict = field(default_factory=dict)  # source-specific extras, display only


class IPInfoSource(ABC):
    key: str  # config key, e.g. "abuseipdb"
    name: str  # display name, e.g. "AbuseIPDB"
    needs_api_key: bool = False

    def _api_key(self) -> str | None:
        return config.load_config().ip_sources.get(self.key, {}).get("api_key")

    def is_enabled(self) -> bool:
        """A keyed source is enabled by having a non-empty api_key (no
        separate on/off flag — "enabled but keyless" can't happen and
        needs no toggle); a keyless source defaults to enabled, opt-out
        via config."""
        if self.needs_api_key:
            return bool(self._api_key())
        src_cfg = config.load_config().ip_sources.get(self.key, {})
        return bool(src_cfg.get("enabled", True))

    @abstractmethod
    def lookup(self, ip: str) -> IPFinding | None:
        """None on any failure (network, bad key, rate limit) — one
        source failing must never break the others."""
        ...
```

```python
# src/ipsources/ipwhois.py
"""Free, keyless — country + ASN-owner domain. No rate limit documented,
kept as the primary source for RU-registration detection (domain TLD
checks live in reputation.py's _reason_tags)."""

from ipsources import base


class IpWhoIsSource(base.IPInfoSource):
    key = "ipwhois"
    name = "ipwho.is"

    def lookup(self, ip: str) -> base.IPFinding | None:
        data = base.fetch_json(f"https://ipwho.is/{ip}")
        if not data or not data.get("success"):
            return None
        conn = data.get("connection") or {}
        return base.IPFinding(
            source=self.name,
            ip=ip,
            country_code=data.get("country_code"),
            country_name=data.get("country"),
            org=conn.get("org"),
            domain=conn.get("domain"),
        )
```

```python
# src/ipsources/ipapi.py
"""Free, keyless — adds hosting/proxy/mobile flags (DataCenter/Residential/
Proxy classification, same idea as a paid multi-source checker). HTTP-only
on the free tier (no key means no HTTPS on their end), capped at 45
req/min — fine for a public IP, no credentials involved."""

from ipsources import base

FIELDS = "status,country,countryCode,isp,org,as,proxy,hosting,mobile,query"


class IpApiSource(base.IPInfoSource):
    key = "ipapi"
    name = "ip-api.com"

    def lookup(self, ip: str) -> base.IPFinding | None:
        data = base.fetch_json(f"http://ip-api.com/json/{ip}?fields={FIELDS}")
        if not data or data.get("status") != "success":
            return None
        return base.IPFinding(
            source=self.name,
            ip=ip,
            country_code=data.get("countryCode"),
            country_name=data.get("country"),
            org=data.get("isp") or data.get("org"),
            hosting=bool(data.get("hosting")),
            proxy=bool(data.get("proxy")),
            mobile=bool(data.get("mobile")),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS (all new tests in `tests/test_ipsources.py` green, full suite still green)

- [ ] **Step 5: Commit**

```bash
git add src/ipsources/ tests/test_ipsources.py
git commit -m "$(cat <<'EOF'
Add ipsources package: IPInfoSource ABC + free ipwho.is/ip-api.com sources

First half of the pluggable IP-intelligence registry described in
docs/superpowers/specs/2026-09-28-pluggable-ip-sources-and-tools-design.md
— mirrors providers/base.py's VPNProvider ABC + registry pattern.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Keyed sources (AbuseIPDB, IPQualityScore) + `ALL_SOURCES` registry

**Files:**
- Create: `src/ipsources/abuseipdb.py`
- Create: `src/ipsources/ipqualityscore.py`
- Modify: `src/ipsources/__init__.py`
- Test: `tests/test_ipsources.py` (append)

**Interfaces:**
- Consumes: `ipsources.base.IPInfoSource`, `IPFinding`, `fetch_json` (Task 1)
- Produces:
  - `ipsources.abuseipdb.AbuseIPDBSource` (`key="abuseipdb"`, `name="AbuseIPDB"`, `needs_api_key=True`)
  - `ipsources.ipqualityscore.IPQualityScoreSource` (`key="ipqualityscore"`, `name="IPQualityScore"`, `needs_api_key=True`)
  - `ipsources.ALL_SOURCES: list[IPInfoSource]` — `[IpWhoIsSource(), IpApiSource(), AbuseIPDBSource(), IPQualityScoreSource()]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_ipsources.py (append)
from ipsources.abuseipdb import AbuseIPDBSource
from ipsources.ipqualityscore import IPQualityScoreSource


def test_abuseipdb_lookup_without_key_returns_none(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")

    def boom(url, **kw):
        raise AssertionError("must not call the network without a key")

    monkeypatch.setattr(base, "fetch_json", boom)
    assert AbuseIPDBSource().lookup("1.2.3.4") is None


def test_abuseipdb_lookup_happy_path(monkeypatch, tmp_path):
    import config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = config.Config()
    cfg.ip_sources["abuseipdb"] = {"api_key": "secret"}
    config.save_config(cfg)

    captured = {}

    def fake_fetch_json(url, headers=None, **kw):
        captured["url"] = url
        captured["headers"] = headers
        return {
            "data": {
                "countryCode": "RU",
                "isp": "Some Hosting Co",
                "usageType": "Data Center/Web Hosting/Transit",
                "abuseConfidenceScore": 42,
            }
        }

    monkeypatch.setattr(base, "fetch_json", fake_fetch_json)
    finding = AbuseIPDBSource().lookup("1.2.3.4")
    assert finding.source == "AbuseIPDB"
    assert finding.country_code == "RU"
    assert finding.hosting is True
    assert finding.abuse_score == 42
    assert captured["headers"]["Key"] == "secret"
    assert "1.2.3.4" in captured["url"]


def test_ipqualityscore_lookup_without_key_returns_none(monkeypatch, tmp_path):
    import config

    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")

    def boom(url, **kw):
        raise AssertionError("must not call the network without a key")

    monkeypatch.setattr(base, "fetch_json", boom)
    assert IPQualityScoreSource().lookup("1.2.3.4") is None


def test_ipqualityscore_lookup_happy_path(monkeypatch, tmp_path):
    import config

    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = config.Config()
    cfg.ip_sources["ipqualityscore"] = {"api_key": "secret"}
    config.save_config(cfg)

    captured = {}

    def fake_fetch_json(url, **kw):
        captured["url"] = url
        return {
            "success": True,
            "country_code": "RU",
            "ISP": "Some Proxy Provider",
            "proxy": True,
            "vpn": False,
            "tor": False,
            "mobile": False,
            "fraud_score": 77,
        }

    monkeypatch.setattr(base, "fetch_json", fake_fetch_json)
    finding = IPQualityScoreSource().lookup("1.2.3.4")
    assert finding.source == "IPQualityScore"
    assert finding.proxy is True
    assert finding.abuse_score == 77
    assert "secret" in captured["url"]


def test_all_sources_registry_has_all_four():
    import ipsources

    names = {s.name for s in ipsources.ALL_SOURCES}
    assert names == {"ipwho.is", "ip-api.com", "AbuseIPDB", "IPQualityScore"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `ModuleNotFoundError: No module named 'ipsources.abuseipdb'`

- [ ] **Step 3: Write the implementation**

```python
# src/ipsources/abuseipdb.py
"""Keyed source: https://www.abuseipdb.com/api (v2 /check). Free tier:
registration + API key, ~1000 checks/day. Auth via a `Key` header — a
genuinely different auth shape from IPQualityScore's key-in-URL-path,
which is the whole point of exercising both against this interface."""

from ipsources import base


class AbuseIPDBSource(base.IPInfoSource):
    key = "abuseipdb"
    name = "AbuseIPDB"
    needs_api_key = True

    def lookup(self, ip: str) -> base.IPFinding | None:
        api_key = self._api_key()
        if not api_key:
            return None
        data = base.fetch_json(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": api_key, "Accept": "application/json"},
        )
        if not data or "data" not in data:
            return None
        d = data["data"]
        usage = (d.get("usageType") or "").lower()
        return base.IPFinding(
            source=self.name,
            ip=ip,
            country_code=d.get("countryCode"),
            org=d.get("isp"),
            hosting="hosting" in usage or "data center" in usage,
            abuse_score=d.get("abuseConfidenceScore"),
        )
```

```python
# src/ipsources/ipqualityscore.py
"""Keyed source: https://www.ipqualityscore.com/documentation/proxy-detection-api/overview
Free tier: registration + API key, ~5000 checks/month on trial. Auth via
the key embedded in the URL path — the other real-world auth shape this
interface needs to handle alongside AbuseIPDB's header key."""

from ipsources import base


class IPQualityScoreSource(base.IPInfoSource):
    key = "ipqualityscore"
    name = "IPQualityScore"
    needs_api_key = True

    def lookup(self, ip: str) -> base.IPFinding | None:
        api_key = self._api_key()
        if not api_key:
            return None
        data = base.fetch_json(f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}")
        if not data or not data.get("success"):
            return None
        return base.IPFinding(
            source=self.name,
            ip=ip,
            country_code=data.get("country_code"),
            org=data.get("ISP"),
            proxy=bool(data.get("proxy") or data.get("vpn") or data.get("tor")),
            mobile=bool(data.get("mobile")),
            abuse_score=data.get("fraud_score"),
        )
```

```python
# src/ipsources/__init__.py
from ipsources.abuseipdb import AbuseIPDBSource
from ipsources.ipapi import IpApiSource
from ipsources.ipqualityscore import IPQualityScoreSource
from ipsources.ipwhois import IpWhoIsSource

ALL_SOURCES = [
    IpWhoIsSource(),
    IpApiSource(),
    AbuseIPDBSource(),
    IPQualityScoreSource(),
]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/ipsources/ tests/test_ipsources.py
git commit -m "$(cat <<'EOF'
Add keyed IP sources (AbuseIPDB, IPQualityScore) + ALL_SOURCES registry

Proves the IPInfoSource interface against two real, differently-shaped
auth mechanisms (header key vs. key-in-path) as called for by the spec.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `config.py` — `ip_sources` / `tools_visible` fields

**Files:**
- Modify: `src/config.py`
- Test: `tests/test_config.py` (append)

**Interfaces:**
- Consumes: nothing new
- Produces:
  - `config.Config.ip_sources: dict[str, dict]`
  - `config.Config.tools_visible: dict[str, bool]`
  - `config.Config.tool_visible(key: str) -> bool`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_config.py (append)
def test_ip_sources_and_tools_visible_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = load_config()
    assert cfg.ip_sources == {}
    assert cfg.tool_visible("anything") is True  # default: visible


def test_ip_sources_roundtrip_with_api_key(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = Config()
    cfg.ip_sources["abuseipdb"] = {"api_key": "secret-123"}
    cfg.tools_visible["dns_leak_test"] = False
    save_config(cfg)

    loaded = load_config()
    assert loaded.ip_sources["abuseipdb"]["api_key"] == "secret-123"
    assert loaded.tool_visible("dns_leak_test") is False
    assert loaded.tool_visible("ip_info") is True  # untouched key still defaults on


def test_old_config_without_new_keys_still_loads(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"killswitch_mode": "happ"}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.killswitch_mode == "happ"
    assert cfg.ip_sources == {}
    assert cfg.tools_visible == {}


def test_malformed_ip_sources_and_tools_visible_ignored(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    p.write_text('{"ip_sources": "nope", "tools_visible": ["also nope"]}')
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    cfg = load_config()
    assert cfg.ip_sources == {}
    assert cfg.tools_visible == {}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'ip_sources'`

- [ ] **Step 3: Write the implementation**

In `src/config.py`, add two fields and a method to the `Config` dataclass:

```python
@dataclass
class Config:
    providers: dict[str, bool] = field(default_factory=dict)
    killswitch_mode: str = "off"  # "off" | "happ" | "all"
    show_empty_providers: bool = False
    happ_gui_fallback: bool = False  # launch the Happ window when headless connect fails
    exit_ip_enabled: bool = True
    exit_ip_max_age: int = 600
    ip_sources: dict[str, dict] = field(default_factory=dict)
    tools_visible: dict[str, bool] = field(default_factory=dict)

    def provider_visible(self, name: str) -> bool:
        return self.providers.get(name.lower(), True)

    def tool_visible(self, key: str) -> bool:
        return self.tools_visible.get(key, True)
```

In `load_config()`, after the `exit_ip` block:

```python
    ip_sources = raw.get("ip_sources")
    if isinstance(ip_sources, dict):
        cfg.ip_sources = {str(k): v for k, v in ip_sources.items() if isinstance(v, dict)}

    tools_visible = raw.get("tools_visible")
    if isinstance(tools_visible, dict):
        cfg.tools_visible = {str(k): bool(v) for k, v in tools_visible.items()}
    return cfg
```

(the existing `return cfg` moves down to after this block — there is only one `return cfg` in the function, at the very end)

In `save_config()`, add two keys to the `raw` dict:

```python
def save_config(cfg: Config) -> None:
    raw = {
        "providers": cfg.providers,
        "killswitch_mode": cfg.killswitch_mode,
        "show_empty_providers": cfg.show_empty_providers,
        "happ_gui_fallback": cfg.happ_gui_fallback,
        "exit_ip": {
            "enabled": cfg.exit_ip_enabled,
            "max_age_seconds": cfg.exit_ip_max_age,
        },
        "ip_sources": cfg.ip_sources,
        "tools_visible": cfg.tools_visible,
    }
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(raw, indent=2) + "\n")
    tmp.replace(CONFIG_PATH)
```

Also update the module docstring's example JSON at the top of `config.py` to mention the two new keys (one line each), matching the existing docstring's style.

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/config.py tests/test_config.py
git commit -m "$(cat <<'EOF'
Add ip_sources/tools_visible fields to config.json schema

Additive only — an existing config.json without these keys still loads
with everything visible/enabled, matching the existing providers/
provider_visible() precedent.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `reputation.py` becomes an orchestrator over `ipsources`

**Files:**
- Modify: `src/reputation.py` (near-total rewrite of the network-calling parts; `is_suspicious`/`_reason_tags`/`mark`/`request_update`/`CACHE`/`MAX_AGE` are unchanged)
- Modify: `tests/test_reputation.py` (replace the `_lookup`/`_lookup_ipapi`/`_get_json`-mocking tests; keep the `is_suspicious`/`_reason_tags`/`mark` tests as-is)

**Interfaces:**
- Consumes: `ipsources.ALL_SOURCES`, `ipsources.base.IPFinding` (Tasks 1-2)
- Produces:
  - `reputation.combined_tags(findings: list[IPFinding]) -> list[str]`
  - `reputation.is_flagged(findings: list[IPFinding]) -> bool`
  - `reputation.lookup_host(host: str, include_keyed: bool) -> list[IPFinding]`
  - `reputation.lookup_self(include_keyed: bool = True) -> list[IPFinding]`
  - `reputation.write_reputations(targets)` (same signature, new internals)
  - Unchanged: `reputation.is_suspicious(entry: dict) -> bool`, `reputation._reason_tags(entry: dict) -> list[str]`, `reputation.mark(name: str) -> str`, `reputation.request_update() -> None`, `reputation.CACHE`, `reputation.MAX_AGE`

- [ ] **Step 1: Write the failing tests**

Replace `tests/test_reputation.py` in full with:

```python
import json
import time

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
    monkeypatch.setattr(reputation.socket, "gethostbyname", lambda h: resolved.append(h) or "1.2.3.4")
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


def test_detect_own_ip_primary_source(monkeypatch):
    monkeypatch.setattr(
        reputation, "_get_json", lambda url: {"success": True, "ip": "1.2.3.4"}
    )
    assert reputation._detect_own_ip() == "1.2.3.4"


def test_detect_own_ip_falls_back_on_primary_failure(monkeypatch):
    monkeypatch.setattr(reputation, "_get_json", lambda url: None)

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `AttributeError: module 'reputation' has no attribute 'combined_tags'` (and similar for the other new names)

- [ ] **Step 3: Write the implementation**

Replace `src/reputation.py` in full with:

```python
"""VPN exit/server IP reputation — flags connections against every enabled
source in ipsources.ALL_SOURCES (Russian-linked registration, datacenter/
proxy flags — see ipsources/ for the individual sources).

Not a privacy/leak check by itself — purely a labelling aid so servers can
be told apart in the menu, discovered manually during a DNS-leak
investigation where several "Germany"-labelled Happ servers turned out to
be registered to Russian entities (.ru/.su ASN-owner domains) or to be a
bridge routing physically through Russia.

Same fire-and-forget cache pattern as happmeta's ping cache (PING_CACHE),
but keyed by connection name with a much longer TTL — ASN registration is
stable, unlike RTT. write_reputations() (the daily background sweep across
every known server) only ever passes include_keyed=False — keyed/paid
sources are for the on-demand lookup_self() ("IP Info" menu action) only,
so a paid source's monthly quota is never at risk from routine menu use.
"""

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import ipsources
from ipsources.base import IPFinding

CACHE = Path.home() / ".cache/vpn-manager/reputation.json"
MAX_AGE = 24 * 3600  # a day — registration data doesn't change hour to hour
LOOKUP_TIMEOUT = 8  # seconds, thread-guarded (urlopen's timeout excludes DNS)
IPWHO_API = "https://ipwho.is/"  # used only by _detect_own_ip()'s primary check
IPAPI_PACE = 1.5  # seconds between sweep hosts, keeps well under ip-api.com's 45/min cap

MANAGER = Path(__file__).resolve().parent / "vpn_manager.py"


def _reason_tags(entry: dict) -> list[str]:
    """Which criteria this entry tripped, in display order. Takes a plain
    dict (not an IPFinding) — this is also called directly by ipinfo.py's
    status_line() and vpn_manager._dns_leak_server_row(), each building an
    ad-hoc dict from a data source unrelated to ipsources."""
    tags = []
    domain = (entry.get("domain") or "").lower()
    if entry.get("country_code") == "RU" or domain.endswith((".ru", ".su")):
        tags.append("RU")
    if entry.get("hosting"):
        tags.append("DC")
    if entry.get("proxy"):
        tags.append("PROXY")
    return tags


def is_suspicious(entry: dict) -> bool:
    return bool(_reason_tags(entry))


def combined_tags(findings: list[IPFinding]) -> list[str]:
    """Union of _reason_tags() over every finding, in first-seen order —
    reuses the single-dict rules per finding instead of duplicating them."""
    tags: list[str] = []
    for finding in findings:
        for tag in _reason_tags(vars(finding)):
            if tag not in tags:
                tags.append(tag)
    return tags


def is_flagged(findings: list[IPFinding]) -> bool:
    return bool(combined_tags(findings))


def _get_json(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=6) as resp:
            return json.loads(resp.read().decode())
    except (OSError, ValueError):
        return None


def _detect_own_ip() -> str | None:
    """Bootstrap for lookup_self(): the same ipwho.is-then-ifconfig.me
    fallback chain ipinfo.py uses for its own exit-IP cache, duplicated
    here (not imported) — ipinfo.py already imports reputation for
    is_suspicious(), so importing ipinfo back would be circular."""
    data = _get_json(IPWHO_API)
    if data and data.get("success") and data.get("ip"):
        return data["ip"]
    try:
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=6) as resp:
            return resp.read().decode().strip()
    except OSError:
        return None


def _enabled_sources(include_keyed: bool):
    return [
        s
        for s in ipsources.ALL_SOURCES
        if s.is_enabled() and (include_keyed or not s.needs_api_key)
    ]


def lookup_host(host: str, include_keyed: bool) -> list[IPFinding]:
    """Resolves host once, queries every enabled source with that one IP
    (thread-guarded exactly like the old single-source _lookup() was —
    urlopen's timeout does not cover gethostbyname(), which can hang far
    longer than LOOKUP_TIMEOUT). One source failing never breaks the
    others; a DNS failure yields no findings at all."""
    result: list[IPFinding] = []

    def _work() -> None:
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return
        for source in _enabled_sources(include_keyed):
            try:
                finding = source.lookup(ip)
            except Exception:  # noqa: BLE001 - one bad source must not break the others
                finding = None
            if finding is not None:
                result.append(finding)

    worker = threading.Thread(target=_work, daemon=True)
    worker.start()
    worker.join(timeout=LOOKUP_TIMEOUT)
    return result


def lookup_self(include_keyed: bool = True) -> list[IPFinding]:
    """On-demand 'IP Info': detect the caller's own public IP once, then
    every enabled source (keyed included by default) against that one
    address — every source is asked about the SAME IP, rather than each
    source's own "self-detect" endpoint potentially reporting a different
    one."""
    ip = _detect_own_ip()
    if not ip:
        return []
    findings = []
    for source in _enabled_sources(include_keyed):
        try:
            finding = source.lookup(ip)
        except Exception:  # noqa: BLE001 - one bad source must not break the others
            finding = None
        if finding is not None:
            findings.append(finding)
    return findings


def _read() -> dict:
    try:
        data = json.loads(CACHE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def mark(name: str) -> str:
    """' ⚠RU/DC' for a flagged connection (only the tags that actually
    tripped), '' otherwise — including a connection never measured yet, so
    the menu stays quiet before the first sweep completes rather than
    marking everything as unknown."""
    entry = _read().get(name)
    if not isinstance(entry, dict) or time.time() - entry.get("at", 0) > MAX_AGE:
        return ""
    tags = entry.get("tags") or []
    return f" ⚠{'/'.join(tags)}" if tags else ""


def request_update() -> None:
    """Fire-and-forget background sweep if the cache is stale."""
    cache = _read()
    if time.time() - cache.get("updated_at", 0) < MAX_AGE:
        return
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-reputation"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def write_reputations(targets: list[tuple[str, str, int]]) -> None:
    """Measure and write the cache (single writer). Dedupes by host — many
    connections (e.g. Happ's rotating 'bridge' servers) share one host, so
    each unique host is looked up once (free sources only —
    include_keyed=False) and the result fanned out to every name that uses
    it. Paced between hosts (IPAPI_PACE) to stay under ip-api.com's
    free-tier rate limit — this only runs in the background, once a day,
    so the extra time doesn't matter."""
    by_host: dict[str, list[IPFinding]] = {}
    entries: dict[str, dict] = {}
    for name, host, _port in targets:
        if host not in by_host:
            try:
                by_host[host] = lookup_host(host, include_keyed=False)
            except Exception:  # noqa: BLE001 - one bad host must not abort the sweep
                by_host[host] = []
            time.sleep(IPAPI_PACE)
        findings = by_host[host]
        if not findings:
            continue
        entries[name] = {
            "at": time.time(),
            "suspicious": is_flagged(findings),
            "tags": combined_tags(findings),
            "country_code": findings[0].country_code,
        }
    entries["updated_at"] = time.time()
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(entries, ensure_ascii=False))
    except OSError:
        pass
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS (`tests/test_reputation.py` and full suite green — check `tests/test_ipinfo.py` specifically too, since `ipinfo.status_line()` calls `reputation.is_suspicious()` unchanged and must still pass without modification)

- [ ] **Step 5: Commit**

```bash
git add src/reputation.py tests/test_reputation.py
git commit -m "$(cat <<'EOF'
Turn reputation.py into an orchestrator over ipsources.ALL_SOURCES

is_suspicious()/_reason_tags()/mark() keep their existing single-dict
signature (ipinfo.py and _dns_leak_server_row() call them unchanged);
combined_tags()/is_flagged() are the new list[IPFinding] equivalents
used by lookup_host()/lookup_self()/write_reputations(). Keyed sources
only ever reach lookup_self() (include_keyed defaults True there);
write_reputations() always passes include_keyed=False.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Dead-connection marker `✗` → `⛔`

**Files:**
- Modify: `src/happmeta.py:729-737` (`ping_mark`), `:740-754` (`server_info_suffix`)
- Modify: `tests/test_happmeta.py:492`
- Modify: `tests/test_provider_ping.py:202,226,267,290`
- Modify: `tests/test_menu.py:194`

**Interfaces:**
- Consumes: nothing new
- Produces: `happmeta.ping_mark(name)` now returns `"⛔"` instead of `"✗"` for a fresh-but-failed ping; `happmeta.server_info_suffix(name)` recognizes `"⛔"` as the "stop, don't append protocol info" case

- [ ] **Step 1: Update the tests to expect `⛔`**

In `tests/test_happmeta.py`, change line 492:
```python
    assert happmeta.server_info_suffix("down") == "⛔"
```

In `tests/test_provider_ping.py`, change line 202:
```python
    assert happmeta.ping_mark("down") == "⛔"
```
and line 267:
```python
    assert "down    ⛔" in options
```
(lines 226 and 290 are comments mentioning "the ✗ mark" — update the comment text to "⛔" too for consistency, no assertion change needed there)

In `tests/test_menu.py`, change line 194:
```python
    assert "⛔" in seen[0][1]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — the three `assert ... == "⛔"` / `in` checks fail because the code still returns `"✗"`

- [ ] **Step 3: Write the implementation**

In `src/happmeta.py`, change `ping_mark`:

```python
def ping_mark(name: str) -> str:
    """'✓ 42 ms' / '⛔' / '' — the Happ GUI availability metaphor for any
    connection name in the shared ping cache (Happ, WireGuard, OpenVPN)."""
    entry = _fresh_ping_entry(name)
    if entry is None:
        return ""
    if entry.get("ms") is None:
        return "⛔"
    return f"✓ {entry['ms']:.0f} ms"
```

and `server_info_suffix`'s early-return check:

```python
def server_info_suffix(name: str) -> str:
    """'✓ 42 ms · trojan/ws' for menu labels — ping_mark plus xray protocol
    info. The standard vless/tcp/reality tuple is omitted (it is the common
    case); a server never measured stays unmarked so the label does not get
    noisy."""
    mark = ping_mark(name)
    if not mark or mark == "⛔":
        return mark
    parts = [mark]
    params = server_params(name)
    if params:
        proto = (params["protocol"], params["network"], params["security"])
        if proto != ("vless", "tcp", "reality"):
            parts.append("/".join(p for p in proto if p))
    return " · ".join(parts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/happmeta.py tests/test_happmeta.py tests/test_provider_ping.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Make the dead-connection marker more visible: ✗ → ⛔

ping_mark() is shared by every provider's menu labels already
(_collect_ping_targets() combines Happ + every ALL_PROVIDERS member's
own ping_targets() into one cache) — one function change covers all of
them.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `crtname.py` — subdomain search (Certificate Transparency)

**Files:**
- Create: `src/crtname.py`
- Test: `tests/test_crtname.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `crtname.search(domain: str) -> list[str] | None`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_crtname.py
import crtname


class _Resp:
    def __init__(self, payload):
        import json

        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_search_happy_path(monkeypatch):
    monkeypatch.setattr(
        crtname.urllib.request,
        "urlopen",
        lambda url, timeout=8: _Resp([{"sub": "example.com"}, {"sub": "www.example.com"}]),
    )
    assert crtname.search("example.com") == ["example.com", "www.example.com"]


def test_search_empty_result(monkeypatch):
    monkeypatch.setattr(crtname.urllib.request, "urlopen", lambda url, timeout=8: _Resp([]))
    assert crtname.search("nosuchdomain.example") == []


def test_search_returns_none_on_network_failure(monkeypatch):
    def boom(url, timeout=8):
        raise OSError("no route")

    monkeypatch.setattr(crtname.urllib.request, "urlopen", boom)
    assert crtname.search("example.com") is None


def test_search_returns_none_on_malformed_json(monkeypatch):
    class _Bad:
        def read(self):
            return b"not json"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(crtname.urllib.request, "urlopen", lambda url, timeout=8: _Bad())
    assert crtname.search("example.com") is None


def test_search_url_encodes_the_domain(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout=8):
        captured["url"] = url
        return _Resp([])

    monkeypatch.setattr(crtname.urllib.request, "urlopen", fake_urlopen)
    crtname.search("exa mple.com")
    assert "exa+mple.com" in captured["url"] or "exa%20mple.com" in captured["url"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `ModuleNotFoundError: No module named 'crtname'`

- [ ] **Step 3: Write the implementation**

```python
# src/crtname.py
"""Subdomain search via crt.name (https://crt.name) — a free, keyless,
passive subdomain index fed by the public Certificate Transparency
firehose. Found during this project's DNS-leak investigation session;
purely on-demand (no background polling), so its own rate limit
(~100/window, seen via X-RateLimit-* response headers) is a non-issue for
normal use.
"""

import json
import urllib.parse
import urllib.request

API = "https://crt.name/v1/search"
TIMEOUT = 8


def search(domain: str) -> list[str] | None:
    """Every subdomain crt.name has on file for domain (possibly empty),
    or None on any network/parse failure."""
    url = f"{API}?apex={urllib.parse.quote_plus(domain)}"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
    except (OSError, ValueError):
        return None
    if not isinstance(data, list):
        return None
    return [entry["sub"] for entry in data if isinstance(entry, dict) and "sub" in entry]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/crtname.py tests/test_crtname.py
git commit -m "$(cat <<'EOF'
Add crtname.py: subdomain search via crt.name's free CT-log API

Backs the new Subdomain Search Tools entry (wired up in a later task).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `speedtest.py` — single-measurement throughput

**Files:**
- Create: `src/speedtest.py`
- Test: `tests/test_speedtest.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `speedtest.measure() -> float | None` (MB/s)

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_speedtest.py
import speedtest


class _Resp:
    def __init__(self, n_bytes):
        self._payload = b"x" * n_bytes

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_measure_happy_path(monkeypatch):
    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda url, timeout=20: _Resp(10_000_000)
    )
    times = iter([100.0, 105.0])  # 5 s elapsed
    monkeypatch.setattr(speedtest.time, "perf_counter", lambda: next(times))
    mbps = speedtest.measure()
    assert mbps == 2.0  # 10 MB / 5 s


def test_measure_returns_none_on_network_failure(monkeypatch):
    def boom(url, timeout=20):
        raise OSError("no route")

    monkeypatch.setattr(speedtest.urllib.request, "urlopen", boom)
    assert speedtest.measure() is None


def test_measure_returns_none_on_zero_elapsed_time(monkeypatch):
    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda url, timeout=20: _Resp(1000)
    )
    monkeypatch.setattr(speedtest.time, "perf_counter", lambda: 100.0)  # same value twice
    assert speedtest.measure() is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `ModuleNotFoundError: No module named 'speedtest'`

- [ ] **Step 3: Write the implementation**

```python
# src/speedtest.py
"""Single-measurement download throughput, through whatever the current
default route is (the VPN tunnel, if one is up) — Cloudflare's public
speed-test endpoint, no auth, the same one speed.cloudflare.com's own page
uses.
"""

import time
import urllib.request

URL = "https://speed.cloudflare.com/__down?bytes=10000000"  # 10 MB
TIMEOUT = 20


def measure() -> float | None:
    """MB/s over a single 10 MB download, or None on failure."""
    try:
        t0 = time.perf_counter()
        with urllib.request.urlopen(URL, timeout=TIMEOUT) as resp:
            n = len(resp.read())
        dt = time.perf_counter() - t0
    except (OSError, ValueError):
        return None
    if dt <= 0:
        return None
    return (n / 1_000_000) / dt
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/speedtest.py tests/test_speedtest.py
git commit -m "$(cat <<'EOF'
Add speedtest.py: single-measurement tunnel throughput via Cloudflare

Backs the new Speed Test Tools entry (wired up in a later task).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `vpn_manager.py` — extract `walker_input()`

**Files:**
- Modify: `src/vpn_manager.py:780-804` (`import_config_file`)
- Test: `tests/test_menu.py` (append)

**Interfaces:**
- Consumes: `WALKER_WIDTH`, `WALKER_MAXWIDTH` (existing constants, `vpn_manager.py:734-735`)
- Produces: `vpn_manager.walker_input(prompt: str) -> str | None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_menu.py (append)
def test_walker_input_returns_stripped_text(monkeypatch):
    class R:
        stdout = "  /home/user/config.conf  \n"

    monkeypatch.setattr(vpn_manager.subprocess, "run", lambda cmd, **k: R())
    assert vpn_manager.walker_input("Path") == "/home/user/config.conf"


def test_walker_input_returns_none_when_empty(monkeypatch):
    class R:
        stdout = "\n"

    monkeypatch.setattr(vpn_manager.subprocess, "run", lambda cmd, **k: R())
    assert vpn_manager.walker_input("Path") is None


def test_walker_input_returns_none_when_walker_missing(monkeypatch):
    def boom(cmd, **k):
        raise FileNotFoundError

    monkeypatch.setattr(vpn_manager.subprocess, "run", boom)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    assert vpn_manager.walker_input("Path") is None


def test_walker_input_passes_width_flags(monkeypatch):
    captured = {}

    class R:
        stdout = "x\n"

    def fake_run(cmd, **k):
        captured["cmd"] = cmd
        return R()

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    vpn_manager.walker_input("Path")
    cmd = captured["cmd"]
    assert "--width" in cmd and cmd[cmd.index("--width") + 1] == str(vpn_manager.WALKER_WIDTH)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `AttributeError: module 'vpn_manager' has no attribute 'walker_input'`

- [ ] **Step 3: Write the implementation**

Replace `import_config_file` (`src/vpn_manager.py:780-804`) with:

```python
def walker_input(prompt: str) -> str | None:
    """Single-field text input via walker (-I, dmenu-only), same widened
    window as walker_select(). None on any failure or empty input."""
    try:
        result = subprocess.run(
            [
                "walker",
                "-d",
                "-I",
                "-p",
                prompt,
                "--width",
                str(WALKER_WIDTH),
                "--maxwidth",
                str(WALKER_MAXWIDTH),
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        notify("Error", "walker not found", urgent=True)
        return None
    text = result.stdout.strip()
    return text or None


def import_config_file(provider, title: str) -> ActionResult:
    path = walker_input(f"{title} config path")
    if not path:
        return ActionResult(success=False, message="No path entered")
    return provider.import_config(path)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vpn_manager.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Extract walker_input() from import_config_file()

Shared single-field-input helper — the new Subdomain Search and Settings
actions need the same -I dialog, not just config import.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: `ip_info_menu()` rewritten for a findings list

**Files:**
- Modify: `src/vpn_manager.py:352-382` (`_ip_info_flag_row`, `ip_info_menu`)
- Modify: `tests/test_menu.py:811-851` (`test_ip_info_menu_builds_rows`, `test_ip_info_menu_handles_network_failure`)

**Interfaces:**
- Consumes: `reputation.lookup_self(include_keyed=True) -> list[IPFinding]` (Task 4)
- Produces: `vpn_manager.ip_info_menu()` (same name/signature, new internals — every enabled source gets a row now, not two hardcoded ones)

- [ ] **Step 1: Update the tests**

Replace the two existing IP-Info tests in `tests/test_menu.py` with:

```python
def test_ip_info_menu_builds_rows(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    findings = [
        IPFinding(source="ipwho.is", ip="1.2.3.4", country_name="Germany", org="jogcorp"),
        IPFinding(
            source="ip-api.com",
            ip="1.2.3.4",
            country_name="France",
            org="SMARTNET Germany GmbH",
            hosting=True,
            proxy=False,
            mobile=False,
        ),
    ]
    monkeypatch.setattr(vpn_manager.reputation, "lookup_self", lambda include_keyed=True: findings)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    result = vpn_manager.ip_info_menu()
    assert result.success
    rows = seen[0]
    assert rows[0] == "IP: 1.2.3.4"
    assert "ipwho.is: Germany · jogcorp" in rows
    assert "ip-api.com: France · SMARTNET Germany GmbH" in rows
    assert "🏢 Datacenter/Hosting: Yes" in rows
    assert "🕵 Proxy/VPN detected: No" in rows
    assert "📱 Mobile network: No" in rows
    assert rows[-1] == "‹ Back"


def test_ip_info_menu_handles_no_findings(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.reputation, "lookup_self", lambda include_keyed=True: [])
    result = vpn_manager.ip_info_menu()
    assert not result.success
```

Add the import at the top of `tests/test_menu.py`:
```python
from ipsources.base import IPFinding
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — old `ip_info_menu()` still expects a dict with `["ip"]`/`["ipwho_country"]` keys, `AttributeError`/`TypeError` against the new `IPFinding` list

- [ ] **Step 3: Write the implementation**

Replace `src/vpn_manager.py:352-382` with:

```python
def _ip_info_flag_row(label: str, value: bool | None) -> tuple[str, callable]:
    text = "Yes" if value else "No"
    return (f"{label}: {text}", lambda: ActionResult(True, ""))


def ip_info_menu() -> ActionResult:
    """Multi-source exit-IP report — one row group per enabled ipsources
    source (free ones on by default; keyed ones once their API key is
    set). A single ad-hoc lookup for the current public IP, not the
    background reputation sweep."""
    notify("IP Info", "Проверка запущена, это займёт несколько секунд…")
    findings = reputation.lookup_self(include_keyed=True)
    if not findings:
        return ActionResult(False, "Не удалось получить информацию об IP — нет сети?")

    items: list[tuple[str, callable]] = [(f"IP: {findings[0].ip}", lambda: ActionResult(True, ""))]
    for finding in findings:
        parts = [p for p in (finding.country_name, finding.org) if p]
        label = f"{finding.source}: {' · '.join(parts)}" if parts else finding.source
        items.append((label, lambda: ActionResult(True, "")))
    items.append(_ip_info_flag_row("🏢 Datacenter/Hosting", any(f.hosting for f in findings)))
    items.append(_ip_info_flag_row("🕵 Proxy/VPN detected", any(f.proxy for f in findings)))
    items.append(_ip_info_flag_row("📱 Mobile network", any(f.mobile for f in findings)))
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt="IP Info")
    return ActionResult(True, "")
```

No import of `IPFinding` is needed in `src/vpn_manager.py` itself — the code above only calls attribute access (`finding.ip`, `finding.source`, ...) on objects it receives from `reputation.lookup_self()`, never constructs or type-annotates one by name. The test file imports `IPFinding` (to build fixture data); the production module does not need to.

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vpn_manager.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Rewrite ip_info_menu() for reputation.lookup_self()'s findings list

One row group per enabled ipsources source instead of two hardcoded
ones — AbuseIPDB/IPQualityScore show up here automatically once an API
key is configured.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: `TOOLS` registry, `tools_menu()`, `menu_loop()` reorg, Subdomain Search, Speed Test

**Files:**
- Modify: `src/vpn_manager.py` (imports; new `TOOLS` list + `tools_menu()` near `_killswitch_item()`, `:297-301`; `menu_loop()`, `:413-460`; new `subdomain_search_menu()`, `speed_test_menu()`)
- Modify: `tests/test_menu.py` (`test_menu_loop_always_shows_dns_leak_test_and_ip_info_rows` → new `tools_menu()`-focused tests; new subdomain-search/speed-test tests)

**Interfaces:**
- Consumes: `crtname.search()` (Task 6), `speedtest.measure()` (Task 7), `config.tool_visible()` (Task 3), `walker_input()` (Task 8)
- Produces:
  - `vpn_manager.TOOLS: list[tuple[str, str, callable]]` — `(key, label, action)`
  - `vpn_manager.tools_menu() -> ActionResult`
  - `vpn_manager.subdomain_search_menu() -> ActionResult`
  - `vpn_manager.speed_test_menu() -> ActionResult`
  - `menu_loop()` gains one `("🛠 Tools", tools_menu)` row in place of the three it drops

- [ ] **Step 1: Write the failing tests**

In `tests/test_menu.py`, replace `test_menu_loop_always_shows_dns_leak_test_and_ip_info_rows` with:

```python
def test_menu_loop_always_shows_tools_row(monkeypatch):
    """Present even with nothing configured/active, right before killswitch
    moved inside it — Tools itself replaces the three separate rows."""
    patch_menu_env(monkeypatch, [], picks=[])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.menu_loop()
    assert "🛠 Tools" in seen[0]
    assert "🔍 DNS Leak Test" not in seen[0]
    assert "ℹ️ IP Info" not in seen[0]
    assert not any(str(row).strip().startswith("Killswitch") for row in seen[0])


def test_tools_menu_lists_every_visible_tool(monkeypatch):
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: config.Config())
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="Tools": (seen.append(list(options)) or None),
    )
    vpn_manager.tools_menu()
    rows = seen[0]
    for label in (
        "🔍 DNS Leak Test",
        "ℹ️ IP Info",
        "🔎 Subdomain Search",
        "⚡ Speed Test",
        "🔄 Refresh All",
        "🗑 Clear Caches",
        "⚙ Settings",
    ):
        assert label in rows
    assert any(str(row).strip().startswith("Killswitch") for row in rows)
    assert rows[-1] == "‹ Back"


def test_tools_menu_hides_disabled_tool(monkeypatch):
    cfg = config.Config()
    cfg.tools_visible["dns_leak_test"] = False
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="Tools": (seen.append(list(options)) or None),
    )
    vpn_manager.tools_menu()
    assert "🔍 DNS Leak Test" not in seen[0]
    assert "ℹ️ IP Info" in seen[0]  # untouched key stays visible


def test_subdomain_search_menu_happy_path(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "example.com")
    monkeypatch.setattr(vpn_manager.crtname, "search", lambda domain: ["a.example.com", "b.example.com"])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    result = vpn_manager.subdomain_search_menu()
    assert result.success
    assert seen[0] == ["a.example.com", "b.example.com", "‹ Back"]


def test_subdomain_search_menu_no_domain_entered(monkeypatch):
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: None)
    result = vpn_manager.subdomain_search_menu()
    assert result.success  # silent cancel, matches import_config_file's "no path" non-error


def test_subdomain_search_menu_network_failure(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "example.com")
    monkeypatch.setattr(vpn_manager.crtname, "search", lambda domain: None)
    result = vpn_manager.subdomain_search_menu()
    assert not result.success


def test_subdomain_search_menu_no_results(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "example.com")
    monkeypatch.setattr(vpn_manager.crtname, "search", lambda domain: [])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.subdomain_search_menu()
    assert seen[0] == ["No subdomains found", "‹ Back"]


def test_speed_test_menu_happy_path(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.speedtest, "measure", lambda: 12.34)
    result = vpn_manager.speed_test_menu()
    assert result.success
    assert "12.3" in result.message


def test_speed_test_menu_network_failure(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.speedtest, "measure", lambda: None)
    result = vpn_manager.speed_test_menu()
    assert not result.success
```

Remove (or leave — they'll simply keep passing) the old `test_menu_loop_always_shows_dns_leak_test_and_ip_info_rows`; it's being **replaced** by `test_menu_loop_always_shows_tools_row` above, so delete the old one.

Also update `test_killswitch_item_toggle_gathers_targets` (`tests/test_menu.py:853`) if it asserted anything about `menu_loop()`'s row order — check it first; it drives `_killswitch_toggle` directly, not through `menu_loop()`, so it needs no change (confirm by reading it before assuming).

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `AttributeError: module 'vpn_manager' has no attribute 'tools_menu'` and friends

- [ ] **Step 3: Write the implementation**

Add near the top of `src/vpn_manager.py`, alongside the other imports:

```python
import crtname
import speedtest
```

`_killswitch_item()` (`src/vpn_manager.py:297-301`) stays exactly where it
is, unchanged — nothing gets added after it. The new block below goes in a
**different** spot: immediately before `def provider_actions(...)`
(currently `src/vpn_manager.py:385`). It has to go *after*
`dns_leak_test_menu`/`ip_info_menu` (defined at `:326`/`:357`) because
`TOOLS` references them by name in a list literal that executes at import
time — Python looks up a bare name used as a value (not inside a function
body) immediately, so referencing a function defined later in the file
would raise `NameError` at import. Insert this whole block right before
`provider_actions()`:

```python
def subdomain_search_menu() -> ActionResult:
    """crt.name-backed subdomain search — prompts for an apex domain, then
    shows every subdomain on file for it."""
    domain = walker_input("Domain (apex)")
    if not domain:
        return ActionResult(True, "")
    subs = crtname.search(domain)
    if subs is None:
        return ActionResult(False, "Не удалось выполнить поиск — нет сети?")
    items = [(s, lambda: ActionResult(True, "")) for s in subs] or [
        ("No subdomains found", lambda: ActionResult(True, ""))
    ]
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt=f"Subdomains: {domain}")
    return ActionResult(True, "")


def speed_test_menu() -> ActionResult:
    """Single-measurement download throughput through the current tunnel."""
    notify("Speed Test", "Тест запущен, это займёт несколько секунд…")
    mbps = speedtest.measure()
    if mbps is None:
        return ActionResult(False, "Не удалось выполнить тест — нет сети?")
    return ActionResult(True, f"⬇ {mbps:.1f} MB/s")


def refresh_all_menu() -> ActionResult:
    raise NotImplementedError  # implemented in Task 11


def clear_caches_menu() -> ActionResult:
    raise NotImplementedError  # implemented in Task 11


def settings_menu() -> ActionResult:
    raise NotImplementedError  # implemented in Task 12


# single source of truth for both tools_menu()'s rows and the configure
# wizard's questions (key, label, action) — killswitch is handled
# separately in both places since its row reflects live on/off state
# (_killswitch_item()), not a fixed action function.
TOOLS = [
    ("dns_leak_test", "🔍 DNS Leak Test", dns_leak_test_menu),
    ("ip_info", "ℹ️ IP Info", ip_info_menu),
    ("subdomain_search", "🔎 Subdomain Search", subdomain_search_menu),
    ("speed_test", "⚡ Speed Test", speed_test_menu),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑 Clear Caches", clear_caches_menu),
    ("settings", "⚙ Settings", settings_menu),
]


def tools_menu() -> ActionResult:
    cfg = config.load_config()
    items = [(label, fn) for key, label, fn in TOOLS if cfg.tool_visible(key)]
    if cfg.tool_visible("killswitch"):
        items.append(_killswitch_item())
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt="Tools")
    return ActionResult(True, "")
```

Now update `menu_loop()` (`src/vpn_manager.py:413-460`): replace

```python
    items.append(("🔍 DNS Leak Test", dns_leak_test_menu))
    items.append(("ℹ️ IP Info", ip_info_menu))
    items.append(_killswitch_item())  # always the last row
    return run_items(items, prompt="VPN")
```

with

```python
    items.append(("🛠 Tools", tools_menu))
    return run_items(items, prompt="VPN")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS for every test *except* any that exercises `refresh_all_menu`/`clear_caches_menu`/`settings_menu` through `tools_menu()`'s actual row action (none do yet — `test_tools_menu_lists_every_visible_tool` only checks label *presence*, never clicks them, so the `NotImplementedError` stubs are never invoked). Confirm the full suite is green.

- [ ] **Step 5: Commit**

```bash
git add src/vpn_manager.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Fold DNS Leak Test/IP Info/Killswitch into a 🛠 Tools submenu

Adds Subdomain Search (crt.name) and Speed Test as real actions;
Refresh All/Clear Caches/Settings land as NotImplementedError stubs,
implemented in the next two tasks — this keeps tools_menu()'s own
wiring and tests isolated from those three tools' internals.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: `refresh_all_menu()` and `clear_caches_menu()`

**Files:**
- Modify: `src/vpn_manager.py` (replace the two `NotImplementedError` stubs from Task 10; add `import contextlib`)
- Modify: `tests/test_menu.py` (append)

**Interfaces:**
- Consumes: `_collect_ping_targets()` pattern (existing `--update-ping`/`--update-subs` CLI flags, `src/vpn_manager.py:846-908`)
- Produces: `vpn_manager.refresh_all_menu() -> ActionResult`, `vpn_manager.clear_caches_menu() -> ActionResult`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_menu.py (append)
def test_refresh_all_menu_spawns_ping_and_subs_unconditionally(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vpn_manager.subprocess, "Popen", lambda cmd, **k: calls.append(cmd) or None
    )
    result = vpn_manager.refresh_all_menu()
    assert result.success
    flags = [c[2] for c in calls]  # [sys.executable, script_path, flag]
    assert "--update-ping" in flags
    assert "--update-subs" in flags


def test_clear_caches_menu_removes_only_json_files(tmp_path, monkeypatch):
    cache_dir = tmp_path / "vpn-manager"
    cache_dir.mkdir()
    (cache_dir / "reputation.json").write_text("{}")
    (cache_dir / "happ-ping.json").write_text("{}")
    keep = cache_dir / "not-a-cache.txt"
    keep.write_text("keep me")
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", cache_dir)

    result = vpn_manager.clear_caches_menu()

    assert result.success
    assert not (cache_dir / "reputation.json").exists()
    assert not (cache_dir / "happ-ping.json").exists()
    assert keep.exists()


def test_clear_caches_menu_tolerates_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", tmp_path / "does-not-exist")
    result = vpn_manager.clear_caches_menu()
    assert result.success
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `NotImplementedError`

- [ ] **Step 3: Write the implementation**

Add `import contextlib` to the top of `src/vpn_manager.py`, alongside the existing `import argparse` etc.

Replace the two stub functions from Task 10:

```python
def refresh_all_menu() -> ActionResult:
    """Force a ping sweep (every provider) + Happ subscription sync now,
    bypassing PING_MAX_AGE/SUB_MAX_AGE — request_ping_update()/
    request_subscription_update() are staleness-gated and would otherwise
    no-op if the last sweep was recent. Reputation is deliberately
    excluded (its own daily cadence + IPAPI_PACE already make it a
    multi-minute background job; forcing it from a menu click isn't
    "refresh now", it's "wait a while", which belongs to its own timer)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-ping"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-subs"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return ActionResult(True, "Обновление запущено в фоне")


CACHE_DIR = Path.home() / ".cache/vpn-manager"


def clear_caches_menu() -> ActionResult:
    """Every cache this project writes lives under CACHE_DIR (happmeta's
    PING_CACHE/PROVIDERS_CACHE/subscription-*.json, reputation.CACHE,
    ipinfo.CACHE_PATH, providers/base.py's RATE_CACHE) — safe to delete on
    demand, every reader already tolerates a missing file.
    ~/.config/happ-capture/ is NOT touched — that's captured server data,
    not a cache."""
    removed = 0
    if CACHE_DIR.is_dir():
        for f in CACHE_DIR.glob("*.json"):
            with contextlib.suppress(OSError):
                f.unlink()
                removed += 1
    return ActionResult(True, f"Кэш очищен ({removed} файлов) — пересоберётся сам")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vpn_manager.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Implement Refresh All and Clear Caches Tools actions

Refresh All bypasses the ping/subs staleness gates unconditionally
(that's the point — "do it now", not "do it now if it wasn't already
about to happen"); reputation is deliberately excluded, it has its own
multi-minute cadence. Clear Caches only touches *.json under
~/.cache/vpn-manager, never ~/.config/happ-capture (captured data, not
a cache).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: `Prompter` abstraction, `run_configure_wizard()`, `settings_menu()`, `--configure`

**Files:**
- Modify: `src/vpn_manager.py` (new `Prompter`/`TerminalPrompter`/`WalkerPrompter` classes, `run_configure_wizard()`, `settings_menu()` replacing its Task-10 stub, `main()`'s argparse block)
- Test: `tests/test_configure_wizard.py` (new)
- Modify: `tests/test_menu.py` (small addition for `settings_menu()`)

**Interfaces:**
- Consumes: `ALL_PROVIDERS` (existing), `ipsources.ALL_SOURCES` (Task 2), `config.Config`/`tool_visible` (Task 3), `TOOLS` (Task 10), `walker_select`/`walker_input` (existing/Task 8)
- Produces:
  - `vpn_manager.Prompter` (ABC): `confirm(question: str, default: bool) -> bool`, `text(question: str) -> str`
  - `vpn_manager.TerminalPrompter(Prompter)`
  - `vpn_manager.WalkerPrompter(Prompter)`
  - `vpn_manager.run_configure_wizard(prompter: Prompter) -> None`
  - `vpn_manager.settings_menu() -> ActionResult`
  - `--configure` CLI flag on `vpn_manager.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_configure_wizard.py
import config
import vpn_manager
from providers.base import ActionResult


class FakePrompter(vpn_manager.Prompter):
    """Feeds canned answers in call order — confirms and texts are two
    separate queues since the wizard interleaves them by section."""

    def __init__(self, confirms, texts=()):
        self._confirms = iter(confirms)
        self._texts = iter(texts)

    def confirm(self, question, default):
        return next(self._confirms, default)

    def text(self, question):
        return next(self._texts, "")


def test_terminal_prompter_confirm_default_on_empty_answer(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is True
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is False


def test_terminal_prompter_confirm_explicit_answer(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is True
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is False


def test_terminal_prompter_text_strips_input(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "  secret-key  ")
    assert vpn_manager.TerminalPrompter().text("Key?") == "secret-key"


def test_walker_prompter_confirm_maps_selection(monkeypatch):
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": "Да")
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=False) is True
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": "Нет")
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=True) is False
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": None)
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=True) is True  # escaped -> default


def test_walker_prompter_text_delegates_to_walker_input(monkeypatch):
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "example.com")
    assert vpn_manager.WalkerPrompter().text("Domain?") == "example.com"


def test_run_configure_wizard_writes_config_from_scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])  # keep the answer sequence short
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [])

    # No providers, no sources -> only the TOOLS (7) + killswitch (1) confirms
    prompter = FakePrompter(confirms=[True] * 8)
    vpn_manager.run_configure_wizard(prompter)

    loaded = config.load_config()
    assert loaded.tools_visible["dns_leak_test"] is True
    assert loaded.tools_visible["killswitch"] is True


def test_run_configure_wizard_respects_existing_config_refusal(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    original = config.Config(killswitch_mode="happ")
    config.save_config(original)

    prompter = FakePrompter(confirms=[False])  # "reconfigure?" -> no
    vpn_manager.run_configure_wizard(prompter)

    assert config.load_config().killswitch_mode == "happ"  # untouched


def test_run_configure_wizard_collects_api_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])

    class FakeSource:
        def __init__(self, key, name, needs_api_key):
            self.key, self.name, self.needs_api_key = key, name, needs_api_key

        def is_enabled(self):
            return False

    keyed = FakeSource("abuseipdb", "AbuseIPDB", True)
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [keyed])

    prompter = FakePrompter(confirms=[True] * 8, texts=["secret-key-123"])
    vpn_manager.run_configure_wizard(prompter)

    loaded = config.load_config()
    assert loaded.ip_sources["abuseipdb"]["api_key"] == "secret-key-123"


def test_settings_menu_runs_wizard_with_walker_prompter(monkeypatch):
    called = {}
    monkeypatch.setattr(
        vpn_manager, "run_configure_wizard", lambda prompter: called.update(kind=type(prompter))
    )
    result = vpn_manager.settings_menu()
    assert result.success
    assert called["kind"] is vpn_manager.WalkerPrompter
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `make test-docker`
Expected: FAIL — `AttributeError: module 'vpn_manager' has no attribute 'Prompter'`

- [ ] **Step 3: Write the implementation**

Add near the top of `src/vpn_manager.py`:
```python
from abc import ABC, abstractmethod

import ipsources
```

Replace the `settings_menu()` stub from Task 10 and add the new classes/function immediately before it (same "before `provider_actions()`" location as the rest of the Tools block from Task 10):

```python
class Prompter(ABC):
    @abstractmethod
    def confirm(self, question: str, default: bool) -> bool: ...

    @abstractmethod
    def text(self, question: str) -> str: ...


class TerminalPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        answer = input(f"{question} {suffix} ").strip().lower()
        return default if not answer else answer in ("y", "yes", "д", "да")

    def text(self, question: str) -> str:
        return input(f"{question}: ").strip()


class WalkerPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        selected = walker_select(["Да", "Нет"], prompt=question)
        return (selected == "Да") if selected else default

    def text(self, question: str) -> str:
        return walker_input(question) or ""


def run_configure_wizard(prompter: Prompter) -> None:
    """The provider/tool/source walk shared by --configure (TerminalPrompter,
    install.sh's last step) and ⚙ Settings (WalkerPrompter, in-menu — no
    reinstall needed). Never touches an existing config.json unless the
    user opts in via the first confirm."""
    if config.CONFIG_PATH.exists():
        if not prompter.confirm("Конфиг уже существует. Перенастроить?", False):
            return
        cfg = config.load_config()
    else:
        cfg = config.Config()

    for provider in ALL_PROVIDERS:
        visible = prompter.confirm(
            f"Показывать {provider.name}?", cfg.provider_visible(provider.name)
        )
        cfg.providers[provider.name.lower()] = visible

    for key, label, _fn in [*TOOLS, ("killswitch", "Killswitch", None)]:
        visible = prompter.confirm(f"Показывать инструмент «{label}»?", cfg.tool_visible(key))
        cfg.tools_visible[key] = visible

    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            answer = prompter.text(
                f"API-ключ {source.name} (Enter — оставить как есть/пропустить)"
            )
            if answer:
                cfg.ip_sources.setdefault(source.key, {})["api_key"] = answer
        else:
            enabled = prompter.confirm(f"Использовать {source.name}?", source.is_enabled())
            cfg.ip_sources.setdefault(source.key, {})["enabled"] = enabled

    config.save_config(cfg)


def settings_menu() -> ActionResult:
    run_configure_wizard(WalkerPrompter())
    return ActionResult(True, "Настройки сохранены")
```

Finally, in `main()` (`src/vpn_manager.py`, in the argparse block), add the new flag next to `--update-reputation`:

```python
    group.add_argument(
        "--configure",
        action="store_true",
        help="Interactive setup wizard: providers, tools, IP sources/keys",
    )
```

and its dispatch, alongside the other `elif` branches:

```python
    elif args.configure:
        run_configure_wizard(TerminalPrompter())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make test-docker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vpn_manager.py tests/test_configure_wizard.py tests/test_menu.py
git commit -m "$(cat <<'EOF'
Add Prompter abstraction + run_configure_wizard() + --configure flag

One question list (providers, TOOLS visibility + killswitch, IP
sources/keys), two front ends: TerminalPrompter (input(), for
--configure / make install) and WalkerPrompter (walker_select()/
walker_input(), for the new ⚙ Settings Tools action) — the wizard logic
itself is written and tested once, against a third, in-memory
FakePrompter.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: `install.sh` calls `--configure` as its last step

**Files:**
- Modify: `install.sh` (append after the existing "Final hints" echo block)

**Interfaces:**
- Consumes: `vpn_manager.py --configure` (Task 12)
- Produces: nothing new (shell script change only, no tests — `install.sh` is a real system installer never executed by the test suite, matching this project's existing convention for `install.sh`)

- [ ] **Step 1: Make the change**

At the end of `install.sh` (after the existing final `echo` lines, currently ending with `echo "      hyprctl reload   (or just log out/in)"`), append:

```bash

# ── Interactive configuration ─────────────────────────────────────────────────

echo ""
python3 "$REPO_DIR/src/vpn_manager.py" --configure
```

- [ ] **Step 2: Verify the script is still valid shell**

Run: `bash -n install.sh`
Expected: no output, exit code 0

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "$(cat <<'EOF'
Run the configuration wizard as the last step of make install

Never touches an existing config.json without the wizard's own
confirm gate (run_configure_wizard() itself handles that) — safe on
both fresh installs and upgrades.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 14: Documentation — `CLAUDE.md`

**Files:**
- Modify: `CLAUDE.md` (local file, gitignored per this repo's `.gitignore` — confirm with `git check-ignore -v CLAUDE.md` before editing; if it's tracked in this checkout for some reason, still edit it the same way, just also `git add` it in the commit)

**Interfaces:**
- Consumes: nothing (docs only)
- Produces: nothing (docs only)

- [ ] **Step 1: Add an "Adding a new IP-intelligence source" section**

Immediately after the existing "## Adding a new provider" section, add:

```markdown
## Adding a new IP-intelligence source

1. Create `src/ipsources/mysource.py` implementing `ipsources.base.IPInfoSource`
   (`key`, `name`, `needs_api_key`, `lookup(ip) -> IPFinding | None`)
2. Register it in `src/ipsources/__init__.py` by adding to `ALL_SOURCES`
3. If it needs an API key, `self._api_key()` (from the base class) reads
   `config.load_config().ip_sources[self.key]["api_key"]` — no separate
   `enabled` flag for keyed sources, a present key *is* "enabled"
4. Keyed sources are never used by the daily background sweep
   (`reputation.write_reputations()`) — only by the on-demand `ℹ️ IP Info`
   Tools action (`reputation.lookup_self(include_keyed=True)`)
```

Immediately after that new section, also add:

```markdown
## Tools submenu

`vpn_manager.py`'s `🛠 Tools` (one row in the main menu, replacing three
separate always-visible rows this project used to have) holds: `🔍 DNS
Leak Test`, `ℹ️ IP Info`, `🔎 Subdomain Search` (crt.name), `⚡ Speed Test`
(Cloudflare), `🔄 Refresh All` (force ping+subs sweep now, bypassing their
staleness gates), `🗑 Clear Caches` (deletes `*.json` under
`~/.cache/vpn-manager`, never `~/.config/happ-capture`), `⚙ Settings`, and
the Killswitch toggle. Each is individually hideable via
`config.json`'s `tools_visible` (see `vpn_manager.TOOLS`).

## Configuration wizard

`vpn_manager.py --configure` (run automatically as the last step of
`make install`) and `🛠 Tools → ⚙ Settings` (in-menu, no reinstall) run the
identical question walk — which VPN providers/Tools entries to show,
which `ipsources.ALL_SOURCES` to use and their API keys — against
`vpn_manager.run_configure_wizard(prompter)`. The only difference between
the two entry points is which `Prompter` gets passed in
(`TerminalPrompter`/`WalkerPrompter`). Never touches an existing
`config.json` without an explicit "reconfigure?" confirmation.
```

Read the current `CLAUDE.md` first and adjust heading level/placement to
match its existing style if the file has moved on since this plan was
written (it's a locally-maintained, gitignored file — the prose above is
the content to add, not a literal byte-for-byte patch).

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md 2>/dev/null || true  # gitignored in this repo; add only if actually tracked
git commit -m "$(cat <<'EOF'
Document the ipsources package and Tools submenu in CLAUDE.md

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)" --allow-empty-message --allow-empty 2>/dev/null || echo "CLAUDE.md is gitignored — edited locally, nothing to commit"
```

(If `CLAUDE.md` is gitignored, as it was confirmed earlier in this project's session history, this step edits the file for the benefit of future sessions but produces no commit — that's expected, not an error.)

---

## Task 15: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `make test-docker`
Expected: every test passes, ruff reports "All checks passed!" (the container runs ruff before pytest — see `Dockerfile.test`)

- [ ] **Step 2: Live sanity check of the new modules against real network (host, not the container)**

```bash
cd /path/to/waybar-vpn-manager && python3 -c "
import sys; sys.path.insert(0, 'src')
import crtname, speedtest, reputation
print('crtname:', crtname.search('example.com')[:3])
print('speedtest:', speedtest.measure(), 'MB/s')
print('ip_info findings:', len(reputation.lookup_self()), 'sources responded')
"
```
Expected: three non-error lines of real output (a live network call — do this on the host, never inside the `--network none` test container)

- [ ] **Step 3: Manually exercise the menu**

Run `python3 src/vpn_manager.py --menu` (or reinstall via `make install` and use the real waybar keybinding) and click through: `🛠 Tools` appears as one row in the main menu (no more separate DNS Leak Test/IP Info/Killswitch rows there) → open it → confirm all seven entries plus Killswitch are listed → run `⚡ Speed Test` and `🔎 Subdomain Search` end to end.

- [ ] **Step 4: Final commit if Step 3 turned up any fixes**

If everything worked with no changes needed, there is nothing to commit here — Task 15 is a verification gate, not a code task.
