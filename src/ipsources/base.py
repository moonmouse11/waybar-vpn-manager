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
