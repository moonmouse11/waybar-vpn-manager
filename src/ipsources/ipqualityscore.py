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
