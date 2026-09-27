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
