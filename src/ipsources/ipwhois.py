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
