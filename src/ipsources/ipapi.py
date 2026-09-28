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
        # ip-api.com's free tier has no HTTPS endpoint at all (verified live —
        # https://ip-api.com/json/... 403s without a paid key); only a public
        # IP is sent, no credentials, so plaintext is the accepted tradeoff
        # for staying keyless. See CLAUDE.md's reputation.py section.
        data = base.fetch_json(f"http://ip-api.com/json/{ip}?fields={FIELDS}")  # NOSONAR
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
