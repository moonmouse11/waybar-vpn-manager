"""Subdomain search via crt.name (https://crt.name) — a free, keyless,
passive subdomain index fed by the public Certificate Transparency
firehose. Found during this project's DNS-leak investigation session;
purely on-demand (no background polling), so its own rate limit
(~100/window, seen via X-RateLimit-* response headers) is a non-issue for
normal use.
"""

import http.client
import urllib.parse
import urllib.request

API = "https://crt.name/v1/search"
TIMEOUT = 8


def search(domain: str) -> list[str] | None:
    """Every subdomain crt.name has on file for domain (possibly empty),
    or None on any network/parse failure. The live API returns a plain
    text, newline-separated list of hostnames — not JSON, despite the
    endpoint's shape suggesting otherwise."""
    url = f"{API}?apex={urllib.parse.quote_plus(domain)}"
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            text = resp.read().decode()
    except (OSError, ValueError, http.client.HTTPException):
        return None
    return [line.strip() for line in text.splitlines() if line.strip()]
