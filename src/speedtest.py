"""Single-measurement download throughput, through whatever the current
default route is (the VPN tunnel, if one is up) — Cloudflare's public
speed-test endpoint, no auth, the same one speed.cloudflare.com's own page
uses.
"""

import http.client
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
    except (OSError, ValueError, http.client.HTTPException):
        return None
    if dt <= 0:
        return None
    return (n / 1_000_000) / dt
