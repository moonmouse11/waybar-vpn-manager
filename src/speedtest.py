"""Single-measurement download throughput, through whatever the current
default route is (the VPN tunnel, if one is up — or the plain uplink if
none is, unless the killswitch drops it).

Any HTTP(S) URL serving a large file works: SERVICES are public presets,
and the menu also accepts a custom URL (e.g. a file on a test stand's own
nginx, where no public service is reachable). The download is capped at
DURATION seconds, so file size only needs to be "big enough".
"""

import http.client
import time
import urllib.request
from dataclasses import dataclass

import logutil

DURATION = 10.0  # seconds of transfer to average over
TIMEOUT = 15  # per socket operation (connect / each read)
CHUNK = 64 * 1024
ERROR_MAXLEN = 80  # keeps a failure row readable in the walker window


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    url: str


SERVICES = [
    # Cloudflare 403s above 50 MB per request (and to urllib's default
    # User-Agent — a browser-like one is always sent, see measure())
    Service("cloudflare", "Cloudflare", "https://speed.cloudflare.com/__down?bytes=50000000"),
    Service("ovh", "OVH (FR)", "https://proof.ovh.net/files/100Mb.dat"),
    Service("tele2", "Tele2 (SE)", "http://speedtest.tele2.net/100MB.zip"),
]


def is_valid_url(url: str) -> bool:
    return url.startswith(("http://", "https://")) and len(url) > len("https://")


@dataclass(frozen=True)
class Measurement:
    """Exactly one of `mbps` / `error` is set."""

    mbps: float | None = None
    error: str | None = None


def measure(url: str, duration: float = DURATION) -> Measurement:
    """Mbit/s over up to `duration` seconds of download from `url`. On
    failure `error` carries a short reason for the results window (also
    logged — "Test failed" with no reason used to be undiagnosable).

    The clock starts once the response headers arrive, so DNS/TLS setup
    and time-to-first-byte don't drag the figure down."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    n = 0
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            t0 = time.perf_counter()
            dt = 0.0
            while dt < duration:
                chunk = resp.read(CHUNK)
                dt = time.perf_counter() - t0
                if not chunk:
                    break
                n += len(chunk)
    except (OSError, ValueError, http.client.HTTPException) as e:
        return _failed(url, f"{type(e).__name__}: {e}")
    if dt <= 0 or n == 0:
        return _failed(url, "no data received")
    return Measurement(mbps=n * 8 / 1_000_000 / dt)


def _failed(url: str, reason: str) -> Measurement:
    logutil.log(f"speedtest {url}: {reason}")
    return Measurement(error=reason[:ERROR_MAXLEN])
