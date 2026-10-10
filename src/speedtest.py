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
from urllib.parse import urlsplit

import logutil

DURATION = 10.0  # seconds of transfer to average over
TIMEOUT = 15  # per socket operation (connect / each read)
CHUNK = 64 * 1024
# Cloudflare 403s urllib's default "Python-urllib/x.y"; Hetzner resets the
# connection on a bare "Mozilla/5.0" (fake-browser filter). An honest
# product UA passes both.
USER_AGENT = "waybar-vpn-manager/1.0"
ERROR_MAXLEN = 80  # keeps a failure row readable in the walker window


@dataclass(frozen=True)
class Service:
    name: str
    url: str


SERVICES = [
    # Cloudflare 403s above 50 MB per request (and to urllib's default
    # User-Agent — see USER_AGENT)
    Service("Cloudflare", "https://speed.cloudflare.com/__down?bytes=50000000"),
    Service("OVH (FR)", "https://proof.ovh.net/files/100Mb.dat"),
    # fsn1-speed.hetzner.com reset connections from some VPN exits; nbg1 didn't
    Service("Hetzner (DE)", "https://nbg1-speed.hetzner.com/100MB.bin"),
]


def is_valid_url(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


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
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
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
