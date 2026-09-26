"""IPv6 DNS/traffic leak guard.

None of the providers here tunnel IPv6: happmeta.py's xray TUN inbound only
claims `autoSystemRoutingTable: ["0.0.0.0/0"]`, and killswitch.py explicitly
skips IPv6 endpoints. Any live IPv6 route on the host — including
systemd-resolved's IPv6 DNS servers — therefore bypasses every tunnel
entirely and leaks, regardless of what's configured inside the tunnel.

Rather than try to make each backend route IPv6 through the tunnel
(unverified whether Happ's bundled xray core even supports a dual-stack
TUN), this disables IPv6 system-wide for the duration of any tunnel and
restores it once nothing is connected — the same blunt approach most
consumer VPN clients take. Driven via the NOPASSWD sudoers rule so menu
actions never block on a password prompt (see install.sh).
"""

import subprocess

import logutil
from providers.base import ActionResult

_ALL_KEY = "net.ipv6.conf.all.disable_ipv6"
_DEFAULT_KEY = "net.ipv6.conf.default.disable_ipv6"


def is_disabled() -> bool:
    """Probe via an unprivileged read — no sudo needed for `sysctl -n`."""
    try:
        result = subprocess.run(
            ["sysctl", "-n", _ALL_KEY], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and result.stdout.strip() == "1"


def disable() -> ActionResult:
    """Turn IPv6 off. Idempotent — a no-op ActionResult(True, ...) when
    already off, so callers can call this on every connect unconditionally."""
    if is_disabled():
        return ActionResult(True, "ipv6 already disabled")
    return _set(1)


def enable() -> ActionResult:
    """Turn IPv6 back on. Idempotent, same as disable()."""
    if not is_disabled():
        return ActionResult(True, "ipv6 already enabled")
    return _set(0)


def _set(value: int) -> ActionResult:
    for key in (_ALL_KEY, _DEFAULT_KEY):
        result = subprocess.run(
            ["sudo", "-n", "sysctl", "-w", f"{key}={value}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = (result.stdout + result.stderr).strip()
        logutil.log(f"ipv6guard: {key}={value} -> rc={result.returncode}: {output[:200]}")
        if result.returncode != 0:
            hint = " — run: make install" if "password" in output.lower() else ""
            reason = output or "no output"
            return ActionResult(False, f"ipv6guard {key}={value} failed{hint}: {reason}")
    verb = "disabled" if value else "enabled"
    return ActionResult(True, f"ipv6 {verb}")
