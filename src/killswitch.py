"""Killswitch integration for the waybar menu.

Wraps the /usr/local/bin/happ-killswitch script (installed root-owned by
install.sh, driven via a NOPASSWD sudoers rule, so menu actions never
block on a password prompt).

The nft table `inet happ-ks` blocks all outbound traffic except the
happ-* tunnel interfaces, local networks and the Happ server IPs listed
in ~/.config/happ-killswitch.conf.
"""

import subprocess

from providers.base import ActionResult

SCRIPT = "/usr/local/bin/happ-killswitch"
TABLE = "happ-ks"


def is_enabled() -> bool:
    result = subprocess.run(
        ["nft", "list", f"table inet {TABLE}"],
        capture_output=True,
    )
    return result.returncode == 0


def enable() -> ActionResult:
    """Enable killswitch, re-detecting Happ server IPs first (they change
    when the user switches servers)."""
    detect = _sudo("detect")
    if not detect.success:
        return detect
    return _sudo("on")


def disable() -> ActionResult:
    return _sudo("off")


def redetect() -> ActionResult:
    """Refresh server IP whitelist without touching the on/off state."""
    return _sudo("detect")


def _sudo(arg: str) -> ActionResult:
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, arg],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        hint = " — run: make install" if "password" in output.lower() else ""
        reason = output.splitlines()[-1] if output else "no output"
        return ActionResult(False, f"killswitch {arg} failed{hint}: {reason}")
    message = output.splitlines()[-1] if output else f"killswitch {arg}: ok"
    return ActionResult(True, message)
