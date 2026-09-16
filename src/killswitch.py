"""Killswitch integration for the waybar menu.

Wraps the /usr/local/bin/happ-killswitch script (installed root-owned by
install.sh, driven via a NOPASSWD sudoers rule, so menu actions never
block on a password prompt).

The nft table `inet happ-ks` blocks all outbound traffic except the
happ-* tunnel interfaces, local networks and the Happ server IPs listed
in ~/.config/happ-killswitch.conf.

Two modes (persisted in the user config):
  "off"  — killswitch managed manually, no auto behaviour
  "happ" — auto: enabled alongside Happ, suspended while another provider
           is connected (their server IPs are not whitelisted), resumed on
           the next Happ connect
"""

import subprocess

import config
import logutil
from providers.base import ActionResult

SCRIPT = "/usr/local/bin/happ-killswitch"
TABLE = "happ-ks"


def is_enabled() -> bool:
    result = subprocess.run(
        ["nft", "list", f"table inet {TABLE}"],
        capture_output=True,
    )
    return result.returncode == 0


def mode() -> str:
    return config.load_config().killswitch_mode


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


# ── Mode-aware helpers used by the menu / connect guard ──────────────────────


def set_mode(on: bool) -> ActionResult:
    """Menu toggle: persist the preference and apply it immediately."""
    cfg = config.load_config()
    cfg.killswitch_mode = "happ" if on else "off"
    config.save_config(cfg)
    return enable() if on else disable()


def suspend_for(provider_name: str) -> ActionResult:
    """Runtime-disable for a non-Happ provider; preference is kept."""
    result = disable()
    if result.success:
        result.message = (
            f"killswitch suspended for {provider_name} (auto-resumes on next Happ connect)"
        )
    return result


def resume_for_happ() -> ActionResult | None:
    """On Happ connect: refresh whitelist / re-enable if auto mode asks for it.

    Returns None when there is nothing to do.
    """
    if is_enabled():
        return redetect()
    if mode() == "happ":
        return enable()
    return None


def _sudo(arg: str) -> ActionResult:
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, arg],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (result.stdout + result.stderr).strip()
    logutil.log(f"killswitch: {arg} -> rc={result.returncode}: {output[:200]}")
    if result.returncode != 0:
        hint = " — run: make install" if "password" in output.lower() else ""
        reason = output.splitlines()[-1] if output else "no output"
        return ActionResult(False, f"killswitch {arg} failed{hint}: {reason}")
    message = output.splitlines()[-1] if output else f"killswitch {arg}: ok"
    return ActionResult(True, message)
