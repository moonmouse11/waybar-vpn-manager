"""Killswitch integration for the waybar menu.

Wraps the /usr/local/bin/happ-killswitch script (installed root-owned by
install.sh, driven via a NOPASSWD sudoers rule, so menu actions never
block on a password prompt).

The nft table `inet happ-ks` blocks all outbound traffic except the VPN
tunnel interfaces (happ-*, plus --iface extras), DNS (dport 53), local
networks and the VPN server IPs (Happ detect conf + endpoint IPs passed
as arguments).

Three modes (persisted in the user config):
  "off"  — killswitch managed manually, no auto behaviour
  "happ" — auto: enabled alongside Happ only
  "all"  — auto: enabled for every connect; WireGuard/OpenVPN endpoints
           are resolved from their configs and whitelisted (the menu
           toggle uses this mode). NetworkManager is not parsed yet —
           the killswitch is suspended for it and re-arms on the next
           WireGuard/OpenVPN/Happ connect.
"""

import socket
import subprocess

import config
import logutil
from providers.base import ActionResult

SCRIPT = "/usr/local/bin/happ-killswitch"


def is_enabled() -> bool:
    """Probe through the script: unprivileged `nft list` needs CAP_NET_ADMIN
    and sudoers intentionally does not grant nft, so the NOPASSWD script's
    `is-on` subcommand is the only reliable source of truth."""
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, "is-on"],
        capture_output=True,
        timeout=15,
    )
    return result.returncode == 0


def mode() -> str:
    return config.load_config().killswitch_mode


def enable(extra_ips: list[str] | None = None, ifaces: list[str] | None = None) -> ActionResult:
    """Enable the killswitch, re-detecting Happ server IPs first (they
    change when the user switches servers).

    extra_ips / ifaces are the "all"-mode additions: resolved
    WireGuard/OpenVPN endpoint addresses and tunnel interface names.
    extra_ips=None means happ-only mode, where a failed detect is fatal;
    in "all" mode a failed detect is tolerated (Happ may simply be
    disconnected) and any stale conf IPs are merged in by the script."""
    detect = _sudo("detect")
    if not detect.success and extra_ips is None:
        return detect
    args = ["on", *(extra_ips or [])]
    for iface in ifaces or []:
        args += ["--iface", iface]
    return _sudo(*args)


def disable() -> ActionResult:
    return _sudo("off")


def redetect() -> ActionResult:
    """Refresh server IP whitelist without touching the on/off state."""
    return _sudo("detect")


# ── Mode-aware helpers used by the menu / connect guard ──────────────────────


def set_mode(on: bool, extra_ips: list[str] | None = None, ifaces: list[str] | None = None) -> ActionResult:
    """Menu toggle: persist the preference ("all" when on) and apply it."""
    cfg = config.load_config()
    cfg.killswitch_mode = "all" if on else "off"
    config.save_config(cfg)
    return enable(extra_ips, ifaces) if on else disable()


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
    if mode() in ("happ", "all"):
        return enable()
    return None


def resolve_endpoint_ips(targets: list[tuple[str, str, int]]) -> list[str]:
    """IPv4 addresses for (name, host, port) targets, sorted, deduplicated.

    Unresolvable hosts are skipped with a log line — a dead endpoint must
    not abort the whole whitelist. IPv6 endpoints are skipped (the nft
    ruleset only has `ip daddr` v4 matches; a v6 literal would fail the
    whole ruleset load)."""
    ips: set[str] = set()
    for name, host, _port in targets:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
        except OSError as e:
            logutil.log(f"killswitch: cannot resolve {host} ({name}): {e}")
            continue
        if infos:
            ips.add(infos[0][4][0])
    return sorted(ips)


def _sudo(*args: str) -> ActionResult:
    result = subprocess.run(
        ["sudo", "-n", SCRIPT, *args],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = (result.stdout + result.stderr).strip()
    logutil.log(f"killswitch: {' '.join(args)} -> rc={result.returncode}: {output[:200]}")
    # error context can sit above the last line — nft prints the offending
    # rule, then a caret-only line ("    ^^^^"); keep the last meaningful one
    meaningful = [l for l in output.splitlines() if l.strip(" ^\t")]
    if result.returncode != 0:
        hint = " — run: make install" if "password" in output.lower() else ""
        reason = meaningful[-1] if meaningful else "no output"
        return ActionResult(False, f"killswitch {' '.join(args)} failed{hint}: {reason}")
    message = meaningful[-1] if meaningful else f"killswitch {' '.join(args)}: ok"
    return ActionResult(True, message)
