#!/usr/bin/env python3
"""
waybar-vpn-manager — entry point
Usage:
  vpn_manager.py --status   Output JSON status for waybar
  vpn_manager.py --menu     Open interactive walker menu
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config
import ipinfo
import killswitch
import logutil
from providers import ALL_PROVIDERS
from providers.base import ActionResult, VPNConnection, iface_traffic

WAYBAR_SIGNAL = 11


def visible_providers() -> list:
    """Providers not hidden in the user config."""
    cfg = config.load_config()
    return [p for p in ALL_PROVIDERS if cfg.provider_visible(p.name)]


def active_connections(providers=None) -> list[VPNConnection]:
    return [
        conn
        for provider in (providers or visible_providers())
        for conn in provider.connections()
        if conn.active
    ]


# ── Status ────────────────────────────────────────────────────────────────────


def get_status() -> dict:
    """Aggregate ALL active connections across providers.

    waybar CSS classes: "vpn-connected" + "vpn-<provider>" per active provider,
    "vpn-disconnected" when nothing is up. Tooltip lists every active
    connection with per-interface traffic stats.
    """
    cfg = config.load_config()
    active = active_connections()

    if not active:
        return {
            "text": " VPN",
            "tooltip": "VPN: not connected",
            "class": "vpn-disconnected",
        }

    extra = f" (+{len(active) - 1})" if len(active) > 1 else ""
    classes = ["vpn-connected"]
    tooltip = []
    for conn in active:
        classes.append(f"vpn-{conn.provider.lower()}")
        line = f"{conn.provider}: {conn.name}"
        if conn.interface:
            traffic = iface_traffic(conn.interface)
            if traffic:
                line += f"\n  {traffic}"
        tooltip.append(line)

    if cfg.exit_ip_enabled:
        exit_line = ipinfo.status_line(active[0].name, cfg.exit_ip_max_age)
        if exit_line:
            tooltip.append(exit_line)
        else:
            request_ip_update(active[0].name)

    first = active[0]
    return {
        "text": f" {first.provider}: {first.name}{extra}",
        "tooltip": "\n".join(tooltip),
        "class": classes,
    }


def request_ip_update(connection_name: str):
    """Fire-and-forget background exit-IP refresh (never blocks waybar)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-ip", connection_name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


# ── Menu actions ──────────────────────────────────────────────────────────────


def guarded_connect(provider, connection: VPNConnection) -> ActionResult:
    """Connect with killswitch interplay.

    - Happ connect: refresh the server-IP whitelist; if the config asks for
      auto killswitch ("happ" mode), make sure it is enabled.
    - Other providers: suspend killswitch for the duration (their servers
      are not whitelisted); it auto-resumes on the next Happ connect.
    """
    ks_result = None
    if provider.name == "Happ":
        ks_result = killswitch.resume_for_happ()
    elif killswitch.is_enabled():
        ks_result = killswitch.suspend_for(provider.name)

    result = provider.connect(connection)
    if ks_result and not ks_result.success:
        notify("Killswitch — warning", ks_result.message)
    return result


def disconnect_all() -> ActionResult:
    stopped, failed = [], []
    # act on everything, even providers hidden from the menu
    for provider in ALL_PROVIDERS:
        for conn in provider.connections():
            if conn.active:
                result = provider.disconnect(conn)
                (stopped if result.success else failed).append(f"{provider.name}: {conn.name}")
    if failed:
        return ActionResult(False, "Failed: " + ", ".join(failed))
    message = ", ".join(stopped) if stopped else "nothing was active"
    return ActionResult(True, f"Disconnected: {message}")


def manage_profiles(provider) -> ActionResult:
    """Second-level walker menu: pick a profile, then autostart/delete."""
    conns = provider.connections()
    if not conns:
        return ActionResult(False, f"No {provider.name} profiles found")

    profile_labels = [f"{c.name}{'  (connected)' if c.active else ''}" for c in conns]
    selected = walker_select(profile_labels, prompt=f"{provider.name} profile")
    if not selected:
        return ActionResult(True, "")
    conn = next((c for c in conns if selected.startswith(c.name)), None)
    if conn is None:
        return ActionResult(False, f"Unknown profile: {selected}")

    action_labels = ["Toggle autostart", "Delete config"]
    if conn.active:
        action_labels.insert(0, "Disconnect")
    selected = walker_select(action_labels, prompt=conn.name)
    if selected == "Toggle autostart":
        return provider.toggle_autostart(conn)
    if selected == "Delete config":
        return provider.delete_config(conn)
    if selected == "Disconnect":
        return provider.disconnect(conn)
    return ActionResult(True, "")


# ── Menu ──────────────────────────────────────────────────────────────────────


def build_menu_items() -> list[tuple[str, callable]]:
    """Returns list of (label, action) pairs for the menu."""
    items = []

    pairs = [(p, c) for p in visible_providers() for c in p.connections()]
    active = [(p, c) for p, c in pairs if c.active]

    if len(active) > 1:
        items.append(("󰅖  Disconnect ALL", disconnect_all))

    for provider, conn in pairs:
        if conn.active:
            label = f"󰅖  {provider.name}: Disconnect {conn.name}"
            items.append((label, lambda p=provider, c=conn: p.disconnect(c)))
        else:
            label = f"󰈀  {provider.name}: Connect {conn.name}"
            items.append((label, lambda p=provider, c=conn: guarded_connect(p, c)))

    # Import / manage options for providers that support it
    for provider in ALL_PROVIDERS:
        if provider.name == "WireGuard":
            items.append(
                (
                    "  Import WireGuard config...",
                    lambda p=provider: import_config_file(p, "WireGuard"),
                )
            )
            items.append(
                (
                    "  Manage WireGuard profiles...",
                    lambda p=provider: manage_profiles(p),
                )
            )
        elif provider.name == "OpenVPN":
            items.append(
                (
                    "  Import OpenVPN config...",
                    lambda p=provider: import_config_file(p, "OpenVPN"),
                )
            )
        elif provider.name == "NetworkManager":
            items.append(
                (
                    "  Import VPN config into NetworkManager...",
                    lambda p=provider: import_config_file(p, "NetworkManager"),
                )
            )
            items.append(
                (
                    "  Manage NetworkManager profiles...",
                    lambda p=provider: manage_profiles(p),
                )
            )

    # Killswitch toggle (Happ TUN mode); the choice is persisted in config
    if killswitch.is_enabled() or killswitch.mode() == "happ":
        items.append(("  Killswitch: ON — click to disable", lambda: killswitch.set_mode(False)))
    else:
        items.append(
            ("  Killswitch: OFF — click to enable (Happ)", lambda: killswitch.set_mode(True))
        )

    return items


def walker_select(options: list[str], prompt: str = "VPN") -> str | None:
    try:
        result = subprocess.run(
            ["walker", "-d", "-p", prompt],
            input="\n".join(options),
            capture_output=True,
            text=True,
        )
        selected = result.stdout.strip()
        return selected if selected else None
    except FileNotFoundError:
        notify("Error", "walker not found", urgent=True)
        return None


def import_config_file(provider, title: str) -> ActionResult:
    try:
        result = subprocess.run(
            ["walker", "-d", "-I", "-p", f"{title} config path"],
            capture_output=True,
            text=True,
        )
        path = result.stdout.strip()
    except FileNotFoundError:
        notify("Error", "walker not found", urgent=True)
        return ActionResult(success=False, message="walker not found")

    if not path:
        return ActionResult(success=False, message="No path entered")
    return provider.import_config(path)


def run_menu():
    items = build_menu_items()
    if not items:
        notify("VPN", "No VPN connections available")
        return

    labels = [label for label, _ in items]
    selected = walker_select(labels)
    if not selected:
        return

    action = next((fn for label, fn in items if label == selected), None)
    if action is None:
        return

    result: ActionResult = action()
    logutil.log(f"menu: [{selected}] -> success={result.success}: {result.message}")
    if result.message:
        if result.success:
            notify("VPN", result.message)
        else:
            notify("VPN — Error", result.message, urgent=True)

    refresh_waybar()


# ── Helpers ───────────────────────────────────────────────────────────────────


def notify(title: str, message: str, urgent: bool = False):
    cmd = ["notify-send"]
    if urgent:
        cmd += ["-u", "critical"]
    cmd += [title, message]
    subprocess.run(cmd, capture_output=True)


def refresh_waybar():
    subprocess.run(["pkill", f"-RTMIN+{WAYBAR_SIGNAL}", "waybar"], capture_output=True)


# ── Main ──────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--status", action="store_true", help="Print waybar JSON status")
    group.add_argument("--menu", action="store_true", help="Open interactive menu")
    group.add_argument(
        "--update-ip",
        metavar="CONN_NAME",
        help="Refresh exit-IP cache in the background (internal)",
    )
    args = parser.parse_args()

    if args.status:
        print(json.dumps(get_status()))
    elif args.menu:
        run_menu()
    elif args.update_ip:
        ipinfo.update(args.update_ip)


if __name__ == "__main__":
    main()
