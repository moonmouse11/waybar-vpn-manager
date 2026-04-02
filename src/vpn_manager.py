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

from providers import ALL_PROVIDERS
from providers.base import VPNConnection, ActionResult


WAYBAR_SIGNAL = 11


# ── Status ────────────────────────────────────────────────────────────────────

def get_status() -> dict:
    for provider in ALL_PROVIDERS:
        for conn in provider.connections():
            if conn.active:
                return {
                    "text": f" {conn.provider}: {conn.name}",
                    "tooltip": f"{conn.provider}: {conn.name}",
                    "class": "vpn-connected",
                }
    return {
        "text": " VPN",
        "tooltip": "VPN: Not connected",
        "class": "vpn-disconnected",
    }


# ── Menu ──────────────────────────────────────────────────────────────────────

def build_menu_items() -> list[tuple[str, callable]]:
    """Returns list of (label, action) pairs for the menu."""
    items = []

    for provider in ALL_PROVIDERS:
        for conn in provider.connections():
            if conn.active:
                label = f"󰅖  {conn.provider}: Disconnect {conn.name}"
                items.append((label, lambda p=provider, c=conn: p.disconnect(c)))
            else:
                label = f"󰈀  {conn.provider}: Connect {conn.name}"
                items.append((label, lambda p=provider, c=conn: p.connect(c)))

    # Import options for providers that support it
    for provider in ALL_PROVIDERS:
        if provider.name == "WireGuard":
            items.append((
                "  Import WireGuard config...",
                lambda p=provider: import_config_file(p, "WireGuard"),
            ))
        elif provider.name == "OpenVPN":
            items.append((
                "  Import OpenVPN config...",
                lambda p=provider: import_config_file(p, "OpenVPN"),
            ))

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
    args = parser.parse_args()

    if args.status:
        print(json.dumps(get_status()))
    elif args.menu:
        run_menu()


if __name__ == "__main__":
    main()
