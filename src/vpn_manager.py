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
import happmeta
import ipinfo
import killswitch
import logutil
from providers import ALL_PROVIDERS
from providers.base import (
    ActionResult,
    VPNConnection,
    iface_rate,
    iface_traffic,
    sample_iface_traffic,
)

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


NO_VPN = "direct"  # pseudo-connection key for the ipinfo cache when no VPN is up


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
            # rate first (units per second, like the menu), then totals —
            # plain arrows on both rows confused "B/s" with "MiB"
            rate = iface_rate(conn.interface)
            traffic = iface_traffic(conn.interface)
            if rate:
                line += f"\n  {rate}"
            if traffic:
                line += f"\n  {traffic} total"
            sample_iface_traffic(conn.interface)  # next tick can show a rate
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

    - Happ connect: refresh the Happ server-IP whitelist; enable when the
      config asks for auto killswitch ("happ"/"all" mode).
    - "all" mode + WireGuard/OpenVPN: resolve every configured endpoint
      and rebuild the whitelist, keeping the killswitch on.
    - otherwise: suspend an enabled killswitch for the duration.
    """
    ks_result = None
    if provider.name == "Happ":
        # Under an enabled killswitch detect() finds nothing pre-connect
        # (no established xray sessions yet), so resolve the target
        # server up front and whitelist it explicitly — otherwise xray is
        # blocked from reaching it and the tunnel comes up dead.
        ips: list[str] = []
        # cache-only: a menu click must never block on a subscription fetch
        # (the background --update-subs keeps the caches fresh)
        params = happmeta.server_params(connection.name, allow_fetch=False)
        if params:
            ips = killswitch.resolve_endpoint_ips(
                [(connection.name, params["host"], params["port"])]
            )
        ks_result = killswitch.resume_for_happ(extra_ips=ips)
    elif killswitch.mode() == "all" and provider.name in (
        "WireGuard",
        "OpenVPN",
        "VLESS",
        "Shadowsocks",
    ):
        ips, ifaces = _killswitch_all_targets()
        ks_result = killswitch.enable(extra_ips=ips, ifaces=ifaces)
    elif killswitch.is_enabled():
        ks_result = killswitch.suspend_for(provider.name)

    # one tunnel at a time: tear down anything else that is up before
    # connecting (two VPNs fight over the default route and traffic splits
    # unpredictably). Same-provider server switching is handled inside the
    # providers themselves (Happ/Keys stop their previous xray first).
    others = [
        c
        for c in active_connections(providers=list(ALL_PROVIDERS))
        if not (c.provider == provider.name and c.name == connection.name)
    ]
    if others:
        down = disconnect_all()
        if not down.success:
            return down

    result = provider.connect(connection)
    if ks_result and not ks_result.success:
        notify("Killswitch — warning", ks_result.message)
    return result


def disconnect_all() -> ActionResult:
    stopped, failed = [], []
    # act on everything, even providers hidden from the menu
    for provider in ALL_PROVIDERS:
        for conn in provider.connections():
            if not conn.active:
                continue
            result = provider.disconnect(conn)
            if result.success:
                stopped.append(f"{provider.name}: {conn.name}")
            elif not any(c.active for c in provider.connections()):
                # reported failure, but nothing is up anymore — e.g. one
                # Happ disconnect stops every happd process at once
                stopped.append(f"{provider.name}: {conn.name}")
            else:
                failed.append(f"{provider.name}: {conn.name}")
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
# Two levels, omarchy-style:
#   level 1 — provider choice (WireGuard / OpenVPN / Happ / ...) + global actions
#   level 2 — connections of the chosen provider + its import/manage actions


def _killswitch_all_targets() -> tuple[list[str], list[str]]:
    """'all' mode whitelist: IPv4 of every configured WireGuard/OpenVPN/
    Keys endpoint + the tunnel interface names to allow through.

    NetworkManager endpoints are not parsed (v1) — connecting one suspends
    the killswitch instead. One broken provider must not stop the others
    (pattern: _collect_ping_targets)."""
    targets: list[tuple[str, str, int]] = []
    ifaces: list[str] = []
    for provider in ALL_PROVIDERS:
        if provider.name == "NetworkManager":
            continue  # endpoints not parsed (v1) — connecting one suspends the killswitch
        try:
            pt = provider.ping_targets()
        except Exception:
            continue
        targets += pt
        if provider.name == "WireGuard":
            # wg-quick names the interface after the profile, and the
            # kernel caps interface names at 15 chars (IFNAMSIZ=16 with
            # NUL) — longer names can never exist as wg interfaces (such
            # profiles are unused or driven by NetworkManager, which has
            # no such limit) and nft rejects the whole ruleset for them.
            ifaces += [n for n, _, _ in pt if len(n) <= 15]
            for n, _, _ in pt:
                if len(n) > 15:
                    logutil.log(f"killswitch: iface name too long, skipped: {n}")
        elif provider.name == "OpenVPN":
            if pt:
                ifaces.append("tun*")  # OpenVPN tunnel interfaces
        elif provider.name in ("VLESS", "Shadowsocks") and pt:
            ifaces.append(provider.tunnel_iface)
    return killswitch.resolve_endpoint_ips(targets), sorted(set(ifaces))


def _killswitch_toggle(on: bool) -> ActionResult:
    if not on:
        return killswitch.set_mode(False)
    ips, ifaces = _killswitch_all_targets()
    return killswitch.set_mode(True, extra_ips=ips, ifaces=ifaces)


def _killswitch_item() -> tuple[str, callable]:
    if killswitch.is_enabled() or killswitch.mode() in ("happ", "all"):
        return ("  Killswitch: ON — click to disable", lambda: _killswitch_toggle(False))
    return ("  Killswitch: OFF — click to enable (all)", lambda: _killswitch_toggle(True))


def provider_actions(provider) -> list[tuple[str, callable]]:
    """Import / manage entries for providers that support them."""
    if provider.name == "WireGuard":
        return [
            ("  Import WireGuard config...", lambda: import_config_file(provider, "WireGuard")),
            ("  Manage WireGuard profiles...", lambda: manage_profiles(provider)),
        ]
    if provider.name == "OpenVPN":
        return [("  Import OpenVPN config...", lambda: import_config_file(provider, "OpenVPN"))]
    if provider.name in ("VLESS", "Shadowsocks"):
        return [("  Import key...", lambda: import_config_file(provider, provider.name))]
    if provider.name == "NetworkManager":
        return [
            (
                "  Import VPN config into NetworkManager...",
                lambda: import_config_file(provider, "NetworkManager"),
            ),
            ("  Manage NetworkManager profiles...", lambda: manage_profiles(provider)),
        ]
    return []


def menu_loop() -> ActionResult:
    """Level 1: the active connection with metrics, providers to pick from,
    quick disconnect, and the killswitch toggle — always the last row."""
    items: list[tuple[str, callable]] = []

    all_active = active_connections(providers=list(ALL_PROVIDERS))
    if all_active:
        items.extend(_current_connection_items(all_active[0]))
    else:
        ip_row = _no_vpn_ip_item()
        if ip_row:
            items.append(ip_row)

    for provider in visible_providers():
        conns = provider.connections()
        if not conns:
            continue
        active = sum(1 for c in conns if c.active)
        items.append((f"{provider.name}  ({active}/{len(conns)})", lambda p=provider: provider_menu(p)))

    # Empty providers are hidden (level 1 lists providers with connections);
    # the empty key-provider import rows below are opt-in via
    # show_empty_providers (a key of either kind lands under its protocol).
    cfg = config.load_config()
    for keys_prov in visible_providers():
        if keys_prov.name not in ("VLESS", "Shadowsocks") or keys_prov.connections():
            continue
        if not cfg.show_empty_providers:
            break
        items.append(
            (
                f"{keys_prov.name}  (no servers — click to import)",
                lambda p=keys_prov: import_config_file(p, p.name),
            )
        )

    if all_active:
        if len(all_active) == 1:
            first = all_active[0]
            items.append((f"Disconnect: {first.provider}: {first.name}", disconnect_all))
        else:
            items.append((f"Disconnect ALL  ({len(all_active)})", disconnect_all))

    items.append(_killswitch_item())  # always the last row
    return run_items(items, prompt="VPN")


def _current_connection_items(conn: VPNConnection) -> list[tuple[str, callable]]:
    """First menu rows: what is connected + live metrics. Row 1 reconnects
    the server; row 2 (metrics, indented) shows the full detail card.
    dmenu rows are single-line, so the metrics get their own row instead
    of being truncated by the walker window width."""
    cfg = config.load_config()
    metrics = []
    rate = iface_rate(conn.interface)
    if rate:
        metrics.append(rate)
    if cfg.exit_ip_enabled:
        exit_line = ipinfo.status_line(conn.name, cfg.exit_ip_max_age)
        if exit_line:
            metrics.append(exit_line.removeprefix("Exit: "))
        else:
            request_ip_update(conn.name)
    rows = [(f"↻ {conn.provider}: {conn.name}", lambda: _reconnect(conn))]
    if metrics:
        rows.append((("     " + " · ".join(metrics)), lambda: _details(conn, cfg)))
    return rows


def _details(conn: VPNConnection, cfg) -> ActionResult:
    lines = [f"{conn.provider}: {conn.name}"]
    if conn.interface:
        live = iface_rate(conn.interface)
        totals = iface_traffic(conn.interface)
        if live:
            lines.append(live)
        if totals:
            lines.append(totals)
    exit_line = ipinfo.status_line(conn.name, cfg.exit_ip_max_age)
    if exit_line:
        lines.append(exit_line)
    notify("VPN — connection", "\n".join(lines))
    return ActionResult(True, "")


def _reconnect(conn: VPNConnection) -> ActionResult:
    provider = next((p for p in ALL_PROVIDERS if p.name == conn.provider), None)
    if provider is None:
        return ActionResult(False, f"Unknown provider: {conn.provider}")
    down = provider.disconnect(conn)
    if not down.success:
        return down
    return guarded_connect(provider, conn)


def _no_vpn_ip_item() -> tuple[str, callable] | None:
    """Not connected: the first row shows the real public IP (cache-first —
    the --status tick is not running to refresh it, so trigger a fetch when
    stale). Click re-fetches and shows the full line."""
    cfg = config.load_config()
    if not cfg.exit_ip_enabled:
        return None
    exit_line = ipinfo.status_line(NO_VPN, cfg.exit_ip_max_age)
    if exit_line is None:
        request_ip_update(NO_VPN)
        label = "● No VPN"
    else:
        label = f"● No VPN · {exit_line.removeprefix('Exit: ')}"

    def _refresh() -> ActionResult:
        line = ipinfo.status_line(NO_VPN, cfg.exit_ip_max_age)
        if line is None:
            request_ip_update(NO_VPN)
            return ActionResult(True, "IP refresh started — reopen the menu to see it")
        notify("VPN", line)
        return ActionResult(True, "")

    return (label, _refresh)


def provider_menu(provider) -> ActionResult:
    """Level 2: connections of one provider, plus its actions."""
    if provider.name == "Happ":
        return happ_menu(provider)

    happmeta.request_ping_update()
    items: list[tuple[str, callable]] = []
    for conn in provider.connections():
        mark = happmeta.ping_mark(conn.name)
        suffix = f"    {mark}" if mark else ""
        if conn.active:
            items.append((f"Disconnect {conn.name}{suffix}", lambda c=conn: provider.disconnect(c)))
        else:
            items.append((f"Connect {conn.name}{suffix}", lambda c=conn: guarded_connect(provider, c)))
    items.extend(provider_actions(provider))
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt=provider.name)
    # The submenu already notified/refreshed; stay silent for the parent level.
    return ActionResult(True, "")


def back_to_main() -> ActionResult:
    menu_loop()
    return ActionResult(True, "")


# ── Happ: providers -> servers (with ping/protocol info) ─────────────────────


def happ_menu(provider) -> ActionResult:
    """Happ level 2: subscription providers, each leading to its servers."""
    happmeta.request_ping_update()
    servers = happmeta.all_servers()
    active_names = {c.name for c in provider.connections() if c.active}

    # Exact match, or the unique substring match (GUI names can lack the
    # emoji prefix); ambiguous prefixes mark nothing.
    matched = {m["name"] for a in active_names if (m := happmeta.match_server(a, servers))}
    groups: dict[str, list] = {}
    for server in servers:
        is_active = server["name"] in matched
        groups.setdefault(server["provider_name"], []).append(
            {"name": server["name"], "active": is_active, "provider_id": server["provider_id"]}
        )

    items: list[tuple[str, callable]] = []
    for pname, group in groups.items():
        active = sum(1 for g in group if g["active"])
        summary = happmeta.provider_ping_summary([g["name"] for g in group])
        suffixes = []
        if active:
            suffixes.append(f"{active}/{len(group)}")
        if summary:
            suffixes.append(summary)
        label = pname
        if suffixes:
            label += "  (" + " · ".join(suffixes) + ")"
        items.append((label, lambda p=pname, g=group: happ_provider_menu(provider, p, g)))
    items.append(("  Refresh subscriptions", _refresh_subscriptions))
    items.append(("‹ Back", back_to_main))
    run_items(items, prompt="Happ")


def _refresh_subscriptions() -> ActionResult:
    """Manual Happ subscription refresh — fire-and-forget (fetches can take
    tens of seconds); the menu rebuilds with fresh servers on next open."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-subs"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    notify("Happ", "Subscription refresh started — reopen the menu in a few seconds")
    return ActionResult(True, "")
    return ActionResult(True, "")


def happ_provider_menu(provider, pname: str, entries: list) -> ActionResult:
    """Happ level 3: servers of one provider with ping + protocol info."""
    if not entries:
        notify("Happ", f"{pname}: нет серверов")
        return ActionResult(True, "")
    items: list[tuple[str, callable]] = []

    # Panel card info (traffic/expiry) from the subscription cache — the
    # first "ⓘ" entry only notifies, it is not connectable.
    sub_id = next((e.get("provider_id") for e in entries if e.get("provider_id")), None)
    info = happmeta.subscription_info(sub_id) if sub_id else None
    if info:
        parts = []
        traffic = happmeta.fmt_traffic(info.get("download"))
        limit = happmeta.fmt_limit(info.get("total"))
        if traffic != "?" or limit != "∞":
            parts.append(f"Трафик {traffic} / {limit}")
        expire = happmeta.fmt_expire(info.get("expire"))
        if expire != "?":
            parts.append(f"до {expire}")
        if parts:
            lines = []
            if info.get("title"):
                lines.append(str(info["title"]))
            lines.append(
                f"↓ {happmeta.fmt_traffic(info.get('download'))} · "
                f"↑ {happmeta.fmt_traffic(info.get('upload'))} / "
                f"{happmeta.fmt_limit(info.get('total'))}"
            )
            if expire != "?":
                lines.append(f"Действует до {expire}")

            def _info_action():
                notify(f"Happ · {pname}", "\n".join(lines))
                return ActionResult(True, "")

            items.append(("ⓘ " + " · ".join(parts), _info_action))

    for entry in entries:
        conn = VPNConnection(name=entry["name"], provider="Happ", active=entry["active"])
        icon = "Disconnect" if conn.active else "Connect"
        label = f"{icon} {conn.name}"
        info = happmeta.server_info_suffix(conn.name)
        if info:
            label += f"    {info}"
        if conn.active:
            items.append((label, lambda c=conn: provider.disconnect(c)))
        else:
            items.append((label, lambda c=conn: guarded_connect(provider, c)))
    items.append(("‹ Back", lambda: happ_menu(provider)))
    run_items(_unique_labels(items), prompt=pname[:40])
    return ActionResult(True, "")


def _unique_labels(items: list[tuple[str, callable]]) -> list[tuple[str, callable]]:
    """Disambiguate repeated labels so every menu entry stays reachable.

    Two servers can render identically (same remarks + same info suffix) and
    walker picks by label text — without this the later entry could never be
    selected. First occurrence keeps its label; repeats get " (2)", " (3)"…"""
    seen: set[str] = set()
    counts: dict[str, int] = {}
    unique = []
    for label, action in items:
        if label not in seen:
            seen.add(label)
            unique.append((label, action))
            continue
        # loop the suffix upward: a generated " (2)" can collide with a
        # genuine later label like "Same (2)"
        n = counts.get(label, 1) + 1
        candidate = f"{label} ({n})"
        while candidate in seen:
            n += 1
            candidate = f"{label} ({n})"
        counts[label] = n
        seen.add(candidate)
        unique.append((candidate, action))
    return unique


def run_items(items: list[tuple[str, callable]], prompt: str) -> ActionResult:
    """Show one walker menu, run the chosen action, notify + refresh waybar."""
    if not items:
        notify("VPN", "Nothing available")
        return ActionResult(False, "nothing available")

    selected = walker_select([label for label, _ in items], prompt=prompt)
    if not selected:
        return ActionResult(True, "")

    # walker returns the selected line with surrounding whitespace trimmed
    # (labels like "  Killswitch: …" keep their indent for display only),
    # so match stripped-to-stripped — no two labels may differ only in
    # surrounding whitespace.
    action = next((fn for label, fn in items if label.strip() == selected), None)
    if action is None:
        logutil.log(f"menu [{prompt}]: no action matches [{selected!r}]")
        return ActionResult(True, "")

    result: ActionResult = action()
    logutil.log(f"menu [{prompt}]: [{selected}] -> success={result.success}: {result.message}")
    if result.message:
        if result.success:
            notify("VPN", result.message)
        else:
            notify("VPN — Error", result.message, urgent=True)

    refresh_waybar()
    return result


WALKER_TIMEOUT = 120  # seconds — a wedged walker service must not hang the menu forever


def walker_select(options: list[str], prompt: str = "VPN") -> str | None:
    try:
        result = subprocess.run(
            ["walker", "-d", "-p", prompt],
            input="\n".join(options),
            capture_output=True,
            text=True,
            timeout=WALKER_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        # the walker gapplication-service occasionally wedges: no window and
        # the client hangs forever. SIGKILL the service (it ignores SIGTERM)
        # — dbus activation brings up a fresh one on the next invocation.
        logutil.log(f"walker timed out after {WALKER_TIMEOUT}s — restarting the service")
        subprocess.run(["pkill", "-9", "-f", "walker --gapplication-service"], capture_output=True)
        subprocess.run(["pkill", "-f", "walker -d"], capture_output=True)
        notify("VPN — Error", "walker завис — сервис перезапущен, откройте меню ещё раз", urgent=True)
        return None
    except FileNotFoundError:
        notify("Error", "walker not found", urgent=True)
        return None
    # rstrip('\n') only: the trailing newline is walker's, the rest of
    # the line is the user's selection.
    selected = result.stdout.rstrip("\n")
    if not selected:
        logutil.log("walker returned no selection")
    return selected if selected else None


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
    menu_loop()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _collect_ping_targets() -> list[tuple[str, str, int]]:
    """Happ + every provider's ping targets for one --update-ping sweep.

    One broken provider must not stop the others (pattern:
    happmeta.update_subscriptions), so a raising ping_targets() is skipped."""
    targets = happmeta.ping_targets()
    for provider in ALL_PROVIDERS:
        try:
            targets += provider.ping_targets()
        except Exception:
            continue
    return targets


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
    group.add_argument(
        "--happ-keeper",
        nargs="?",
        const="",
        metavar="SERVER",
        help="Hold the happd session that owns the xray process (internal)",
    )
    group.add_argument(
        "--keys-keeper",
        nargs=2,
        metavar=("KIND", "SERVER_ID"),
        help="Hold the happd session that owns a key xray process (internal)",
    )
    group.add_argument(
        "--update-ping",
        action="store_true",
        help="Refresh Happ server ping cache in the background (internal)",
    )
    group.add_argument(
        "--update-subs",
        action="store_true",
        help="Refresh Happ subscription caches in the background (internal)",
    )
    args = parser.parse_args()

    if args.status:
        print(json.dumps(get_status()))
    elif args.menu:
        run_menu()
    elif args.update_ip:
        ipinfo.update(args.update_ip)
    elif args.update_ping:
        happmeta.write_pings(_collect_ping_targets())
    elif args.update_subs:
        happmeta.update_subscriptions()
    elif args.happ_keeper is not None:
        from providers.happ import run_keeper

        run_keeper(args.happ_keeper or None)
    elif args.keys_keeper is not None:
        from providers.keys import run_keeper as run_keys_keeper

        run_keys_keeper(*args.keys_keeper)


if __name__ == "__main__":
    main()
