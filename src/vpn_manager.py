#!/usr/bin/env python3
"""
waybar-vpn-manager — entry point
Usage:
  vpn_manager.py --status   Output JSON status for waybar
  vpn_manager.py --menu     Open interactive walker menu
"""

import argparse
import contextlib
import getpass
import json
import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

import config
import dnsleak
import happmeta
import ipinfo
import ipsources
import ipv6guard
import killswitch
import logutil
import notifyutil
import reputation
import speedtest
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
BACK_LABEL = "‹ Back"


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
        line = conn.label
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
        "text": f" {first.label}{extra}",
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
        # every balancer member, not just the first: xray may dial any of them
        endpoints = happmeta.server_endpoints(
            connection.name, allow_fetch=False, provider_id=connection.subscription_id
        )
        if endpoints:
            # + subscription hosts: refreshing them goes through xray and is
            # often routed `direct` (Russian-hosted), which the killswitch blocks
            ips = killswitch.resolve_endpoint_ips(
                [(connection.name, host, port) for host, port in endpoints]
                + happmeta.subscription_targets()
            )
        ks_result = killswitch.resume_for_happ(extra_ips=ips)
    elif killswitch.mode() == "all" and provider.name in (
        "WireGuard",
        "AmneziaWG",
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
    _sync_ipv6_guard()
    return result


def guarded_disconnect(provider, connection: VPNConnection) -> ActionResult:
    """provider.disconnect() plus keeping the IPv6 guard in sync — every
    menu disconnect action should go through this, not provider.disconnect
    directly, so IPv6 gets restored as soon as nothing is left active."""
    result = provider.disconnect(connection)
    _sync_ipv6_guard()
    return result


def _sync_ipv6_guard() -> None:
    """IPv6 must be off while anything is tunneled (none of our providers
    route it, so it would otherwise leak straight past every tunnel) and
    back on once nothing is active."""
    if active_connections(providers=list(ALL_PROVIDERS)):
        guard = ipv6guard.disable()
    else:
        guard = ipv6guard.enable()
    if not guard.success:
        notify("IPv6 guard — warning", guard.message)


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
    _sync_ipv6_guard()
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
        return guarded_disconnect(provider, conn)
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
        if provider.name in ("WireGuard", "AmneziaWG"):
            # wg-quick/awg-quick name the interface after the profile, and
            # the kernel caps interface names at 15 chars (IFNAMSIZ=16 with
            # NUL) — longer names can never exist as wg/awg interfaces (such
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
    targets += happmeta.subscription_targets()  # refreshes must survive the killswitch
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


def _dns_leak_server_row(
    server: dict, ip_country: str = "", ip_asn: int | None = None
) -> tuple[str, callable]:
    """One row per detected resolver — the wider walker window (see
    WALKER_WIDTH) is the actual fix for these getting truncated; no need to
    collapse the list to make it fit. 'Leaked' when dnsleak.server_tags()
    finds the resolver is neither the VPN's nor a public one (ASN) or sits in
    another country than the exit IP (GEO) — wherever that country is."""
    country = (server.get("country") or "").upper()
    flag = ipinfo.flag_emoji(country)
    org = server.get("org") or server.get("asn") or ""
    label = f"{flag} {server.get('ip') or '?'}".strip()
    if org:
        label += f" · {org}"
    if dnsleak.server_tags(server, ip_country, ip_asn):
        label += "  Leaked"
    return (label, lambda: ActionResult(True, ""))


def _dns_leak_exit_row(ip_country: str, active: list[VPNConnection]) -> str:
    """Does the public IP bash.ws saw fit the active connection? Compared by
    country — the server's country comes from the reputation sweep's cache.
    The exit IP legitimately differs from the endpoint (Happ bridges,
    CDN-fronted xray), but a different country is a real red flag."""
    if not active:
        return "No VPN active — this is your real IP"
    known = [(c.name, reputation.country_of(c.name)) for c in active]
    known = [(name, cc) for name, cc in known if cc]
    if not known:
        return f"VPN: {active[0].name}"
    for name, cc in known:
        if cc == ip_country:
            return f"Exit matches {name} {ipinfo.flag_emoji(cc)}"
    name, cc = known[0]
    return f"Leaked: exit ≠ {name} {ipinfo.flag_emoji(cc)}"


def _dns_leak_ipv6_row(vpn_active: bool) -> str:
    if ipv6guard.is_disabled():
        return "IPv6: disabled"
    return "Leaked: IPv6 enabled — bypasses the tunnel" if vpn_active else "IPv6: enabled"


def _dns_leak_verdict_row(result: dict) -> str | None:
    """Own verdict over every resolver, shown next to bash.ws's. None when
    the exit IP's country and ASN are both unknown — server_tags() would
    then flag nobody, and an all-clear built on no data would be a lie."""
    servers = result["dns_servers"]
    ip_country, ip_asn = result["ip_country"], result.get("ip_asn")
    if not servers or not (ip_country or ip_asn):
        return None
    flagged = sum(1 for s in servers if dnsleak.server_tags(s, ip_country, ip_asn))
    if flagged:
        return f"Leaked: {flagged}/{len(servers)} DNS outside VPN/public resolvers"
    return "DNS via VPN or public resolvers"


def dns_leak_test_menu() -> ActionResult:
    """DNS leak test — same backend (bash.ws) as dnsleaktest.com. Runs
    synchronously (a few seconds of DNS probes) and shows the result as a
    submenu rather than a single notification, so a long DNS-server list
    stays readable instead of getting truncated in a notify-send bubble."""
    notify("DNS Leak Test", "Test started, this takes a few seconds…")
    result = dnsleak.run()
    if result is None:
        return ActionResult(False, "Test failed — no network?")

    active = active_connections()
    ip_country, ip_asn = result["ip_country"], result.get("ip_asn")
    items: list[tuple[str, callable]] = []
    if result["ip"]:
        flag = ipinfo.flag_emoji(ip_country)
        items.append((f"IP: {result['ip']} {flag}".strip(), lambda: ActionResult(True, "")))
    items.append((_dns_leak_exit_row(ip_country, active), lambda: ActionResult(True, "")))
    items.append((_dns_leak_ipv6_row(bool(active)), lambda: ActionResult(True, "")))
    if result["dns_servers"]:
        items.extend(_dns_leak_server_row(s, ip_country, ip_asn) for s in result["dns_servers"])
    else:
        items.append(("No DNS servers found", lambda: ActionResult(True, "")))
    verdict = _dns_leak_verdict_row(result)
    if verdict:
        items.append((verdict, lambda: ActionResult(True, "")))
    if result["conclusion"]:
        items.append((f"bash.ws: {result['conclusion']}", lambda: ActionResult(True, "")))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt="DNS Leak Test")
    return ActionResult(True, "")


def _ip_info_flag_row(label: str, value: bool | None) -> tuple[str, callable]:
    text = "Yes" if value else "No"
    return (f"{label}: {text}", lambda: ActionResult(True, ""))


def ip_info_menu() -> ActionResult:
    """Multi-source exit-IP report — one row group per enabled ipsources
    source (free ones on by default; keyed ones once their API key is
    set). A single ad-hoc lookup for the current public IP, not the
    background reputation sweep."""
    notify("IP Info", "Test started, this takes a few seconds…")
    findings = reputation.lookup_self(include_keyed=True)
    if not findings:
        return ActionResult(False, "Could not get IP info — no network?")

    items: list[tuple[str, callable]] = [(f"IP: {findings[0].ip}", lambda: ActionResult(True, ""))]
    for finding in findings:
        parts = [p for p in (finding.country_name, finding.org) if p]
        if finding.abuse_score is not None:
            parts.append(f"abuse {finding.abuse_score}/100")
        label = f"{finding.source}: {' · '.join(parts)}" if parts else finding.source
        items.append((label, lambda: ActionResult(True, "")))
    items.append(_ip_info_flag_row("🏢 Datacenter/Hosting", any(f.hosting for f in findings)))
    items.append(_ip_info_flag_row("🕵 Proxy/VPN detected", any(f.proxy for f in findings)))
    items.append(_ip_info_flag_row("📱 Mobile network", any(f.mobile for f in findings)))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt="IP Info")
    return ActionResult(True, "")


SPEED_TEST_TITLE = "Speed Test"  # walker prompt + progress notification title
SPEED_TEST_ALL_LABEL = "🌍 All services"
SPEED_TEST_CUSTOM_LABEL = "✏ Custom URL…"
SPEED_TEST_MAX_URLS = 5  # remembered custom URLs, newest first
# per service in "All services" — run one after another (in parallel they'd
# split the same uplink and each report a fraction of it), so this keeps
# the whole sweep around half a minute
SPEED_TEST_ALL_DURATION = 5.0


def speed_test_menu() -> ActionResult:
    """Pick a service (or all of them), then measure download throughput
    through whatever the current route is (tunnel or, with no VPN up, the
    plain uplink). Results open in their own walker window, like the DNS
    leak test — a multi-service comparison doesn't fit a notify bubble."""
    # public presets, then custom URLs remembered in config.json
    # (`speed_test_urls` — e.g. a test stand's own file server)
    targets = [("🌐", s.name, s.url) for s in speedtest.SERVICES]
    preset_urls = {s.url for s in speedtest.SERVICES}
    targets += [
        ("🔗", url, url)
        for url in config.load_config().speed_test_urls
        if url not in preset_urls  # its preset row already covers it
    ]
    every = [(name, url) for _icon, name, url in targets]
    items: list[tuple[str, callable]] = [
        (SPEED_TEST_ALL_LABEL, lambda: _run_speed_tests(every, SPEED_TEST_ALL_DURATION))
    ]
    items += [
        (f"{icon} {name}", lambda t=(name, url): _run_speed_tests([t]))
        for icon, name, url in targets
    ]
    items.append((SPEED_TEST_CUSTOM_LABEL, _speed_test_custom_url))
    items.append((BACK_LABEL, tools_menu))
    run_items(_unique_labels(items), prompt=SPEED_TEST_TITLE)
    return ActionResult(True, "")


def _speed_test_custom_url() -> ActionResult:
    url = walker_input("Speed test URL (http/https, large file)")
    if not url:
        return ActionResult(False, "No URL entered")
    if not speedtest.is_valid_url(url):
        return ActionResult(False, f"Not an http(s) URL: {url}")
    cfg = config.load_config()
    cfg.speed_test_urls = [url, *(u for u in cfg.speed_test_urls if u != url)][:SPEED_TEST_MAX_URLS]
    config.save_config(cfg)
    return _run_speed_tests([(url, url)])


def _run_speed_tests(
    targets: list[tuple[str, str]], duration: float = speedtest.DURATION
) -> ActionResult:
    """Measure each target in turn (progress via notify — the walker window
    can't update while a test runs), then show every result in one window."""
    results = []
    for i, (name, url) in enumerate(targets, 1):
        step = f"{i}/{len(targets)} · " if len(targets) > 1 else ""
        notify(SPEED_TEST_TITLE, f"{step}{name}: measuring for ~{duration:.0f} s…")
        results.append((name, speedtest.measure(url, duration)))

    noop = lambda: ActionResult(True, "")  # noqa: E731 — info rows do nothing
    active = active_connections()
    items: list[tuple[str, callable]] = [
        (_speed_test_route_row(active), noop),
        *((_speed_test_result_row(name, m), noop) for name, m in results),
    ]
    ok = [(name, m.mbps) for name, m in results if m.mbps is not None]
    if len(results) > 1 and ok:
        best = max(ok, key=lambda r: r[1])
        items.append((f"🏆 Fastest: {best[0]} ({best[1]:.1f} Mbit/s)", noop))
    if not ok and killswitch.is_enabled() and not active:
        items.append(("⚠ Killswitch is on and no VPN is active — traffic is blocked", noop))
    items.append(("🔁 Run again", lambda: _run_speed_tests(targets, duration)))
    items.append((BACK_LABEL, speed_test_menu))
    run_items(_unique_labels(items), prompt=SPEED_TEST_TITLE)
    return ActionResult(True, "")


def _speed_test_route_row(active: list[VPNConnection]) -> str:
    if not active:
        return "Route: direct (no VPN)"
    return "Route: " + ", ".join(c.label for c in active)


def _speed_test_result_row(name: str, m: speedtest.Measurement) -> str:
    if m.mbps is not None:
        return f"{name}: ⬇ {m.mbps:.1f} Mbit/s"
    return f"{name}: ✗ {m.error}"


def refresh_all_menu() -> ActionResult:
    """Force a ping sweep (every provider) + Happ subscription sync now,
    bypassing PING_MAX_AGE/SUB_MAX_AGE — request_ping_update()/
    request_subscription_update() are staleness-gated and would otherwise
    no-op if the last sweep was recent. Reputation is deliberately
    excluded (its own daily cadence + IPAPI_PACE already make it a
    multi-minute background job; forcing it from a menu click isn't
    "refresh now", it's "wait a while", which belongs to its own timer)."""
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-ping"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    subprocess.Popen(
        [sys.executable, str(Path(__file__)), "--update-subs-force"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return ActionResult(True, "Refresh started in the background")


CACHE_DIR = Path.home() / ".cache/vpn-manager"


def clear_caches_menu() -> ActionResult:
    """Every cache this project writes lives under CACHE_DIR (happmeta's
    PING_CACHE/PROVIDERS_CACHE, reputation.CACHE, ipinfo.CACHE_PATH,
    providers/base.py's RATE_CACHE) — safe to delete on demand, every reader
    already tolerates a missing file. subscription-*.json is kept: it is
    server data, refreshed in place by the subscription sweep.
    ~/.config/happ-capture/ is NOT touched — that's captured server data,
    not a cache."""
    removed = 0
    if CACHE_DIR.is_dir():
        for f in CACHE_DIR.glob("*.json"):
            if f.name.startswith("subscription-"):
                # the only offline copy of a subscription's servers: deleting
                # it empties the Happ menu until a refetch succeeds, which a
                # killswitch or a dead network can block indefinitely
                continue
            with contextlib.suppress(OSError):
                f.unlink()
                removed += 1
    return ActionResult(True, f"Cache cleared ({removed} files) — rebuilt automatically")


class Prompter(ABC):
    @abstractmethod
    def confirm(self, question: str, default: bool) -> bool: ...

    @abstractmethod
    def text(self, question: str) -> str: ...


class TerminalPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        suffix = "[Y/n]" if default else "[y/N]"
        try:
            answer = input(f"{question} {suffix} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return default
        return default if not answer else answer in ("y", "yes")

    def text(self, question: str) -> str:
        try:
            return getpass.getpass(f"{question}: ").strip()
        except (EOFError, KeyboardInterrupt):
            return ""


class WalkerPrompter(Prompter):
    def confirm(self, question: str, default: bool) -> bool:
        selected = walker_select(["Yes", "No"], prompt=question)
        return (selected == "Yes") if selected else default

    def text(self, question: str) -> str:
        return walker_input(question) or ""


def run_configure_wizard(prompter: Prompter) -> bool:
    """The provider/tool/source walk shared by --configure (TerminalPrompter,
    install.sh's last step) and ⚙ Settings (WalkerPrompter, in-menu — no
    reinstall needed). Never touches an existing config.json unless the
    user opts in via the first confirm. Returns False when the user
    declines reconfigure on an existing file; True after save."""
    if config.CONFIG_PATH.exists():
        if not prompter.confirm("Config already exists. Reconfigure?", False):
            return False
        cfg = config.load_config()
    else:
        cfg = config.Config()

    for provider in ALL_PROVIDERS:
        visible = prompter.confirm(
            f"Show {provider.name}?", cfg.provider_visible(provider.name)
        )
        cfg.providers[provider.name.lower()] = visible

    for key, label, _fn in [*TOOLS, ("killswitch", "Killswitch", None)]:
        visible = prompter.confirm(f"Show tool “{label}”?", cfg.tool_visible(key))
        cfg.tools_visible[key] = visible

    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            answer = prompter.text(
                f"{source.name} API key (Enter — keep current / skip)"
            )
            if answer:
                cfg.ip_sources.setdefault(source.key, {})["api_key"] = answer
        else:
            enabled = prompter.confirm(f"Use {source.name}?", source.is_enabled())
            cfg.ip_sources.setdefault(source.key, {})["enabled"] = enabled

    config.save_config(cfg)
    return True


def settings_menu() -> ActionResult:
    if run_configure_wizard(WalkerPrompter()):
        return ActionResult(True, "Settings saved")
    # Declined reconfigure — not a failure; run_items() maps success=False to urgent errors.
    return ActionResult(True, "Settings unchanged")


# single source of truth for both tools_menu()'s rows and the configure
# wizard's questions (key, label, action) — killswitch is handled
# separately in both places since its row reflects live on/off state
# (_killswitch_item()), not a fixed action function.
TOOLS = [
    ("dns_leak_test", "🔍 DNS Leak Test", dns_leak_test_menu),
    ("ip_info", "ℹ️ IP Info", ip_info_menu),
    ("speed_test", "⚡ Speed Test", speed_test_menu),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑 Clear Caches", clear_caches_menu),
    ("settings", "⚙ Settings", settings_menu),
]


def tools_menu() -> ActionResult:
    cfg = config.load_config()
    items = [(label, fn) for key, label, fn in TOOLS if cfg.tool_visible(key)]
    if cfg.tool_visible("killswitch"):
        items.append(_killswitch_item())
    items.append((BACK_LABEL, back_to_main))
    run_items(_unique_labels(items), prompt="Tools")
    return ActionResult(True, "")


def provider_actions(provider) -> list[tuple[str, callable]]:
    """Import / manage entries for providers that support them."""
    if provider.name in ("WireGuard", "AmneziaWG"):
        return [
            (
                f"  Import {provider.name} config...",
                lambda: import_config_file(provider, provider.name),
            ),
            (
                f"  Manage {provider.name} profiles...",
                lambda: manage_profiles(provider),
            ),
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
        label = f"{provider.name}  ({active}/{len(conns)})"
        items.append((label, lambda p=provider: provider_menu(p)))

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
            items.append((f"Disconnect: {first.label}", disconnect_all))
        else:
            items.append((f"Disconnect ALL  ({len(all_active)})", disconnect_all))

    items.append(("🛠 Tools", tools_menu))
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
    rows = [(f"↻ {conn.label}", lambda: _reconnect(conn))]
    if metrics:
        rows.append((("     " + " · ".join(metrics)), lambda: _details(conn, cfg)))
    return rows


def _details(conn: VPNConnection, cfg) -> ActionResult:
    lines = [conn.label]
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
    down = guarded_disconnect(provider, conn)
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
    reputation.request_update()
    items: list[tuple[str, callable]] = []
    for conn in provider.connections():
        info = happmeta.ping_mark(conn.name)
        suffix = f"    {info}" if info else ""
        if conn.active:
            items.append(
                (f"Disconnect {conn.name}{suffix}", lambda c=conn: guarded_disconnect(provider, c))
            )
        else:
            label = f"{conn.name}{suffix}"
            items.append((label, lambda c=conn: guarded_connect(provider, c)))
    items.extend(provider_actions(provider))
    items.append((BACK_LABEL, back_to_main))
    run_items(_unique_labels(items), prompt=provider.name)
    # The submenu already notified/refreshed; stay silent for the parent level.
    return ActionResult(True, "")


def back_to_main() -> ActionResult:
    menu_loop()
    return ActionResult(True, "")


# ── Happ: providers -> servers (with ping/protocol info) ─────────────────────


def happ_menu(provider) -> ActionResult:
    """Happ level 2: subscription providers, each leading to its servers."""
    happmeta.request_subscription_update()
    happmeta.request_ping_update()
    reputation.request_update()
    servers = happmeta.all_servers(allow_fetch=False)
    active_conns = [c for c in provider.connections() if c.active]

    # Exact match, or the unique substring match (GUI names can lack the
    # emoji prefix); ambiguous prefixes mark nothing. Matched by
    # (subscription, name) — the same name in another subscription is a
    # different server and must not light up too.
    matched = {
        (m["provider_id"], m["name"])
        for c in active_conns
        if (m := happmeta.match_server(c.name, servers, c.subscription_id))
    }
    groups: dict[str, list] = {}
    for server in servers:
        is_active = (server["provider_id"], server["name"]) in matched
        groups.setdefault(server["provider_name"], []).append(
            {
                "name": server["name"],
                "active": is_active,
                "provider_id": server["provider_id"],
                "protocol": happmeta.protocol_label(server["config"]),
            }
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
    items.append((BACK_LABEL, back_to_main))
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


def happ_provider_menu(provider, pname: str, entries: list) -> ActionResult:
    """Happ level 3: servers of one provider with ping + protocol info."""
    if not entries:
        notify("Happ", f"{pname}: no servers")
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
            parts.append(f"Traffic {traffic} / {limit}")
        expire = happmeta.fmt_expire(info.get("expire"))
        if expire != "?":
            parts.append(f"until {expire}")
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
                lines.append(f"Valid until {expire}")

            def _info_action():
                notify(f"Happ · {pname}", "\n".join(lines))
                return ActionResult(True, "")

            items.append(("ⓘ " + " · ".join(parts), _info_action))

    for entry in entries:
        conn = VPNConnection(
            name=entry["name"],
            provider="Happ",
            active=entry["active"],
            subscription_id=entry.get("provider_id"),
            subscription_name=pname,
        )
        label = f"Disconnect {conn.name}" if conn.active else conn.name
        info = happmeta.server_info_suffix(conn.name, entry.get("protocol", ""))
        if info:
            label += f"    {info}"
        if conn.active:
            items.append((label, lambda c=conn: guarded_disconnect(provider, c)))
        else:
            items.append((label, lambda c=conn: guarded_connect(provider, c)))
    items.append((BACK_LABEL, lambda: happ_menu(provider)))
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
# The default theme's window is 644px — comfortably wide labels here (DNS
# leak test / server names + ASN info) get truncated with no wrapping.
# Long-form flags only: walker's own --help warns the -w/-h shorthand
# clashes with GOption parsing ("DONT USE SHORTHAND").
WALKER_WIDTH = 900
WALKER_MAXWIDTH = 860  # content area, a bit narrower than the box for padding


def walker_select(options: list[str], prompt: str = "VPN") -> str | None:
    try:
        result = subprocess.run(
            [
                "walker",
                "-d",
                "-p",
                prompt,
                "--width",
                str(WALKER_WIDTH),
                "--maxwidth",
                str(WALKER_MAXWIDTH),
            ],
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
        notify(
            "VPN — Error",
            "walker hung — service restarted, open the menu again",
            urgent=True,
        )
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


def walker_input(prompt: str) -> str | None:
    """Single-field text input via walker (-I, dmenu-only), same widened
    window as walker_select(). None on any failure or empty input."""
    try:
        result = subprocess.run(
            [
                "walker",
                "-d",
                "-I",
                "-p",
                prompt,
                "--width",
                str(WALKER_WIDTH),
                "--maxwidth",
                str(WALKER_MAXWIDTH),
            ],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        notify("Error", "walker not found", urgent=True)
        return None
    text = result.stdout.strip()
    return text or None


def import_config_file(provider, title: str) -> ActionResult:
    path = walker_input(f"{title} config path")
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
    # title/message can carry a VPN daemon's own error text or a
    # subscription provider's server name — notifyutil cleans both
    notifyutil.send(title, message, urgent=urgent)


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
        nargs="*",
        metavar="SERVER [SUBSCRIPTION_ID]",
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
    group.add_argument(
        "--update-subs-force",
        action="store_true",
        help="Like --update-subs but bypassing the SUB_MAX_AGE cache gate (Refresh All)",
    )
    group.add_argument(
        "--update-reputation",
        action="store_true",
        help="Refresh server IP-reputation cache in the background (internal)",
    )
    group.add_argument(
        "--configure",
        action="store_true",
        help="Interactive setup wizard: providers, tools, IP sources/keys",
    )
    args = parser.parse_args()
    if args.keys_keeper is not None and args.keys_keeper[0] not in ("ss", "vless"):
        kind = args.keys_keeper[0]
        parser.error(f"argument --keys-keeper: invalid KIND {kind!r} (choose from 'ss', 'vless')")

    if args.status:
        print(json.dumps(get_status()))
    elif args.menu:
        run_menu()
    elif args.update_ip:
        ipinfo.update(args.update_ip)
    elif args.update_ping:
        happmeta.write_pings(_collect_ping_targets())
    elif args.update_reputation:
        reputation.write_reputations(_collect_ping_targets())
    elif args.update_subs:
        happmeta.update_subscriptions()
    elif args.update_subs_force:
        happmeta.update_subscriptions(force=True)
    elif args.happ_keeper is not None:
        from providers.happ import run_keeper

        run_keeper(*args.happ_keeper[:2])
    elif args.keys_keeper is not None:
        from providers.keys import run_keeper as run_keys_keeper

        run_keys_keeper(*args.keys_keeper)
    elif args.configure:
        run_configure_wizard(TerminalPrompter())


if __name__ == "__main__":
    main()
