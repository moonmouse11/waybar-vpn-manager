import pytest

import config
import vpn_manager
from ipsources.base import IPFinding
from providers.base import ActionResult, VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns
        self.connected = []
        self.disconnected = []

    def connections(self):
        return self._conns

    def connect(self, conn):
        self.connected.append(conn.name)
        return ActionResult(True, f"connected {conn.name}")

    def disconnect(self, conn):
        self.disconnected.append(conn.name)
        return ActionResult(True, f"disconnected {conn.name}")


def patch_menu_env(monkeypatch, providers, picks):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", providers)
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: config.Config())
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    # deterministic default: the real ~/.cache/vpn-manager/reputation.json
    # could carry real entries from this machine's own use of the feature
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    # real values only where a test overrides these after calling us (e.g. the
    # metrics-row test below) — real `ip` may be absent (containerized CI)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", lambda iface: None)
    iterator = iter(picks)
    monkeypatch.setattr(
        vpn_manager, "walker_select", lambda options, prompt="VPN": next(iterator, None)
    )


def test_level1_shows_providers_with_counts(monkeypatch):
    wg = FakeProvider(
        "WireGuard",
        [
            VPNConnection(name="a", provider="WireGuard", active=True),
            VPNConnection(name="b", provider="WireGuard", active=False),
        ],
    )
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=False)])
    picks = iter([None])  # user escapes
    seen = []
    patch_menu_env(monkeypatch, [wg, happ], picks=[])
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or next(picks, None)),
    )
    vpn_manager.run_menu()
    options = seen[0]
    assert "WireGuard  (1/2)" in options  # active count suffix
    assert "Happ  (0/1)" in options  # inactive providers show a zero count too
    assert "Disconnect ALL" not in options  # only one active connection
    assert sum(o in ("WireGuard  (1/2)", "Happ  (0/1)") for o in options) == 2


def test_happ_provider_menu_disambiguates_duplicate_labels(monkeypatch):
    """Two servers with identical rendered labels must both be reachable."""

    class RecordingProvider:
        name = "Happ"

        def __init__(self):
            self.connected = []

        def connections(self):
            return []

        def connect(self, conn):
            self.connected.append(conn)
            return ActionResult(True, "ok")

        def disconnect(self, conn):
            return ActionResult(True, "ok")

    provider = RecordingProvider()
    entries = [{"name": "Same", "active": False}, {"name": "Same", "active": False}]

    from types import SimpleNamespace

    made = []
    monkeypatch.setattr(
        vpn_manager,
        "VPNConnection",
        lambda **kw: (made.append(SimpleNamespace(**kw)) or made[-1]),
    )
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [provider])
    monkeypatch.setattr(vpn_manager.happmeta, "server_info_suffix", lambda name, protocol="": "")
    monkeypatch.setattr(vpn_manager.happmeta, "server_params", lambda name, **kw: None)
    monkeypatch.setattr(vpn_manager.killswitch, "resume_for_happ", lambda extra_ips=None: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    picks = iter(["Same (2)"])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or next(picks, None)),
    )

    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["Same", "Same (2)", "‹ Back"]
    # picking the disambiguated label must run the SECOND entry's action
    assert provider.connected == [made[1]]


def _happ_menu_setup(monkeypatch, tmp_path, pings):
    """Drive happ_menu with stubbed servers; return the captured option list."""
    servers = [
        {"name": "s1", "provider_name": "P1", "provider_id": "1", "config": {}},
        {"name": "s2", "provider_name": "P1", "provider_id": "1", "config": {}},
        {"name": "s3", "provider_name": "P2", "provider_id": "2", "config": {}},
    ]
    provider = FakeProvider(
        "Happ", [VPNConnection(name="s1", provider="Happ", active=True)]
    )
    monkeypatch.setattr(vpn_manager.happmeta, "request_ping_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "all_servers", lambda allow_fetch=True: servers)
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", ping_file)
    if pings is not None:
        ping_file.write_text(pings)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.happ_menu(provider)
    return seen[0]


def test_happ_provider_menu_labels_show_availability(monkeypatch, tmp_path):
    """Server labels carry the Happ GUI ✓/✗ availability marks."""

    class IdleProvider:
        name = "Happ"

        def connect(self, conn):
            return ActionResult(True, "ok")

        def disconnect(self, conn):
            return ActionResult(True, "ok")

    import json
    import time

    now = time.time()
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", ping_file)
    ping_file.write_text(
        json.dumps(
            {
                "up": {"ms": 12.0, "at": now},
                "down": {"ms": None, "at": now},
                "unknown": {"ms": 7.0, "at": now - 9999},  # stale -> unmarked
            }
        )
    )
    monkeypatch.setattr(vpn_manager.happmeta, "server_params", lambda name: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )

    entries = [
        {"name": "up", "active": False},
        {"name": "down", "active": False},
        {"name": "unknown", "active": False},
    ]
    vpn_manager.happ_provider_menu(IdleProvider(), "P", entries)
    assert "✓ 12 ms" in seen[0][0]
    assert "⛔" in seen[0][1]
    assert seen[0][2] == "unknown"  # stale -> no mark at all





def test_happ_menu_provider_labels_include_ping_summary(monkeypatch, tmp_path):
    import json
    import time

    now = time.time()
    pings = json.dumps(
        {
            "s1": {"ms": 10.0, "at": now},
            "s2": {"ms": 30.0, "at": now},
            "s3": {"ms": 5.0, "at": now - 9999},  # stale: P2 has no fresh data
        }
    )
    options = _happ_menu_setup(monkeypatch, tmp_path, pings)
    assert "P1  (1/2 · ✓ 2/2 · ⌀20ms)" in options
    assert "P2" in options  # no fresh pings -> old plain label
    assert not any(o.startswith("P2  (") for o in options)
    assert options[-1] == "‹ Back"


def test_happ_menu_provider_label_without_ping_data(monkeypatch, tmp_path):
    options = _happ_menu_setup(monkeypatch, tmp_path, None)  # no cache file at all
    assert "P1  (1/2)" in options  # old format: active suffix only
    assert "P2" in options


def test_happ_menu_never_blocks_on_the_network(monkeypatch):
    """Regression: happ_menu() must read all_servers() cache-only and kick
    off the background refresh, exactly like providers/happ.py's --status
    path — it must NEVER call the network-fetching default (allow_fetch=True
    fetches every stale subscription synchronously; measured 15s against a
    real stale cache, see CLAUDE.md)."""
    provider = FakeProvider("Happ", [])
    monkeypatch.setattr(vpn_manager.happmeta, "request_ping_update", lambda: None)
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    calls = []
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "request_subscription_update",
        lambda: calls.append("request_subscription_update"),
    )

    def fake_all_servers(allow_fetch=True):
        calls.append(("all_servers", allow_fetch))
        if allow_fetch:
            raise AssertionError("happ_menu() must never fetch subscriptions synchronously")
        return []

    monkeypatch.setattr(vpn_manager.happmeta, "all_servers", fake_all_servers)
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": None)

    vpn_manager.happ_menu(provider)

    assert "request_subscription_update" in calls
    assert ("all_servers", False) in calls


def test_two_level_connect(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard  (0/1)", "nl"])
    vpn_manager.run_menu()
    assert wg.connected == ["nl"]


def test_two_level_disconnect_active(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=True)])
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard  (1/1)", "Disconnect nl"])
    vpn_manager.run_menu()
    assert wg.disconnected == ["nl"]





def test_back_returns_to_level1(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    # level1 -> WireGuard, level2 -> Back, level1 -> escape
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard  (0/1)", "‹ Back", None])
    vpn_manager.run_menu()
    assert wg.connected == []


class HappLikeProvider:
    """One disconnect stops everything (like Happ stopping all happd
    processes); later disconnect calls then report 'not connected'."""

    name = "Happ"

    def __init__(self):
        self.calls = 0

    def connections(self):
        active = self.calls == 0
        return [
            VPNConnection(name="Germany", provider="Happ", active=active),
            VPNConnection(name="Germany 4", provider="Happ", active=active),
        ]

    def connect(self, conn):
        return ActionResult(True, "connected")

    def disconnect(self, conn):
        self.calls += 1
        if self.calls == 1:
            return ActionResult(True, "Disconnected: xray-core")
        return ActionResult(False, "Happ is not connected")


def test_disconnect_all_treats_not_connected_as_stopped(monkeypatch):
    happ = HappLikeProvider()
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [happ])
    result = vpn_manager.disconnect_all()
    assert result.success, result.message
    assert "Failed" not in result.message


def test_level1_active_count_label(monkeypatch):
    wg = FakeProvider(
        "WireGuard",
        [
            VPNConnection(name="a", provider="WireGuard", active=True),
            VPNConnection(name="b", provider="WireGuard", active=False),
        ],
    )
    picks = iter(["WireGuard  (1/2)", None])
    seen_prompts = []
    patch_menu_env(monkeypatch, [wg], picks=[])
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (
            seen_prompts.append((prompt, list(options))) or next(picks, None)
        ),
    )
    vpn_manager.run_menu()
    level1_options = seen_prompts[0][1]
    assert "WireGuard  (1/2)" in level1_options
    assert "🛠 Tools" in level1_options


def test_killswitch_all_mode_arms_wg(monkeypatch, tmp_path):
    """'all' mode: a WireGuard connect rebuilds the whitelist (endpoints +
    tunnel ifaces) instead of suspending the killswitch."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(
        vpn_manager, "_killswitch_all_targets", lambda: (["1.2.3.4"], ["nl", "tun*"])
    )
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "enable",
        lambda **kw: calls.append(kw) or ActionResult(True, "on"),
    )
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert wg.connected == ["nl"]
    assert calls == [{"extra_ips": ["1.2.3.4"], "ifaces": ["nl", "tun*"]}]


def test_guarded_connect_all_mode_suspends_for_nm(monkeypatch, tmp_path):
    """NetworkManager has no endpoint parser (v1): the killswitch is
    suspended for it even in 'all' mode."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = vpn_manager.killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    vpn_manager.killswitch.config.save_config(cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    suspended = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "suspend_for",
        lambda name: suspended.append(name) or ActionResult(True, "suspended"),
    )
    nm = FakeProvider(
        "NetworkManager", [VPNConnection(name="office", provider="NetworkManager", active=False)]
    )
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [nm])
    result = vpn_manager.guarded_connect(nm, nm.connections()[0])
    assert result.success
    assert suspended == ["NetworkManager"]


def test_guarded_connect_off_mode_suspends_when_enabled(monkeypatch, tmp_path):
    """mode 'off' + killswitch on manually: other providers still suspend it."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: True)
    suspended = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "suspend_for",
        lambda name: suspended.append(name) or ActionResult(True, "suspended"),
    )
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert suspended == ["WireGuard"]


def test_killswitch_all_targets_gathers_wg_and_ovpn_only(monkeypatch):
    """Only WireGuard/OpenVPN endpoints feed the 'all' whitelist; wg profile
    names become allowed interfaces, OpenVPN gets the tun* glob."""

    class PtProvider(FakeProvider):
        def __init__(self, name, targets):
            super().__init__(name, [])
            self._targets = targets

        def ping_targets(self):
            return self._targets

    wg = PtProvider("WireGuard", [("nl", "93.184.216.34", 51820)])
    # >15 chars: never a valid wg interface name (kernel IFNAMSIZ) — the
    # iface is filtered out, but its endpoint IP still joins the whitelist
    # (the config may be driven by NetworkManager, which has no such cap).
    wg_long = PtProvider("WireGuard", [("ThinkPadNetherland", "93.184.216.37", 51820)])
    ovpn = PtProvider("OpenVPN", [("de", "93.184.216.35", 1194)])
    nm = PtProvider("NetworkManager", [("office", "93.184.216.36", 443)])
    broken = PtProvider("WireGuard", [])
    broken.ping_targets = lambda: (_ for _ in ()).throw(OSError("boom"))
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg, wg_long, ovpn, nm, broken])
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resolve_endpoint_ips",
        lambda targets: sorted(host for _, host, _ in targets),
    )
    monkeypatch.setattr(
        vpn_manager.happmeta, "subscription_targets", lambda: [("P", "93.184.216.40", 443)]
    )
    ips, ifaces = vpn_manager._killswitch_all_targets()
    # NM endpoint excluded; the Happ subscription host joins so refreshes still work
    assert ips == ["93.184.216.34", "93.184.216.35", "93.184.216.37", "93.184.216.40"]
    assert ifaces == ["nl", "tun*"]  # wg profile name + OpenVPN glob; long name filtered


def test_happ_connect_passes_resolved_server_ip(monkeypatch, tmp_path):
    """guarded_connect(Happ) resolves the target server and hands its IP to
    resume_for_happ — otherwise the killswitch blocks xray from the server."""
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=False)])
    patch_menu_env(monkeypatch, [happ], picks=[])
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "server_endpoints",
        lambda name, **kw: [("de.example.com", 443), ("de2.example.com", 36106)],
    )
    monkeypatch.setattr(
        vpn_manager.happmeta, "subscription_targets", lambda: [("P", "sub.example.ru", 443)]
    )
    resolved = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resolve_endpoint_ips",
        lambda t: resolved.append(t) or ["2.26.86.35", "3.3.3.3"],
    )
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resume_for_happ",
        lambda extra_ips=None: calls.append(extra_ips) or ActionResult(True, "ok"),
    )
    result = vpn_manager.guarded_connect(happ, happ.connections()[0])
    assert result.success
    # every balancer member is whitelisted, not just the first one — plus the
    # subscription hosts, so refreshing them still works under the killswitch
    assert [host for _, host, _ in resolved[0]] == [
        "de.example.com",
        "de2.example.com",
        "sub.example.ru",
    ]
    assert calls == [["2.26.86.35", "3.3.3.3"]]


def test_walker_timeout_restarts_service(monkeypatch):
    """A wedged walker (no window, client hangs) must not hang the menu
    forever: timeout -> SIGKILL the service -> error notification."""
    import subprocess

    ran = []

    def fake_run(cmd, **kwargs):
        ran.append(cmd)
        if "walker" in cmd and "-d" in cmd:
            raise subprocess.TimeoutExpired(cmd, 1)
        class R:
            returncode = 0
        return R()

    notified = []
    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: notified.append(a))
    assert vpn_manager.walker_select(["a", "b"]) is None
    assert any("walker hung" in str(n) for n in notified)
    assert any("pkill" in str(c) and "-9" in c for c in ran)  # SIGKILL on the service


def test_walker_select_passes_width_flags(monkeypatch):
    """Regression: the default theme's window is too narrow for our longer
    labels (DNS leak test / server + ASN info), which walker truncates with
    no wrapping — must always ask for a wider window."""
    captured = {}

    class R:
        stdout = "a\n"

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return R()

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    vpn_manager.walker_select(["a", "b"])
    cmd = captured["cmd"]
    assert "--width" in cmd
    assert cmd[cmd.index("--width") + 1] == str(vpn_manager.WALKER_WIDTH)
    assert "--maxwidth" in cmd
    assert cmd[cmd.index("--maxwidth") + 1] == str(vpn_manager.WALKER_MAXWIDTH)


def test_level1_layout_connected(monkeypatch):
    """Menu order: current connection (first, with metrics) → providers →
    quick disconnect, Tools ALWAYS the last row."""
    wg = FakeProvider(
        "WireGuard",
        [VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")],
    )
    patch_menu_env(monkeypatch, [wg], picks=[])
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: "↓ 2.0 MiB/s ↑ 512.0 KiB/s")
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda name, age: "Exit: 1.2.3.4 🇩🇪")
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.run_menu()
    options = seen[0]
    assert options[0].startswith("↻ WireGuard: nl")
    assert options[1] == "     ↓ 2.0 MiB/s ↑ 512.0 KiB/s · 1.2.3.4 🇩🇪"  # metrics row
    assert "Disconnect: WireGuard: nl" in options
    assert options[-1] == "🛠 Tools"


def test_connect_disconnects_other_tunnels(monkeypatch):
    """One tunnel at a time: connecting while another provider is up tears
    the old one down first (two VPNs fight over the default route)."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=True)])
    patch_menu_env(monkeypatch, [wg, happ], picks=[])
    result = vpn_manager.guarded_connect(wg, wg.connections()[0])
    assert result.success
    assert wg.connected == ["nl"]
    assert happ.disconnected == ["de"]  # torn down before the new connect


def test_reconnect_row_drops_and_reconnects(monkeypatch):
    """Selecting the current-connection row is a reconnect: disconnect the
    server, then connect it again."""
    wg = FakeProvider(
        "WireGuard",
        [VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")],
    )
    patch_menu_env(monkeypatch, [wg], picks=["↻ WireGuard: nl"])
    result = vpn_manager.menu_loop()
    assert result.success
    assert wg.disconnected == ["nl"] and wg.connected == ["nl"]


def test_no_vpn_row_shows_current_ip(monkeypatch):
    """Disconnected: the first row is the real public IP (not a VPN one)."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda name, age: "Exit: 95.24.1.2 🇷🇺")
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.run_menu()
    assert seen[0][0] == "● No VPN · 95.24.1.2 🇷🇺"


def test_no_vpn_row_when_cache_stale_and_ip_disabled(monkeypatch):
    """Stale cache -> bare '● No VPN' row and a background fetch; exit_ip
    disabled in config -> no row at all."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda name, age: None)
    fetched = []
    monkeypatch.setattr(vpn_manager, "request_ip_update", fetched.append)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.run_menu()
    assert seen[0][0] == "● No VPN"
    assert fetched == [vpn_manager.NO_VPN]

    cfg = config.Config()
    cfg.exit_ip_enabled = False
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    vpn_manager.run_menu()
    assert seen[1][0] == "WireGuard  (0/1)"  # no IP row, providers start right away


def test_level1_disconnect_all_label_for_multiple(monkeypatch):
    wg = FakeProvider(
        "WireGuard",
        [VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")],
    )
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=True)])
    patch_menu_env(monkeypatch, [wg, happ], picks=[])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.run_menu()
    options = seen[0]
    assert "Disconnect ALL  (2)" in options
    assert options[-1] == "🛠 Tools"


def test_level1_no_disconnect_row_when_idle(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.run_menu()
    options = seen[0]
    assert not any(o.startswith("Disconnect") for o in options)
    assert not any(o.startswith("▶") for o in options)
    assert options[-1] == "🛠 Tools"


def test_menu_loop_shows_named_keys_row_when_empty(monkeypatch):
    """Opt-in (show_empty_providers): an empty key provider appears as a
    named row whose action is the key import."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    keys = FakeProvider("VLESS", [])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg, keys])
    cfg = config.Config()
    cfg.show_empty_providers = True
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    imported = []
    monkeypatch.setattr(
        vpn_manager,
        "import_config_file",
        lambda p, t: imported.append(t) or ActionResult(True, ""),
    )
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (
            seen.append(list(options))
            or next((o for o in options if o.startswith("VLESS")), None)
        ),
    )
    vpn_manager.menu_loop()
    assert any(o.startswith("VLESS") for o in seen[0])
    assert seen[0][-1] == "🛠 Tools"  # Tools always last
    assert imported == ["VLESS"]


def test_menu_loop_hides_empty_keys_by_default(monkeypatch):
    """Default config: no empty-provider row at all (providers without
    connections stay hidden)."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    keys = FakeProvider("VLESS", [])
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [wg, keys])
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: config.Config())
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda name, age: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.menu_loop()
    assert not any(o.startswith("VLESS") for o in seen[0])
    assert seen[0][-1] == "🛠 Tools"


def test_menu_loop_always_shows_tools_row(monkeypatch):
    """Present even with nothing configured/active, right before killswitch
    moved inside it — Tools itself replaces the three separate rows."""
    patch_menu_env(monkeypatch, [], picks=[])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.menu_loop()
    assert "🛠 Tools" in seen[0]
    assert "🔍 DNS Leak Test" not in seen[0]
    assert "ℹ️ IP Info" not in seen[0]
    assert not any(str(row).strip().startswith("Killswitch") for row in seen[0])


def test_tools_menu_lists_every_visible_tool(monkeypatch):
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: config.Config())
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="Tools": (seen.append(list(options)) or None),
    )
    vpn_manager.tools_menu()
    rows = seen[0]
    for label in (
        "🔍 DNS Leak Test",
        "ℹ️ IP Info",
        "⚡ Speed Test",
        "🔄 Refresh All",
        "🗑 Clear Caches",
        "⚙ Settings",
    ):
        assert label in rows
    assert any(str(row).strip().startswith("Killswitch") for row in rows)
    assert rows[-1] == "‹ Back"


def test_tools_menu_hides_disabled_tool(monkeypatch):
    cfg = config.Config()
    cfg.tools_visible["dns_leak_test"] = False
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager.killswitch, "mode", lambda: "off")
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="Tools": (seen.append(list(options)) or None),
    )
    vpn_manager.tools_menu()
    assert "🔍 DNS Leak Test" not in seen[0]
    assert "ℹ️ IP Info" in seen[0]  # untouched key stays visible


def _speed_test_env(monkeypatch, *, measure, ks_on=False, active=(), urls=(), picks=()):
    """picks: walker selections in order; once exhausted walker returns None
    (window closed). Returns (cfg, notes, windows) — windows is every
    (prompt, rows) walker was shown."""
    notes, windows = [], []
    picks = iter(picks)
    cfg = config.Config(speed_test_urls=list(urls))
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg)
    monkeypatch.setattr(vpn_manager, "notify", lambda t, m, urgent=False: notes.append(m))
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager.speedtest, "measure", measure)
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: ks_on)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda: list(active))
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="": windows.append((prompt, list(options))) or next(picks, None),
    )
    return cfg, notes, windows


def _ok(mbps):
    return vpn_manager.speedtest.Measurement(mbps=mbps)


def _err(reason):
    return vpn_manager.speedtest.Measurement(error=reason)


def test_speed_test_menu_lists_all_presets_custom_urls_and_custom_row(monkeypatch):
    *_, windows = _speed_test_env(
        monkeypatch, measure=lambda url, d: _ok(1.0), urls=["http://10.0.0.5/f.bin"]
    )
    vpn_manager.speed_test_menu()
    rows = windows[0][1]
    assert rows[0] == vpn_manager.SPEED_TEST_ALL_LABEL
    for s in vpn_manager.speedtest.SERVICES:
        assert f"🌐 {s.name}" in rows
    assert "🔗 http://10.0.0.5/f.bin" in rows
    assert rows[-2:] == [vpn_manager.SPEED_TEST_CUSTOM_LABEL, "‹ Back"]


def test_speed_test_single_service_shows_result_in_window_not_notification(monkeypatch):
    called = []
    svc = vpn_manager.speedtest.SERVICES[0]
    _, notes, windows = _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append((url, d)) or _ok(123.45),
        picks=[f"🌐 {svc.name}"],
    )
    result = vpn_manager.speed_test_menu()
    assert called == [(svc.url, vpn_manager.speedtest.DURATION)]
    assert result.message == ""
    assert not any("Mbit/s" in m for m in notes)  # only the progress bubble
    prompt, rows = windows[1]
    assert prompt == vpn_manager.SPEED_TEST_TITLE
    assert rows[0] == "Route: direct (no VPN)"
    assert f"{svc.name}: ⬇ 123.5 Mbit/s" in rows
    assert not any(r.startswith("🏆") for r in rows)  # single result — nothing to compare
    assert rows[-2:] == ["🔁 Run again", "‹ Back"]


def test_speed_test_all_services_runs_each_in_turn_and_names_fastest(monkeypatch):
    speeds = {
        "http://a": _ok(50.0),
        "http://b": _err("HTTPError: HTTP Error 403"),
        "http://c": _ok(90.0),
    }
    monkeypatch.setattr(
        vpn_manager.speedtest,
        "SERVICES",
        [vpn_manager.speedtest.Service(k.upper(), f"http://{k}") for k in "ab"],
    )
    called = []
    _, notes, windows = _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append((url, d)) or speeds[url],
        urls=["http://c"],
        picks=[vpn_manager.SPEED_TEST_ALL_LABEL],
    )
    vpn_manager.speed_test_menu()
    d = vpn_manager.SPEED_TEST_ALL_DURATION
    assert called == [("http://a", d), ("http://b", d), ("http://c", d)]
    assert [m.split(":")[0] for m in notes] == ["1/3 · A", "2/3 · B", "3/3 · http"]
    rows = windows[1][1]
    assert "A: ⬇ 50.0 Mbit/s" in rows
    assert "B: ✗ HTTPError: HTTP Error 403" in rows
    assert "http://c: ⬇ 90.0 Mbit/s" in rows
    assert "🏆 Fastest: http://c (90.0 Mbit/s)" in rows


def test_speed_test_run_again_repeats_same_targets(monkeypatch):
    called = []
    _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append(url) or _ok(1.0),
        picks=["🔁 Run again"],
    )
    vpn_manager._run_speed_tests([("X", "http://x")])
    assert called == ["http://x", "http://x"]


def test_speed_test_route_row_names_active_vpn(monkeypatch):
    conn = VPNConnection(name="de1", provider="WireGuard", active=True)
    *_, windows = _speed_test_env(monkeypatch, measure=lambda url, d: _ok(1.0), active=[conn])
    vpn_manager._run_speed_tests([("X", "http://x")])
    assert windows[0][1][0] == f"Route: {conn.label}"


def test_speed_test_custom_url_is_measured_and_remembered(monkeypatch):
    saved, called = [], []
    _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append(url) or _ok(5.0),
        urls=["http://old/a", "http://new/b"],
    )
    monkeypatch.setattr(vpn_manager.config, "save_config", saved.append)
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "http://new/b")
    assert vpn_manager._speed_test_custom_url().success
    assert called == ["http://new/b"]
    assert saved and saved[0].speed_test_urls == ["http://new/b", "http://old/a"]


def test_speed_test_custom_urls_capped_newest_first(monkeypatch):
    saved = []
    old = [f"http://old/{i}" for i in range(vpn_manager.SPEED_TEST_MAX_URLS)]
    _speed_test_env(monkeypatch, measure=lambda url, d: _ok(5.0), urls=old)
    monkeypatch.setattr(vpn_manager.config, "save_config", saved.append)
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "http://new/x")
    assert vpn_manager._speed_test_custom_url().success
    assert saved[0].speed_test_urls == ["http://new/x", *old[:-1]]


def test_speed_test_custom_url_matching_a_preset_is_not_listed_twice(monkeypatch):
    preset = vpn_manager.speedtest.SERVICES[0]
    called = []
    *_, windows = _speed_test_env(
        monkeypatch,
        measure=lambda url, d: called.append(url) or _ok(1.0),
        urls=[preset.url],
        picks=[vpn_manager.SPEED_TEST_ALL_LABEL],
    )
    vpn_manager.speed_test_menu()
    assert not any(preset.url in row for row in windows[0][1])
    assert called.count(preset.url) == 1


def test_speed_test_custom_url_rejects_non_http(monkeypatch):
    _speed_test_env(monkeypatch, measure=lambda url, d: _ok(5.0))
    monkeypatch.setattr(vpn_manager.config, "save_config", lambda cfg: pytest.fail("saved"))
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "file:///etc/passwd")
    assert not vpn_manager._speed_test_custom_url().success


def test_speed_test_failure_explains_killswitch_without_vpn(monkeypatch):
    *_, windows = _speed_test_env(monkeypatch, measure=lambda url, d: _err("URLError"), ks_on=True)
    vpn_manager._run_speed_tests([("X", "http://x")])
    assert any("Killswitch is on" in r for r in windows[0][1])


def test_speed_test_failure_without_killswitch_has_no_killswitch_row(monkeypatch):
    *_, windows = _speed_test_env(monkeypatch, measure=lambda url, d: _err("URLError"))
    vpn_manager._run_speed_tests([("X", "http://x")])
    rows = windows[0][1]
    assert "X: ✗ URLError" in rows
    assert not any("Killswitch" in r for r in rows)


def test_dns_leak_server_row_country_alone_is_not_a_leak():
    # a resolver in Russia is no more a leak than one anywhere else — only
    # the ASN/GEO checks against the exit IP decide
    row = vpn_manager._dns_leak_server_row(
        {"ip": "172.69.50.15", "country": "ru", "org": "CloudFlare Inc"}
    )
    assert row[0] == "🇷🇺 172.69.50.15 · CloudFlare Inc"


def test_dns_leak_server_row_clean_no_warning():
    row = vpn_manager._dns_leak_server_row({"ip": "9.9.9.9", "country": "de", "org": "Quad9"})
    label = row[0]
    assert label == "🇩🇪 9.9.9.9 · Quad9"
    assert "⚠RU" not in label


def test_dns_leak_server_row_falls_back_to_asn_without_org():
    row = vpn_manager._dns_leak_server_row(
        {"ip": "1.1.1.1", "country": "au", "asn": "AS13335 CloudFlare Inc"}
    )
    assert "AS13335 CloudFlare Inc" in row[0]


def _dns_leak_menu_env(monkeypatch, result, active=(), countries=None, ipv6_off=True):
    """Wire dns_leak_test_menu()'s collaborators; returns the captured rows list."""
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager.dnsleak, "run", lambda: result)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: list(active))
    monkeypatch.setattr(
        vpn_manager.reputation, "country_of", lambda name: (countries or {}).get(name)
    )
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: ipv6_off)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    return seen


def _leak_result(dns_servers, ip_country="DE", ip_asn=24940):
    return {
        "ip": "1.2.3.4",
        "ip_country": ip_country,
        "ip_asn": ip_asn,
        "dns_servers": dns_servers,
        "conclusion": "",
    }


def _wg(name):
    return VPNConnection(name=name, provider="WireGuard", active=True)


def test_dns_leak_server_row_adds_own_check_tags():
    row = vpn_manager._dns_leak_server_row(
        {"ip": "5.6.7.8", "country": "ru", "asn": "AS12389 Rostelecom"},
        ip_country="DE",
        ip_asn=24940,
    )
    assert row[0].endswith("  Leaked")


def test_dns_leak_menu_own_verdict_flags_foreign_resolvers(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result(
            [
                {"ip": "5.6.7.8", "country": "de", "asn": "AS3320 Telekom"},
                {"ip": "172.69.50.15", "country": "nl", "asn": "AS13335 CloudFlare"},
            ]
        ),
        active=[_wg("de1")],
    )
    vpn_manager.dns_leak_test_menu()
    assert "Leaked: 1/2 DNS outside VPN/public resolvers" in seen[0]


def test_dns_leak_menu_own_verdict_clean(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([{"ip": "172.69.50.15", "country": "nl", "asn": "AS13335 CloudFlare"}]),
        active=[_wg("de1")],
    )
    vpn_manager.dns_leak_test_menu()
    assert "DNS via VPN or public resolvers" in seen[0]


def test_dns_leak_menu_no_own_verdict_without_exit_ip_data(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([{"ip": "9.9.9.9"}], ip_country="", ip_asn=None),
        active=[_wg("de1")],
    )
    vpn_manager.dns_leak_test_menu()
    assert not any("DNS via" in r or "DNS outside" in r for r in seen[0])


def test_dns_leak_menu_warns_when_no_vpn_active(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[])
    vpn_manager.dns_leak_test_menu()
    assert "No VPN active — this is your real IP" in seen[0]


def test_dns_leak_menu_exit_country_matches_connection(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch, _leak_result([]), active=[_wg("de1")], countries={"de1": "DE"}
    )
    vpn_manager.dns_leak_test_menu()
    assert "Exit matches de1 🇩🇪" in seen[0]


def test_dns_leak_menu_exit_country_mismatch(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="RU"),
        active=[_wg("de1")],
        countries={"de1": "DE"},
    )
    vpn_manager.dns_leak_test_menu()
    assert "Leaked: exit ≠ de1 🇩🇪" in seen[0]


def test_dns_leak_menu_unknown_server_country_just_names_connection(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")])
    vpn_manager.dns_leak_test_menu()
    assert "VPN: de1" in seen[0]


def test_dns_leak_menu_ipv6_row_warns_only_with_active_vpn(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")], ipv6_off=False)
    vpn_manager.dns_leak_test_menu()
    assert "Leaked: IPv6 enabled — bypasses the tunnel" in seen[0]

    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[], ipv6_off=False)
    vpn_manager.dns_leak_test_menu()
    assert "IPv6: enabled" in seen[0]


def test_dns_leak_menu_ipv6_disabled_row(monkeypatch):
    seen = _dns_leak_menu_env(monkeypatch, _leak_result([]), active=[_wg("de1")], ipv6_off=True)
    vpn_manager.dns_leak_test_menu()
    assert "IPv6: disabled" in seen[0]


def test_dns_leak_test_menu_builds_result_rows(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "active_connections", lambda providers=None: [])
    monkeypatch.setattr(vpn_manager.ipv6guard, "is_disabled", lambda: False)
    monkeypatch.setattr(
        vpn_manager.dnsleak,
        "run",
        lambda: {
            "ip": "1.2.3.4",
            "ip_country": "DE",
            "dns_servers": [
                {"ip": "172.69.50.15", "country": "ru", "org": "CloudFlare Inc"},
                {"ip": "9.9.9.9", "country": "de", "org": "Quad9"},
            ],
            "conclusion": "DNS may be leaking.",
        },
    )
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    result = vpn_manager.dns_leak_test_menu()
    assert result.success
    rows = seen[0]
    assert rows[0] == "IP: 1.2.3.4 🇩🇪"
    # CloudFlare egress in RU vs a DE exit -> GEO -> Leaked; Quad9 in DE is fine
    assert any("CloudFlare Inc" in r and r.endswith("Leaked") for r in rows)
    assert any("Quad9" in r and "Leaked" not in r for r in rows)
    assert "bash.ws: DNS may be leaking." in rows
    assert not any(ch in r for r in rows for ch in "⚠✅")  # plain text, no status emoji
    assert rows[-1] == "‹ Back"


def test_dns_leak_test_menu_handles_network_failure(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.dnsleak, "run", lambda: None)
    result = vpn_manager.dns_leak_test_menu()
    assert not result.success


def test_ip_info_menu_builds_rows(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    findings = [
        IPFinding(source="ipwho.is", ip="1.2.3.4", country_name="Germany", org="jogcorp"),
        IPFinding(
            source="ip-api.com",
            ip="1.2.3.4",
            country_name="France",
            org="SMARTNET Germany GmbH",
            hosting=True,
            proxy=False,
            mobile=False,
        ),
    ]
    monkeypatch.setattr(vpn_manager.reputation, "lookup_self", lambda include_keyed=True: findings)
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    result = vpn_manager.ip_info_menu()
    assert result.success
    rows = seen[0]
    assert rows[0] == "IP: 1.2.3.4"
    assert "ipwho.is: Germany · jogcorp" in rows
    assert "ip-api.com: France · SMARTNET Germany GmbH" in rows
    assert "🏢 Datacenter/Hosting: Yes" in rows
    assert "🕵 Proxy/VPN detected: No" in rows
    assert "📱 Mobile network: No" in rows
    assert rows[-1] == "‹ Back"


def test_ip_info_menu_handles_no_findings(monkeypatch):
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager.reputation, "lookup_self", lambda include_keyed=True: [])
    result = vpn_manager.ip_info_menu()
    assert not result.success


def test_killswitch_item_toggle_gathers_targets(monkeypatch, tmp_path):
    """The OFF item enables 'all' mode with the gathered whitelist."""
    monkeypatch.setattr(vpn_manager.killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager.killswitch, "is_enabled", lambda: False)
    monkeypatch.setattr(vpn_manager, "_killswitch_all_targets", lambda: (["1.2.3.4"], ["nl"]))
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "set_mode",
        lambda on, **kw: calls.append((on, kw)) or ActionResult(True, "ok"),
    )
    label, fn = vpn_manager._killswitch_item()
    assert "OFF" in label and "(all)" in label
    fn()
    assert calls == [(True, {"extra_ips": ["1.2.3.4"], "ifaces": ["nl"]})]


def test_run_items_matches_indented_labels(monkeypatch):
    """walker returns the selected line trimmed (log proof: "no action
    matches ['Killswitch: …']" without the leading spaces), so run_items
    must compare labels stripped — the '  Killswitch: …' / '  Import …'
    items otherwise can never be activated."""
    seen = []
    monkeypatch.setattr(
        vpn_manager, "walker_select", lambda options, prompt="VPN": options[0].strip()
    )
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: seen.append(a))
    result = vpn_manager.run_items(
        [("  Killswitch: OFF — click to enable (all)", lambda: ActionResult(True, "on"))],
        prompt="VPN",
    )
    assert result.success
    assert seen == [("VPN", "on")]  # action ran and notified


def test_unique_labels_suffix_cannot_collide_with_genuine_label():
    """A generated " (2)" disambiguator must not shadow a genuine later label."""
    items = [
        ("Same", lambda: 1),
        ("Same", lambda: 2),
        ("Same (2)", lambda: 3),
    ]
    labels = [label for label, _ in vpn_manager._unique_labels(items)]
    assert labels == ["Same", "Same (2)", "Same (2) (2)"]
    # actions stay attached to their original entry
    unique = vpn_manager._unique_labels(items)
    assert [a() for _, a in unique] == [1, 2, 3]


def _happ_provider_menu_env(monkeypatch, entries, info, seen, notifications, picks):
    class P:
        name = "Happ"

        def connections(self):
            return []

        def connect(self, conn):
            return ActionResult(True, "ok")

        def disconnect(self, conn):
            return ActionResult(True, "ok")

    monkeypatch.setattr(vpn_manager.happmeta, "server_info_suffix", lambda name, protocol="": "")
    monkeypatch.setattr(vpn_manager.happmeta, "subscription_info", lambda sub_id: info)
    monkeypatch.setattr(
        vpn_manager, "notify", lambda *a, **k: notifications.append((a, k))
    )
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    picks_iter = iter(picks)
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or next(picks_iter, None)),
    )
    return P()


def test_happ_provider_menu_shows_traffic_info(monkeypatch):
    """Panel info present -> leading ⓘ entry with traffic + expiry; its action
    only notifies (never connectable)."""
    entries = [{"name": "s1", "active": False, "provider_id": "42"}]
    info = {
        "upload": 0,
        "download": 1973660012446,
        "total": 0,
        "expire": 1797232846,
        "title": "oplVPN_bot",
    }
    seen, notifications = [], []
    provider = _happ_provider_menu_env(
        monkeypatch, entries, info, seen, notifications, picks=[None]
    )

    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["ⓘ Traffic 1838 GB / ∞ · until 14.12.2026", "s1", "‹ Back"]

    # picking the ⓘ entry notifies with the full card, connects nothing
    info_label = "ⓘ Traffic 1838 GB / ∞ · until 14.12.2026"
    seen2, notifications2 = [], []
    provider2 = _happ_provider_menu_env(
        monkeypatch, entries, info, seen2, notifications2, picks=[info_label]
    )
    vpn_manager.happ_provider_menu(provider2, "P", entries)
    card = "oplVPN_bot\n↓ 1838 GB · ↑ 0 GB / ∞\nValid until 14.12.2026"
    assert notifications2 == [(("Happ · P", card), {})]


def test_happ_provider_menu_omits_missing_info_parts(monkeypatch):
    """expire None -> no 'until …' part; nothing raises on partial info."""
    entries = [{"name": "s1", "active": False, "provider_id": "42"}]
    info = {"upload": None, "download": None, "total": 0, "expire": None, "title": None}
    seen, notifications = [], []
    provider = _happ_provider_menu_env(
        monkeypatch, entries, info, seen, notifications, picks=[None]
    )
    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["s1", "‹ Back"]  # nothing worth showing -> no ⓘ


def test_happ_provider_menu_no_info_entry_without_record(monkeypatch):
    """Older caches / captured extras (no provider_id, no info record) keep the
    plain server list."""
    entries = [{"name": "s1", "active": False, "provider_id": ""}]
    seen, notifications = [], []
    provider = _happ_provider_menu_env(
        monkeypatch, entries, None, seen, notifications, picks=[None]
    )
    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["s1", "‹ Back"]


def test_walker_input_returns_stripped_text(monkeypatch):
    class R:
        stdout = "  /home/user/config.conf  \n"

    monkeypatch.setattr(vpn_manager.subprocess, "run", lambda cmd, **k: R())
    assert vpn_manager.walker_input("Path") == "/home/user/config.conf"


def test_walker_input_returns_none_when_empty(monkeypatch):
    class R:
        stdout = "\n"

    monkeypatch.setattr(vpn_manager.subprocess, "run", lambda cmd, **k: R())
    assert vpn_manager.walker_input("Path") is None


def test_walker_input_returns_none_when_walker_missing(monkeypatch):
    def boom(cmd, **k):
        raise FileNotFoundError

    monkeypatch.setattr(vpn_manager.subprocess, "run", boom)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    assert vpn_manager.walker_input("Path") is None


def test_walker_input_passes_width_flags(monkeypatch):
    captured = {}

    class R:
        stdout = "x\n"

    def fake_run(cmd, **k):
        captured["cmd"] = cmd
        return R()

    monkeypatch.setattr(vpn_manager.subprocess, "run", fake_run)
    vpn_manager.walker_input("Path")
    cmd = captured["cmd"]
    assert "--width" in cmd and cmd[cmd.index("--width") + 1] == str(vpn_manager.WALKER_WIDTH)


def test_refresh_all_menu_spawns_ping_and_subs_unconditionally(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vpn_manager.subprocess, "Popen", lambda cmd, **k: calls.append(cmd) or None
    )
    result = vpn_manager.refresh_all_menu()
    assert result.success
    flags = [c[2] for c in calls]  # [sys.executable, script_path, flag]
    assert "--update-ping" in flags
    # the forced variant — plain --update-subs would keep the SUB_MAX_AGE
    # gate inside fetch_subscription and no-op on a fresh cache
    assert "--update-subs-force" in flags


def test_clear_caches_menu_removes_only_json_files(tmp_path, monkeypatch):
    cache_dir = tmp_path / "vpn-manager"
    cache_dir.mkdir()
    (cache_dir / "reputation.json").write_text("{}")
    (cache_dir / "happ-ping.json").write_text("{}")
    keep = cache_dir / "not-a-cache.txt"
    keep.write_text("keep me")
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", cache_dir)

    result = vpn_manager.clear_caches_menu()

    assert result.success
    assert not (cache_dir / "reputation.json").exists()
    assert not (cache_dir / "happ-ping.json").exists()
    assert keep.exists()


def test_clear_caches_menu_keeps_subscription_server_lists(tmp_path, monkeypatch):
    """subscription-*.json is the only offline copy of each subscription's
    servers — deleting it empties the Happ menu until a refetch succeeds,
    which a killswitch or a dead network can block indefinitely."""
    cache_dir = tmp_path / "vpn-manager"
    cache_dir.mkdir()
    sub = cache_dir / "subscription-123.json"
    sub.write_text("{}")
    (cache_dir / "happ-ping.json").write_text("{}")
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", cache_dir)
    vpn_manager.clear_caches_menu()
    assert sub.exists()
    assert not (cache_dir / "happ-ping.json").exists()


def test_clear_caches_menu_tolerates_missing_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(vpn_manager, "CACHE_DIR", tmp_path / "does-not-exist")
    result = vpn_manager.clear_caches_menu()
    assert result.success


def test_happ_menu_name_clash_marks_only_active_provider(monkeypatch, tmp_path):
    servers = [
        {"name": "🇩🇪 Germany", "provider_name": "P1", "provider_id": "1", "config": {}},
        {"name": "🇩🇪 Germany", "provider_name": "P2", "provider_id": "2", "config": {}},
    ]
    active = VPNConnection(name="🇩🇪 Germany", provider="Happ", active=True, subscription_id="2")
    provider = FakeProvider("Happ", [active])
    monkeypatch.setattr(vpn_manager.happmeta, "request_ping_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "all_servers", lambda allow_fetch=True: servers)
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", tmp_path / "ping.json")
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.happ_menu(provider)
    assert "P2  (1/1)" in seen[0]
    assert "P1" in seen[0]  # no active suffix for the same-named P1 server


def test_happ_provider_menu_connects_with_subscription_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", tmp_path / "ping.json")
    monkeypatch.setattr(vpn_manager.happmeta, "server_params", lambda name, **kw: None)
    monkeypatch.setattr(vpn_manager.happmeta, "subscription_info", lambda sub_id: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    got = []
    monkeypatch.setattr(
        vpn_manager, "guarded_connect", lambda p, c: got.append(c) or ActionResult(True, "")
    )
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": "🇩🇪 Germany")
    entries = [{"name": "🇩🇪 Germany", "active": False, "provider_id": "2"}]
    vpn_manager.happ_provider_menu(FakeProvider("Happ", []), "P2", entries)
    assert (got[0].subscription_id, got[0].subscription_name) == ("2", "P2")


def test_main_menu_current_connection_shows_subscription(monkeypatch):
    conn = VPNConnection(
        name="🇩🇪 Germany", provider="Happ", active=True, subscription_name="Wirecat"
    )
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: "")
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: config.Config())
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda name, age: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    rows = vpn_manager._current_connection_items(conn)
    assert rows[0][0] == "↻ Happ · Wirecat: 🇩🇪 Germany"


def test_happ_menu_passes_protocol_to_server_rows(monkeypatch, tmp_path):
    servers = [
        {
            "name": "de",
            "provider_name": "P",
            "provider_id": "1",
            "config": {
                "outbounds": [
                    {
                        "protocol": "hysteria",
                        "streamSettings": {"network": "hysteria", "security": "tls"},
                    }
                ]
            },
        }
    ]
    monkeypatch.setattr(vpn_manager.happmeta, "request_ping_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(vpn_manager.reputation, "request_update", lambda: None)
    monkeypatch.setattr(vpn_manager.happmeta, "all_servers", lambda allow_fetch=True: servers)
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", tmp_path / "ping.json")
    monkeypatch.setattr(vpn_manager.happmeta, "subscription_info", lambda sub_id: None)
    picks = iter(["P"])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": seen.append(list(options)) or next(picks, None),
    )
    vpn_manager.happ_menu(FakeProvider("Happ", []))
    assert "de    hysteria/tls" in seen[1]  # server level shows the protocol


def _record_ipv6_guard(monkeypatch):
    calls = []
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "disable", lambda: calls.append("disable") or ActionResult(True, "")
    )
    monkeypatch.setattr(
        vpn_manager.ipv6guard, "enable", lambda: calls.append("enable") or ActionResult(True, "")
    )
    return calls


def test_successful_connect_disables_ipv6_even_before_the_tunnel_shows_up(monkeypatch):
    """Happ's keeper reports "connected" on happd's start ack — before xray
    has created happ-xray, while happd's process list may still be the
    cached pre-switch one. Re-probing active_connections() right then saw
    nothing and ENABLED IPv6 on a live tunnel (journal, 17:19:34: xray
    started and disable_ipv6=0 in the same second). A successful connect is
    itself the proof something is up."""
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    calls = _record_ipv6_guard(monkeypatch)

    assert vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert calls == ["disable"]


def test_failed_connect_still_syncs_ipv6_with_what_is_actually_up(monkeypatch):
    class Failing(FakeProvider):
        def connect(self, conn):
            return ActionResult(False, "nope")

    wg = Failing("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=[])
    calls = _record_ipv6_guard(monkeypatch)

    assert not vpn_manager.guarded_connect(wg, wg.connections()[0]).success
    assert calls == ["enable"]  # nothing up -> IPv6 back on


def test_dns_leak_exit_row_trusts_name_flag_over_bridge_entry_country(monkeypatch):
    """Whitelist-bypass servers ("🇩🇪 Германия+": every member is a DE+-RU-*
    Russian entry relay) enter in RU and exit in DE by design. The sweep's
    country is the entry IP's, so comparing against it flagged every such
    server as a leak; the provider's flag names the exit country."""
    bridge = "🇩🇪 Германия+"
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="DE"),
        active=[_wg(bridge)],
        countries={bridge: "RU"},
    )
    vpn_manager.dns_leak_test_menu()
    assert f"Exit matches {bridge} 🇩🇪" in seen[0]
    assert not any(r.startswith("Leaked: exit") for r in seen[0])


def test_dns_leak_exit_row_flags_exit_outside_the_name_flag_country(monkeypatch):
    seen = _dns_leak_menu_env(
        monkeypatch,
        _leak_result([], ip_country="RU"),
        active=[_wg("🇩🇪 Германия+")],
        countries={"🇩🇪 Германия+": "RU"},  # entry RU must not excuse a RU exit
    )
    vpn_manager.dns_leak_test_menu()
    assert "Leaked: exit ≠ 🇩🇪 Германия+ 🇩🇪" in seen[0]


def test_country_from_name_flag():
    assert vpn_manager._name_flag_country("🇩🇪 Германия+") == "DE"
    assert vpn_manager._name_flag_country("Fast 🇳🇱 NL-2") == "NL"  # not only leading
    assert vpn_manager._name_flag_country("Germany #41294") is None
    assert vpn_manager._name_flag_country("🇩 broken") is None  # lone regional indicator


def test_dns_leak_exit_row_eu_flag_accepts_any_member_state(monkeypatch):
    # 🇪🇺 is not a country: 13 real servers carry it and exit in NL/DE/EE...
    cases = (("NL", "Exit matches 🇪🇺 Europe 🇪🇺"), ("RU", "Leaked: exit ≠ 🇪🇺 Europe 🇪🇺"))
    for exit_cc, row in cases:
        seen = _dns_leak_menu_env(
            monkeypatch, _leak_result([], ip_country=exit_cc), active=[_wg("🇪🇺 Europe")]
        )
        vpn_manager.dns_leak_test_menu()
        assert row in seen[0], exit_cc
