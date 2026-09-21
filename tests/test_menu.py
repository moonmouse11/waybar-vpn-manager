import config
import vpn_manager
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
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
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
    monkeypatch.setattr(vpn_manager.happmeta, "server_info_suffix", lambda name: "")
    monkeypatch.setattr(vpn_manager.killswitch, "resume_for_happ", lambda extra_ips=None: None)
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: None)
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: None)
    picks = iter(["Connect Same (2)"])
    seen = []
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or next(picks, None)),
    )

    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["Connect Same", "Connect Same (2)", "‹ Back"]
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
    monkeypatch.setattr(vpn_manager.happmeta, "all_servers", lambda: servers)
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
    assert "✗" in seen[0][1]
    assert seen[0][2] == "Connect unknown"  # stale -> no mark at all


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


def test_two_level_connect(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard  (0/1)", "Connect nl"])
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
    assert any("Killswitch" in o for o in level1_options)


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
    ips, ifaces = vpn_manager._killswitch_all_targets()
    assert ips == ["93.184.216.34", "93.184.216.35", "93.184.216.37"]  # NM endpoint excluded
    assert ifaces == ["nl", "tun*"]  # wg profile name + OpenVPN glob; long name filtered


def test_happ_connect_passes_resolved_server_ip(monkeypatch, tmp_path):
    """guarded_connect(Happ) resolves the target server and hands its IP to
    resume_for_happ — otherwise the killswitch blocks xray from the server."""
    happ = FakeProvider("Happ", [VPNConnection(name="de", provider="Happ", active=False)])
    patch_menu_env(monkeypatch, [happ], picks=[])
    monkeypatch.setattr(
        vpn_manager.happmeta,
        "server_params",
        lambda name, allow_fetch=True: {"host": "de.example.com", "port": 443},
    )
    monkeypatch.setattr(
        vpn_manager.killswitch, "resolve_endpoint_ips", lambda t: ["2.26.86.35"]
    )
    calls = []
    monkeypatch.setattr(
        vpn_manager.killswitch,
        "resume_for_happ",
        lambda extra_ips=None: calls.append(extra_ips) or ActionResult(True, "ok"),
    )
    result = vpn_manager.guarded_connect(happ, happ.connections()[0])
    assert result.success
    assert calls == [["2.26.86.35"]]


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
    assert any("walker завис" in str(n) for n in notified)
    assert any("pkill" in str(c) and "-9" in c for c in ran)  # SIGKILL on the service


def test_level1_layout_connected(monkeypatch):
    """Menu order: current connection (first, with metrics) → providers →
    quick disconnect, killswitch ALWAYS the last row."""
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
    assert "↓ 2.0 MiB/s" in options[0] and "1.2.3.4" in options[0]
    assert "Disconnect: WireGuard: nl" in options
    assert options[-1].strip().startswith("Killswitch")


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
    assert options[-1].strip().startswith("Killswitch")


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
    assert options[-1].strip().startswith("Killswitch")


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
    assert seen[0][-1].strip().startswith("Killswitch")  # killswitch always last
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
    assert seen[0][-1].strip().startswith("Killswitch")


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

    monkeypatch.setattr(vpn_manager.happmeta, "server_info_suffix", lambda name: "")
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
    provider = _happ_provider_menu_env(monkeypatch, entries, info, seen, notifications, picks=[None])

    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["ⓘ Трафик 1838 GB / ∞ · до 14.12.2026", "Connect s1", "‹ Back"]

    # picking the ⓘ entry notifies with the full card, connects nothing
    seen2, notifications2 = [], []
    provider2 = _happ_provider_menu_env(
        monkeypatch, entries, info, seen2, notifications2, picks=["ⓘ Трафик 1838 GB / ∞ · до 14.12.2026"]
    )
    vpn_manager.happ_provider_menu(provider2, "P", entries)
    assert notifications2 == [(("Happ · P", "oplVPN_bot\n↓ 1838 GB · ↑ 0 GB / ∞\nДействует до 14.12.2026"), {})]


def test_happ_provider_menu_omits_missing_info_parts(monkeypatch):
    """expire None -> no 'до …' part; nothing raises on partial info."""
    entries = [{"name": "s1", "active": False, "provider_id": "42"}]
    info = {"upload": None, "download": None, "total": 0, "expire": None, "title": None}
    seen, notifications = [], []
    provider = _happ_provider_menu_env(monkeypatch, entries, info, seen, notifications, picks=[None])
    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["Connect s1", "‹ Back"]  # nothing worth showing -> no ⓘ


def test_happ_provider_menu_no_info_entry_without_record(monkeypatch):
    """Older caches / captured extras (no provider_id, no info record) keep the
    plain server list."""
    entries = [{"name": "s1", "active": False, "provider_id": ""}]
    seen, notifications = [], []
    provider = _happ_provider_menu_env(monkeypatch, entries, None, seen, notifications, picks=[None])
    vpn_manager.happ_provider_menu(provider, "P", entries)
    assert seen[0] == ["Connect s1", "‹ Back"]
