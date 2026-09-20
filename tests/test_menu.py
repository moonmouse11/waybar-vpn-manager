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
    assert "Happ" in options  # inactive provider: no count suffix
    assert not any(o.startswith("Happ  (") for o in options)
    assert "Disconnect ALL" not in options  # only one active connection
    assert sum(o in ("WireGuard  (1/2)", "Happ") for o in options) == 2


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
    monkeypatch.setattr(vpn_manager.killswitch, "resume_for_happ", lambda: None)
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
                "unknown": {"ms": 7.0, "at": now - 999},  # stale -> unmarked
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
            "s3": {"ms": 5.0, "at": now - 999},  # stale: P2 has no fresh data
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
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard", "Connect nl"])
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
    patch_menu_env(monkeypatch, [wg], picks=["WireGuard", "‹ Back", None])
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
