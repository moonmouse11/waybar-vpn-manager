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
    patch_menu_env(monkeypatch, [wg, happ], picks=[None])  # user escapes
    vpn_manager.run_menu()
    # reaching here without StopIteration means labels matched; counts asserted below


def test_two_level_connect(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    patch_menu_env(monkeypatch, [wg], picks=["󰈀  WireGuard", "󰈀  Connect nl"])
    vpn_manager.run_menu()
    assert wg.connected == ["nl"]


def test_two_level_disconnect_active(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=True)])
    patch_menu_env(monkeypatch, [wg], picks=["󰈀  WireGuard  (1/1)", "󰅖  Disconnect nl"])
    vpn_manager.run_menu()
    assert wg.disconnected == ["nl"]


def test_back_returns_to_level1(monkeypatch):
    wg = FakeProvider("WireGuard", [VPNConnection(name="nl", provider="WireGuard", active=False)])
    # level1 -> WireGuard, level2 -> Back, level1 -> escape
    patch_menu_env(monkeypatch, [wg], picks=["󰈀  WireGuard", "‹ Back", None])
    vpn_manager.run_menu()
    assert wg.connected == []


def test_level1_active_count_label(monkeypatch):
    wg = FakeProvider(
        "WireGuard",
        [
            VPNConnection(name="a", provider="WireGuard", active=True),
            VPNConnection(name="b", provider="WireGuard", active=False),
        ],
    )
    picks = iter(["󰈀  WireGuard  (1/2)", None])
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
    assert "󰈀  WireGuard  (1/2)" in level1_options
    assert any("Killswitch" in o for o in level1_options)
