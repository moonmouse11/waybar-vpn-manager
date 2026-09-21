import config
import vpn_manager
from providers.base import VPNConnection


class FakeProvider:
    def __init__(self, name, conns):
        self.name = name
        self._conns = conns

    def connections(self):
        return self._conns


def patch_env(monkeypatch, providers, cfg=None, traffic="↓ 1 MiB  ↑ 2 MiB",
              rate="↓ 3 KiB/s ↑ 4 KiB/s"):
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", providers)
    monkeypatch.setattr(vpn_manager.config, "load_config", lambda: cfg or config.Config())
    monkeypatch.setattr(vpn_manager, "iface_traffic", lambda iface: traffic)
    monkeypatch.setattr(vpn_manager, "iface_rate", lambda iface: rate)
    monkeypatch.setattr(vpn_manager, "sample_iface_traffic", lambda iface: None)
    monkeypatch.setattr(vpn_manager, "request_ip_update", lambda name: None)
    monkeypatch.setattr(vpn_manager.ipinfo, "status_line", lambda conn, age: "Exit: 9.9.9.9")


def test_disconnected(monkeypatch):
    patch_env(monkeypatch, [])
    status = vpn_manager.get_status()
    assert status["class"] == "vpn-disconnected"
    assert status["text"] == " VPN"


def test_single_active(monkeypatch):
    conn = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    patch_env(monkeypatch, [FakeProvider("WireGuard", [conn])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl"
    assert status["class"] == ["vpn-connected", "vpn-wireguard"]
    assert "↓ 3 KiB/s ↑ 4 KiB/s" in status["tooltip"]  # rate, units per second
    assert "↓ 1 MiB  ↑ 2 MiB total" in status["tooltip"]  # totals, marked
    assert "Exit: 9.9.9.9" in status["tooltip"]


def test_multiple_active(monkeypatch):
    wg = VPNConnection(name="nl", provider="WireGuard", active=True, interface="wg0")
    happ = VPNConnection(name="de", provider="Happ", active=True)
    patch_env(monkeypatch, [FakeProvider("WireGuard", [wg]), FakeProvider("Happ", [happ])])
    status = vpn_manager.get_status()
    assert status["text"] == " WireGuard: nl (+1)"
    assert status["class"] == ["vpn-connected", "vpn-wireguard", "vpn-happ"]
    assert "Happ: de" in status["tooltip"]


def test_hidden_provider_excluded(monkeypatch):
    conn = VPNConnection(name="x", provider="Outline", active=True)
    cfg = config.Config(providers={"outline": False})
    patch_env(monkeypatch, [FakeProvider("Outline", [conn])], cfg=cfg)
    status = vpn_manager.get_status()
    assert status["class"] == "vpn-disconnected"


def test_no_traffic_when_no_interface(monkeypatch):
    conn = VPNConnection(name="de", provider="Happ", active=True, interface=None)
    patch_env(monkeypatch, [FakeProvider("Happ", [conn])], traffic=None)
    status = vpn_manager.get_status()
    assert "↓" not in status["tooltip"]
