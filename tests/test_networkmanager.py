from providers import networkmanager as nm


def test_terse_lines_honour_escapes():
    lines = nm._terse_lines("my\\:vpn:uuid-1:vpn\nplain:uuid-2:wireguard")
    assert lines == [["my:vpn", "uuid-1", "vpn"], ["plain", "uuid-2", "wireguard"]]


def test_connections_parsing(monkeypatch):
    saved = "HomeWG:u1:wireguard\nCorp VPN:u2:vpn\nWiFi:u3:802-11-wireless\n"
    active = "u1:wg0\nu2:\n"

    def fake_run(cmd):
        if "--active" in cmd:
            return 0, active
        return 0, saved

    monkeypatch.setattr(nm, "_run", fake_run)
    conns = nm.NetworkManagerProvider().connections()

    assert [c.name for c in conns] == ["HomeWG", "Corp VPN"]  # WiFi excluded
    assert conns[0].active and conns[0].interface == "wg0"
    assert conns[1].active and conns[1].interface is None  # deviceless VPN
    assert conns[0].uuid == "u1"


def test_nmcli_missing(monkeypatch):
    monkeypatch.setattr(nm.shutil, "which", lambda _: None)
    assert nm.NetworkManagerProvider().connections() == []


def test_nmcli_failure(monkeypatch):
    monkeypatch.setattr(nm.shutil, "which", lambda _: "/usr/bin/nmcli")
    monkeypatch.setattr(nm, "_run", lambda cmd: (8, "Error: NetworkManager is not running."))
    assert nm.NetworkManagerProvider().connections() == []


def test_toggle_autostart(monkeypatch):
    calls = []
    state = {"value": "yes\n"}

    def fake_run(cmd):
        calls.append(cmd)
        if "-g" in cmd:
            return 0, state["value"]
        return 0, ""

    monkeypatch.setattr(nm, "_run", fake_run)
    provider = nm.NetworkManagerProvider()

    from providers.base import VPNConnection

    c = VPNConnection(name="HomeWG", provider="NetworkManager", active=False, uuid="u1")
    result = provider.toggle_autostart(c)
    assert result.success and "disabled" in result.message
    assert calls[-1][-2:] == ["connection.autoconnect", "no"]
