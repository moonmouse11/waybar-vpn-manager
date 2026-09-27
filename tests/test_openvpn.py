from providers import openvpn
from providers.base import VPNConnection
from providers.openvpn import OpenVPNProvider


def test_connect_wires_dns_updown_script(tmp_path, monkeypatch):
    monkeypatch.setattr(openvpn, "PID_DIR", tmp_path)
    calls = []

    def fake_run(cmd):
        calls.append(cmd)
        return (0, "")

    monkeypatch.setattr(openvpn, "_run", fake_run)
    provider = OpenVPNProvider()
    conn = VPNConnection(
        name="nl", provider="OpenVPN", active=False, config_path=str(tmp_path / "nl.conf")
    )

    result = provider.connect(conn)

    assert result.success
    launch = calls[-1]
    assert launch[:2] == ["sudo", "openvpn"]
    assert "--script-security" in launch
    assert launch[launch.index("--script-security") + 1] == "2"
    assert launch[launch.index("--up") + 1] == f"{openvpn.DNS_UPDOWN} up"
    assert launch[launch.index("--down") + 1] == f"{openvpn.DNS_UPDOWN} down"


def test_connect_failure_surfaces_message(tmp_path, monkeypatch):
    monkeypatch.setattr(openvpn, "PID_DIR", tmp_path)
    monkeypatch.setattr(openvpn, "_run", lambda cmd: (1, "boom"))
    provider = OpenVPNProvider()
    conn = VPNConnection(
        name="nl", provider="OpenVPN", active=False, config_path=str(tmp_path / "nl.conf")
    )

    result = provider.connect(conn)
    assert not result.success
    assert result.message == "boom"
