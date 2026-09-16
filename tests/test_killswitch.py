import killswitch
import providers.base as base
from providers.base import ActionResult, human_bytes, iface_traffic


def test_human_bytes():
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(2048) == "2.0 KiB"
    assert human_bytes(5 * 1024**3) == "5.0 GiB"


IP_S_LINK = """\
2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN
    link/none
    RX: bytes  packets  errors  dropped missed  mcast
    123456     1000     0       0       0       0
    TX: bytes  packets  errors  dropped missed  collisions carrier
    654321     2000     0       0       0       0          0
"""


def test_iface_traffic_parses(monkeypatch):
    class Result:
        returncode = 0
        stdout = IP_S_LINK

    monkeypatch.setattr(base.subprocess, "run", lambda *a, **k: Result())
    assert iface_traffic("wg0") == "↓ 120.6 KiB  ↑ 639.0 KiB"


def test_iface_traffic_missing(monkeypatch):
    class Result:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(base.subprocess, "run", lambda *a, **k: Result())
    assert iface_traffic("nope") is None


def test_set_mode_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(
        killswitch, "_sudo", lambda arg: calls.append(arg) or ActionResult(True, "ok")
    )

    assert killswitch.set_mode(True).success
    assert calls == ["detect", "on"]  # enable re-detects server IPs first
    assert killswitch.mode() == "happ"

    calls.clear()
    assert killswitch.set_mode(False).success
    assert calls == ["off"]
    assert killswitch.mode() == "off"


def test_suspend_for_keeps_preference(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "disable", lambda: ActionResult(True, "ok"))
    result = killswitch.suspend_for("WireGuard")
    assert result.success
    assert "WireGuard" in result.message and "auto-resumes" in result.message
    assert killswitch.mode() == "off"  # preference untouched


def test_resume_for_happ_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: True)
    calls = []
    monkeypatch.setattr(
        killswitch, "redetect", lambda: calls.append("redetect") or ActionResult(True, "ok")
    )
    assert killswitch.resume_for_happ().success
    assert calls == ["redetect"]


def test_resume_for_happ_mode_off_noop(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    assert killswitch.resume_for_happ() is None
