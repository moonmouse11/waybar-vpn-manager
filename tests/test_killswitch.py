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


def test_is_enabled_probes_via_script(monkeypatch):
    """Unprivileged nft can't list tables and sudoers has no nft rule, so
    is_enabled must shell out to the script's 'is-on' and map its rc."""
    ran = []

    class Result:
        def __init__(self, rc):
            self.returncode = rc

    calls = {"n": 0}

    def fake_run(cmd, **kwargs):
        ran.append(cmd)
        calls["n"] += 1
        return Result(0 if calls["n"] == 1 else 1)

    monkeypatch.setattr(killswitch.subprocess, "run", fake_run)
    assert killswitch.is_enabled()
    assert ran == [["sudo", "-n", killswitch.SCRIPT, "is-on"]]
    assert not killswitch.is_enabled()


def test_set_mode_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(
        killswitch, "_sudo", lambda *args: calls.append(args) or ActionResult(True, "ok")
    )

    assert killswitch.set_mode(True).success
    assert calls == [("detect",), ("on",)]  # enable re-detects Happ server IPs first
    assert killswitch.mode() == "all"  # the menu toggle means "all providers"

    calls.clear()
    assert killswitch.set_mode(False).success
    assert calls == [("off",)]
    assert killswitch.mode() == "off"


def test_enable_all_mode_merges_endpoints_and_ifaces(monkeypatch, tmp_path):
    """'all' mode: resolved WG/OVPN IPs + tunnel ifaces reach the script as
    'on <ips…> --iface <name>…' after the Happ detect."""
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch, "_sudo", lambda *args: calls.append(args) or ActionResult(True, "ok")
    )

    result = killswitch.enable(extra_ips=["1.2.3.4", "5.6.7.8"], ifaces=["wg0", "tun*"])
    assert result.success
    assert calls == [
        ("detect",),
        ("on", "1.2.3.4", "5.6.7.8", "--iface", "wg0", "--iface", "tun*"),
    ]


def test_enable_all_mode_tolerates_detect_failure(monkeypatch, tmp_path):
    """Happ disconnected in 'all' mode: detect fails but 'on' still runs —
    the WG/OVPN whitelist is enough. In happ-only mode (extra_ips=None) a
    failed detect stays fatal."""
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    calls = []
    monkeypatch.setattr(
        killswitch,
        "_sudo",
        lambda *args: calls.append(args)
        or ActionResult(args[0] != "detect", "ok" if args[0] != "detect" else "no happ"),
    )

    assert killswitch.enable(extra_ips=["1.2.3.4"]).success
    assert [c[0] for c in calls] == ["detect", "on"]

    calls.clear()
    failed = killswitch.enable()
    assert not failed.success
    assert calls == [("detect",)]  # never reached 'on'


def test_resume_for_happ_enables_in_all_mode(monkeypatch, tmp_path):
    monkeypatch.setattr(killswitch.config, "CONFIG_PATH", tmp_path / "config.json")
    cfg = killswitch.config.load_config()
    cfg.killswitch_mode = "all"
    killswitch.config.save_config(cfg)
    monkeypatch.setattr(killswitch, "is_enabled", lambda: False)
    calls = []
    monkeypatch.setattr(
        killswitch, "enable", lambda **kw: calls.append(kw) or ActionResult(True, "ok")
    )
    assert killswitch.resume_for_happ().success
    assert calls == [{}]


def test_resolve_endpoint_ips(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port, family):
        if host == "dead.example":
            raise OSError("NXDOMAIN")
        if host == "v6-only.example":
            return []  # A-записи нет — запрос с AF_INET пуст
        return [(socket.AF_INET, 0, 0, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(killswitch.socket, "getaddrinfo", fake_getaddrinfo)
    targets = [("nl", "example.com", 51820), ("de", "example.com", 51820), ("x", "dead.example", 1)]
    assert killswitch.resolve_endpoint_ips(targets) == ["93.184.216.34"]  # dedup + skip dead
    assert killswitch.resolve_endpoint_ips([("v6", "v6-only.example", 1)]) == []


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
