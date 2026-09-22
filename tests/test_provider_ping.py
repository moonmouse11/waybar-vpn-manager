"""Ping ✓/✗ availability for WireGuard/OpenVPN: endpoint parsing, the shared
ping cache writer, and provider_menu labels."""

import json
import time

from test_menu import FakeProvider, patch_menu_env

import happmeta
import vpn_manager
from providers.base import VPNConnection
from providers.openvpn import ovpn_endpoint
from providers.wireguard import wg_endpoint

# ── wg_endpoint ───────────────────────────────────────────────────────────────


def test_wg_endpoint_forms(tmp_path):
    def conf(body):
        p = tmp_path / "x.conf"
        p.write_text(body)
        return str(p)

    dns = conf("[Peer]\nPublicKey = k\nEndpoint = vpn.example.com:51820\n")
    assert wg_endpoint(dns) == ("vpn.example.com", 51820)

    ipv4 = conf("[Interface]\nAddress = 10.0.0.1\n[Peer]\nEndpoint = 1.2.3.4:443\n")
    assert wg_endpoint(ipv4) == ("1.2.3.4", 443)

    v6 = conf("[Peer]\nEndpoint = [2001:db8::1]:51820\n")
    assert wg_endpoint(v6) == ("2001:db8::1", 51820)

    bare_v6 = conf("[Peer]\nEndpoint = 2001:db8::1\n")  # no port -> default
    assert wg_endpoint(bare_v6) == ("2001:db8::1", 51820)

    junk_after_bracket = conf("[Peer]\nEndpoint = [2001:db8::1]12345\n")
    assert wg_endpoint(junk_after_bracket) == ("2001:db8::1", 51820)  # tolerant

    port_too_big = conf("[Peer]\nEndpoint = vpn.example.com:70000\n")
    assert wg_endpoint(port_too_big) is None  # OverflowError would abort a sweep

    v6_port_too_big = conf("[Peer]\nEndpoint = [2001:db8::1]:70000\n")
    assert wg_endpoint(v6_port_too_big) is None

    no_port = conf("[Peer]\nEndpoint = vpn.example.com\n")
    assert wg_endpoint(no_port) == ("vpn.example.com", 51820)

    # only the [Peer] Endpoint counts, not [Interface] keys
    assert wg_endpoint(conf("[Interface]\nEndpoint = 9.9.9.9:1\n")) is None
    assert wg_endpoint(conf("[Peer]\nPublicKey = k\n")) is None
    assert wg_endpoint(conf("")) is None
    assert wg_endpoint(conf("[Peer]\nEndpoint = :51820\n")) is None
    assert wg_endpoint(str(tmp_path / "missing.conf")) is None


def test_wg_provider_ping_targets(tmp_path, monkeypatch):
    from providers import wireguard
    from providers.wireguard import WireGuardProvider

    good = tmp_path / "good.conf"
    good.write_text("[Peer]\nEndpoint = vpn.example.com:51820\n")
    bad = tmp_path / "noendpoint.conf"
    bad.write_text("[Peer]\nPublicKey = k\n")
    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: [])  # no real `ip`
    provider = WireGuardProvider()
    # config_dir is a class attribute bound at class-definition time, not a
    # live read of the module-level WG_DIR — patching wireguard.WG_DIR alone
    # has no effect on it, so the instance attribute must be overridden.
    provider.config_dir = tmp_path
    provider.other_config_dirs = ()
    targets = provider.ping_targets()
    assert targets == [("good", "vpn.example.com", 51820)]


def test_amneziawg_lists_its_own_dir_independently(tmp_path, monkeypatch):
    """WireGuard and AmneziaWG each list configs strictly from their own
    config_dir — a same-named profile in the other dir is a distinct file
    and must not hide either one (covers the real collision this machine
    has: /etc/wireguard/amneziawg.conf alongside /etc/amnezia/amneziawg/)."""
    from providers import wireguard
    from providers.wireguard import AmneziaWGProvider, WireGuardProvider

    wg_dir = tmp_path / "wireguard"
    awg_dir = tmp_path / "amneziawg"
    wg_dir.mkdir()
    awg_dir.mkdir()
    (wg_dir / "amneziawg.conf").write_text("[Peer]\nEndpoint = 1.2.3.4:51820\n")
    (wg_dir / "plain.conf").write_text("[Peer]\nEndpoint = 5.6.7.8:51820\n")
    (awg_dir / "amneziawg.conf").write_text("[Peer]\nEndpoint = 1.2.3.4:51821\nJc = 4\n")

    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: [])

    wg = WireGuardProvider()
    wg.config_dir = wg_dir
    wg.other_config_dirs = (awg_dir,)
    awg = AmneziaWGProvider()
    awg.config_dir = awg_dir
    awg.other_config_dirs = (wg_dir,)

    assert {c.name for c in wg.connections()} == {"amneziawg", "plain"}
    assert {c.name for c in awg.connections()} == {"amneziawg"}


def test_orphan_active_iface_excluded_if_claimed_by_other_provider(tmp_path, monkeypatch):
    """An active `type wireguard` interface with no matching WireGuard
    config file, but a matching profile under AmneziaWG's dir (kernel
    link-type overlap misattributing it), must not appear as a phantom
    WireGuard connection."""
    from providers import wireguard
    from providers.wireguard import WireGuardProvider

    wg_dir = tmp_path / "wireguard"
    awg_dir = tmp_path / "amneziawg"
    wg_dir.mkdir()
    awg_dir.mkdir()
    (awg_dir / "foo.conf").write_text("[Peer]\nEndpoint = 1.2.3.4:51820\nJc = 4\n")

    monkeypatch.setattr(wireguard, "_active_interfaces", lambda *_: ["foo"])

    wg = WireGuardProvider()
    wg.config_dir = wg_dir
    wg.other_config_dirs = (awg_dir,)
    assert wg.connections() == []

    wg.other_config_dirs = ()  # unclaimed elsewhere: falls back to the orphan listing
    conns = wg.connections()
    assert len(conns) == 1
    assert conns[0].name == "foo" and conns[0].active


def test_amneziawg_uses_awg_quick(monkeypatch):
    from providers.wireguard import AmneziaWGProvider

    provider = AmneziaWGProvider()
    assert provider.name == "AmneziaWG"
    assert provider.quick_bin == "awg-quick"
    assert provider.systemd_prefix == "awg-quick"
    assert provider.link_type == "amneziawg"


# ── ovpn_endpoint ─────────────────────────────────────────────────────────────


def test_ovpn_endpoint_forms(tmp_path):
    def conf(body):
        p = tmp_path / "x.ovpn"
        p.write_text(body)
        return str(p)

    simple = conf("client\nremote vpn.example.com 443\n")
    assert ovpn_endpoint(simple) == ("vpn.example.com", 443)

    with_proto = conf("remote vpn.example.com 1194 udp\n")
    assert ovpn_endpoint(with_proto) == ("vpn.example.com", 1194)

    commented = conf(";remote a.example.com 443\n#remote b.example.com 443\n")
    assert ovpn_endpoint(commented) is None

    no_port = conf("remote vpn.example.com\n")
    assert ovpn_endpoint(no_port) is None

    garbage_port = conf("remote vpn.example.com abc\n")
    assert ovpn_endpoint(garbage_port) is None

    port_too_big = conf("remote vpn.example.com 70000\n")
    assert ovpn_endpoint(port_too_big) is None  # OverflowError would abort a sweep

    assert ovpn_endpoint(conf("client\nnobind\n")) is None
    assert ovpn_endpoint(str(tmp_path / "missing.ovpn")) is None


def test_ovpn_provider_ping_targets(tmp_path, monkeypatch):
    from providers import openvpn
    from providers.openvpn import OpenVPNProvider

    good = tmp_path / "good.conf"
    good.write_text("client\nremote vpn.example.com 1194 udp\n")
    bad = tmp_path / "noremote.conf"
    bad.write_text("client\nnobind\n")
    monkeypatch.setattr(openvpn, "OVPN_DIR", tmp_path)
    targets = OpenVPNProvider().ping_targets()
    assert targets == [("good", "vpn.example.com", 1194)]


# ── ping_mark ─────────────────────────────────────────────────────────────────


def test_ping_mark_states(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    now = time.time()
    ping_file.write_text(
        json.dumps(
            {
                "up": {"ms": 42.0, "at": now},
                "down": {"ms": None, "at": now},
                "stale": {"ms": 1.0, "at": now - 9999},
            }
        )
    )
    assert happmeta.ping_mark("up") == "✓ 42 ms"
    assert happmeta.ping_mark("down") == "✗"
    assert happmeta.ping_mark("stale") == ""
    assert happmeta.ping_mark("absent") == ""


# ── write_pings (single-writer format, combined targets) ──────────────────────


def test_write_pings_combined_targets(tmp_path, monkeypatch):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)
    measured = {}

    def fake_measure(host, port):
        measured[(host, port)] = True
        return 7.0 if port != 9 else None

    monkeypatch.setattr(happmeta, "measure_ping", fake_measure)
    targets = [("srv-happ", "h.example.com", 443), ("wg", "w.example.com", 51820),
               ("dead", "127.0.0.1", 9)]
    happmeta.write_pings(targets)
    data = json.loads(ping_file.read_text())
    assert data["srv-happ"] == {"ms": 7.0, "at": data["srv-happ"]["at"]}
    assert data["wg"]["ms"] == 7.0
    assert data["dead"]["ms"] is None  # failure recorded for the ✗ mark
    assert set(measured) == {("h.example.com", 443), ("w.example.com", 51820),
                             ("127.0.0.1", 9)}
    assert time.time() - data["updated_at"] < 5


# ── provider_menu labels ──────────────────────────────────────────────────────


def test_provider_menu_labels_show_ping(monkeypatch, tmp_path):
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(vpn_manager.happmeta, "PING_CACHE", ping_file)
    monkeypatch.setattr(vpn_manager.happmeta, "request_ping_update", lambda: None)
    now = time.time()
    ping_file.write_text(
        json.dumps(
            {
                "fast": {"ms": 12.0, "at": now},
                "down": {"ms": None, "at": now},
                "unmeasured": {"ms": 1.0, "at": now - 9999},
            }
        )
    )
    wg = FakeProvider(
        "WireGuard",
        [
            VPNConnection(name="fast", provider="WireGuard", active=False),
            VPNConnection(name="down", provider="WireGuard", active=False),
            VPNConnection(name="unmeasured", provider="WireGuard", active=True),
        ],
    )
    seen = []
    patch_menu_env(monkeypatch, [wg], picks=[])
    monkeypatch.setattr(
        vpn_manager,
        "walker_select",
        lambda options, prompt="VPN": (seen.append(list(options)) or None),
    )
    vpn_manager.provider_menu(wg)
    options = seen[0]
    assert "Connect fast    ✓ 12 ms" in options
    assert "Connect down    ✗" in options
    assert "Disconnect unmeasured" in options  # stale measurement: plain label
    assert not any(o.endswith("unmeasured    ✓ 1 ms") for o in options)


# ── sweep resilience (FIX 1) ──────────────────────────────────────────────────


def test_write_pings_bad_target_does_not_abort_sweep(tmp_path, monkeypatch):
    """A target whose measurement raises (e.g. port out of range slipping
    through) is recorded as a failure; the rest of the sweep completes."""
    ping_file = tmp_path / "ping.json"
    monkeypatch.setattr(happmeta, "PING_CACHE", ping_file)

    def flaky_measure(host, port):
        if port > 65535:
            raise OverflowError("port must be 0-65535")
        return 5.0

    monkeypatch.setattr(happmeta, "measure_ping", flaky_measure)
    happmeta.write_pings([("good", "g.example.com", 443), ("bad", "b.example.com", 70000)])
    data = json.loads(ping_file.read_text())
    assert data["good"]["ms"] == 5.0
    assert data["bad"]["ms"] is None  # recorded as ✗, sweep not aborted
    assert time.time() - data["updated_at"] < 5


def test_collect_ping_targets_skips_broken_provider(monkeypatch):
    """--update-ping combination: a provider whose ping_targets() raises is
    skipped, others still contribute (pattern: update_subscriptions)."""
    broken = FakeProvider("Broken", [])

    def _raise():
        raise RuntimeError("corrupt config state")

    broken.ping_targets = _raise
    ok = FakeProvider("Ok", [])
    ok.ping_targets = lambda: [("ok-conn", "o.example.com", 443)]
    happ_targets = [("happ", "h.example.com", 443)]
    monkeypatch.setattr(vpn_manager.happmeta, "ping_targets", lambda: happ_targets)
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [broken, ok])
    targets = vpn_manager._collect_ping_targets()
    assert ("happ", "h.example.com", 443) in targets
    assert ("ok-conn", "o.example.com", 443) in targets
    assert not any(t[0].startswith("Broken") for t in targets)


# ── elevated config read (FIX 2) ──────────────────────────────────────────────


def _stub_privileged_read(monkeypatch, text, returncode=0):
    """Make base.read_config_text take the sudo-cat path and return `text`."""
    from providers import base

    class DeniedPath:
        def __init__(self, p):
            self._p = str(p)

        def read_text(self, **kwargs):
            raise PermissionError(13, "Permission denied")

        def __str__(self):
            return self._p

    class FakeResult:
        def __init__(self):
            self.returncode = returncode
            self.stdout = text

    ran = []

    def fake_run(cmd, **kwargs):
        ran.append(cmd)
        return FakeResult()

    monkeypatch.setattr(base, "Path", DeniedPath)
    monkeypatch.setattr(base.subprocess, "run", fake_run)
    return ran


def test_elevated_read_fallback_parses_endpoint(monkeypatch):
    ran = _stub_privileged_read(monkeypatch, "[Peer]\nEndpoint = vpn.example.com:51820\n")
    assert wg_endpoint("/etc/wireguard/stale.conf") == ("vpn.example.com", 51820)
    assert ran == [["sudo", "-n", "cat", "/etc/wireguard/stale.conf"]]


def test_elevated_read_fallback_openvpn(monkeypatch):
    ran = _stub_privileged_read(monkeypatch, "client\nremote vpn.example.com 443\n")
    assert ovpn_endpoint("/etc/openvpn/client/stale.conf") == ("vpn.example.com", 443)
    assert ran == [["sudo", "-n", "cat", "/etc/openvpn/client/stale.conf"]]


def test_elevated_read_sudo_failure_returns_none(monkeypatch):
    _stub_privileged_read(monkeypatch, "", returncode=1)
    assert wg_endpoint("/etc/wireguard/stale.conf") is None
    assert ovpn_endpoint("/etc/openvpn/client/stale.conf") is None
