import json
import struct
import subprocess
from pathlib import Path

import pytest

from providers import happ


def _frame(obj):
    payload = json.dumps(obj).encode()
    return struct.pack(">I", len(payload)) + payload


class FakeSock:
    """In-memory unix-socket stand-in for _send_frame/_recv_frame: recv()
    returns b"" (peer closed) once the scripted bytes run out; with
    raise_timeout it raises TimeoutError (socket.timeout) instead."""

    def __init__(self, incoming: bytes = b"", raise_timeout: bool = False):
        self._in = incoming
        self._raise_timeout = raise_timeout
        self.sent = b""
        self.closed = False

    def recv(self, n):
        if not self._in:
            if self._raise_timeout:
                raise TimeoutError("socket timeout")
            return b""
        chunk, self._in = self._in[:n], self._in[n:]
        return chunk

    def sendall(self, data):
        self.sent += data

    def settimeout(self, _t):
        pass

    def close(self):
        self.closed = True


class _FrozenTime:
    """run_keeper's request id is f"wm-{time.time_ns()}" — freeze both so a
    scripted fake socket can answer with the matching request id."""

    @staticmethod
    def time():
        return 0.0  # every deadline stays in the future

    @staticmethod
    def time_ns():
        return 12345

    sleep = lambda s: None  # noqa: E731 - time.sleep stand-in


def test_frame_round_trip():
    sock = FakeSock()
    happ._send_frame(sock, {"action": "list"})
    reader = FakeSock(sock.sent)
    assert happ._recv_frame(reader) == {"action": "list"}
    assert reader.recv(1) == b""  # nothing left over


def test_recv_frame_truncated_raises():
    sock = FakeSock(struct.pack(">I", 100) + b"{}")
    with pytest.raises(ConnectionError):
        happ._recv_frame(sock)


def test_recv_frame_malformed_json_returns_none():
    payload = b"not json"
    sock = FakeSock(struct.pack(">I", len(payload)) + payload)
    assert happ._recv_frame(sock) is None


def _run_keeper_env(tmp_path, monkeypatch, sock, cfg):
    """Stub everything around run_keeper; record every state write."""
    import happmeta

    writes = []
    real_write = happ._write_keeper_state

    def recording(state):
        writes.append(dict(state))
        real_write(state)

    monkeypatch.setattr(happ, "KEEPER_STATE", tmp_path / "keeper.json")
    monkeypatch.setattr(happ, "_write_keeper_state", recording)
    monkeypatch.setattr(happmeta, "resolve_config", lambda name, **kw: cfg)
    monkeypatch.setattr(happ, "_open_session", lambda: sock)
    monkeypatch.setattr(happ, "_routing_asset_dir", lambda: None)
    monkeypatch.setattr(happ, "xray_config_error", lambda cfg, asset_dir: None)
    monkeypatch.setattr(happ, "notify_failure", lambda title, message: None)
    monkeypatch.setattr(happ, "_iface_exists", lambda name: True)
    monkeypatch.setattr(happ, "time", _FrozenTime)
    return writes


def _run_keeper_env_factory(tmp_path, monkeypatch, factory, cfg):
    """Like _run_keeper_env, but _open_session calls factory() — a FRESH
    fake socket per session (needed for re-arm tests)."""
    import happmeta

    writes = []
    real_write = happ._write_keeper_state

    def recording(state):
        writes.append(dict(state))
        real_write(state)

    monkeypatch.setattr(happ, "KEEPER_STATE", tmp_path / "keeper.json")
    monkeypatch.setattr(happ, "_write_keeper_state", recording)
    monkeypatch.setattr(happmeta, "resolve_config", lambda name, **kw: cfg)
    monkeypatch.setattr(happ, "_open_session", factory)
    monkeypatch.setattr(happ, "_routing_asset_dir", lambda: None)
    monkeypatch.setattr(happ, "xray_config_error", lambda cfg, asset_dir: None)
    monkeypatch.setattr(happ, "notify_failure", lambda title, message: None)
    monkeypatch.setattr(happ, "_iface_exists", lambda name: False)
    monkeypatch.setattr(happ, "time", _FrozenTime)
    return writes


def test_run_keeper_skips_foreign_request_id_and_connects(tmp_path, monkeypatch):
    sock = FakeSock(
        # a response for another request must be skipped, not acted on
        _frame({"request-id": "wm-other", "status": "failed", "error": "ignore me"})
        # the matching ack -> connected; then the peer closes the session
        + _frame({"request-id": "wm-12345", "status": "started"})
    )
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, cfg)

    happ.run_keeper("S")

    statuses = [w["status"] for w in writes]
    assert statuses[0] == "connecting"
    assert "connected" in statuses
    assert statuses[-1] == "exited"
    connected = next(w for w in writes if w["status"] == "connected")
    assert connected["server"] == "S"
    assert sock.closed


def test_run_keeper_error_ack_writes_error_state(tmp_path, monkeypatch):
    sock = FakeSock(_frame({"request-id": "wm-12345", "status": "failed", "error": "boom"}))
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, {"remarks": "S", "inbounds": []})

    happ.run_keeper("S")

    error = next(w for w in writes if w["status"] == "error")
    assert "boom" in error["message"]
    assert writes[-1]["status"] == "exited"


def test_run_keeper_claim_wins_over_stale_gap_write(tmp_path, monkeypatch):
    """Un-claim window: _headless_connect unlinks KEEPER_STATE and designates
    this keeper, so its initial claim must be unconditional — a stale keeper's
    error/"exited" write that landed in the unlink->claim gap (here seeded as
    the pre-existing file) must not own the file and must not drop any of the
    new keeper's later states."""
    import os

    stale = {"status": "exited", "pid": 999999}
    (tmp_path / "keeper.json").write_text(json.dumps(stale))
    sock = FakeSock(_frame({"request-id": "wm-12345", "status": "started"}))
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, cfg)

    happ.run_keeper("S")

    final = json.loads((tmp_path / "keeper.json").read_text())
    assert final["pid"] == os.getpid()  # the stale gap write does not own the file
    assert final["status"] == "exited"  # and every one of our states landed
    assert any(w["status"] == "connected" for w in writes)


def test_keeper_rearms_on_iface_gone(tmp_path, monkeypatch):
    """iface gone -> sleep -> ownership re-check -> a SECOND start frame on a
    fresh session; the keeper ends in "exited"."""
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    socks = []

    def factory():
        # session 1: ack, then socket timeouts with the iface gone; session 2:
        # ack, then happd closes the connection -> keeper exits (no 3rd arm)
        sock = FakeSock(
            _frame({"request-id": "wm-12345", "status": "started"}),
            raise_timeout=(len(socks) == 0),
        )
        socks.append(sock)
        return sock

    writes = _run_keeper_env_factory(tmp_path, monkeypatch, factory, cfg)

    happ.run_keeper("S")

    assert len(socks) == 2
    starts = [s for s in socks if b'"action": "start"' in s.sent]
    assert len(starts) == 2  # the keeper re-armed after the iface went away
    assert writes[-1]["status"] == "exited"


def test_keeper_aborts_rearm_when_ownership_lost(tmp_path, monkeypatch):
    """A foreign pid claiming KEEPER_STATE during the backoff sleep (a new
    keeper from a server switch, or disconnect invalidation) must abort the
    re-arm — exactly ONE start frame, no resurrection."""
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    socks = []

    def factory():
        sock = FakeSock(
            _frame({"request-id": "wm-12345", "status": "started"}),
            raise_timeout=True,
        )
        socks.append(sock)
        return sock

    _run_keeper_env_factory(tmp_path, monkeypatch, factory, cfg)

    def seize_ownership(seconds):
        # simulate a newer keeper claiming the state file mid-sleep
        (tmp_path / "keeper.json").write_text(json.dumps({"status": "connecting", "pid": 424242}))

    monkeypatch.setattr(_FrozenTime, "sleep", staticmethod(seize_ownership))
    happ.run_keeper("S")

    starts = [s for s in socks if b'"action": "start"' in s.sent]
    assert len(starts) == 1  # ownership lost -> never re-armed


def test_keeper_no_rearm_on_stopped(tmp_path, monkeypatch):
    """happd's own "stopped" event is the user's disconnect — the keeper
    must NOT re-arm; exactly one start frame is sent."""
    sock = FakeSock(
        _frame({"request-id": "wm-12345", "status": "started"})
        + _frame({"event": "stopped"})
    )
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, cfg)

    happ.run_keeper("S")

    assert sock.sent.count(b'"action": "start"') == 1
    assert writes[-1]["status"] == "exited"


def test_guarded_write_respects_foreign_owner(tmp_path, monkeypatch):
    """Race A (server switch): a stale keeper exiting AFTER the new keeper
    claimed the file must not overwrite the newer keeper's state."""
    import os

    state_path = tmp_path / "keeper.json"
    foreign = {"status": "connected", "server": "New", "pid": 999999}
    state_path.write_text(json.dumps(foreign))
    monkeypatch.setattr(happ, "KEEPER_STATE", state_path)

    happ._write_own_keeper_state({"status": "exited", "pid": os.getpid()})

    assert json.loads(state_path.read_text()) == foreign


def _server(name):
    return {
        "remarks": name,
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {"vnext": [{"address": "h", "port": 1}]},
                "streamSettings": {"network": "tcp", "security": "reality"},
            },
        ],
    }


def _patch_env(monkeypatch, tmp_path, servers, interfaces, processes, last, keeper_status):
    """Stub happmeta so no network/files are touched."""
    import happmeta

    monkeypatch.setattr(happmeta, "all_servers", lambda *a, **k: servers)
    monkeypatch.setattr(happmeta, "request_subscription_update", lambda: None)
    monkeypatch.setattr(
        happmeta, "resolve_config", lambda name, **kw: _server(name) if name else None
    )
    monkeypatch.setattr(happ, "_happ_interfaces", lambda: interfaces)
    monkeypatch.setattr(happ, "_daemon_running_processes", lambda fresh=False: processes)
    monkeypatch.setattr(happ, "_last_server_name", lambda: last)
    state = tmp_path / "keeper.json"
    if keeper_status is not None:
        state.write_text(json.dumps(keeper_status))
    monkeypatch.setattr(happ, "KEEPER_STATE", state)


def test_connections_keys_process_is_not_happ(tmp_path, monkeypatch):
    """The keys providers run their xray through the same happd — a
    'xray-keys-*' process must not mark any Happ server active (phantom
    connection in the menu), even with a stale connected keeper state."""
    servers = [
        {"name": "🇩🇪 Germany 1", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    keeper = {"status": "connected", "server": "🇩🇪 Germany 1"}
    _patch_env(monkeypatch, tmp_path, servers, [], ["xray-keys-ss"], None, keeper)
    conns = happ.HappProvider().connections()
    assert not any(c.active for c in conns)


def test_daemon_procs_file_cache(monkeypatch, tmp_path):
    """--status ticks are fresh processes; the file cache must collapse
    repeated happd 'list' queries within the TTL into one."""
    import json as _json

    cache = tmp_path / "procs.json"
    monkeypatch.setattr(happ, "PROCS_CACHE", cache)
    calls = {"n": 0}

    def fake_request(action, **kw):
        calls["n"] += 1
        return {"status": "success", "processes": [{"process-id": "xray-core", "running": True}]}

    monkeypatch.setattr(happ, "_daemon_request", fake_request)
    assert happ._daemon_running_processes() == ["xray-core"]
    assert happ._daemon_running_processes() == ["xray-core"]  # served from cache
    assert calls["n"] == 1
    # stale cache -> requery
    stale = _json.loads(cache.read_text())
    stale["at"] = 0
    cache.write_text(_json.dumps(stale))
    assert happ._daemon_running_processes() == ["xray-core"]
    assert calls["n"] == 2


def test_procs_cache_corrupt_at(tmp_path, monkeypatch):
    """A cache file with a non-numeric "at" must fall through to a live
    happd query instead of raising TypeError."""
    import json as _json

    cache = tmp_path / "procs.json"
    cache.write_text(_json.dumps({"at": "x", "procs": []}))
    monkeypatch.setattr(happ, "PROCS_CACHE", cache)
    calls = {"n": 0}

    def fake_request(action, **kw):
        calls["n"] += 1
        return {"status": "success", "processes": [{"process-id": "xray-core", "running": True}]}

    monkeypatch.setattr(happ, "_daemon_request", fake_request)
    assert happ._daemon_running_processes() == ["xray-core"]
    assert calls["n"] == 1


def test_connections_lists_subscription_servers(tmp_path, monkeypatch):
    servers = [
        {"name": "🇦🇹 Austria", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇫🇮 Finland", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    _patch_env(monkeypatch, tmp_path, servers, [], [], None, None)
    conns = happ.HappProvider().connections()
    assert [c.name for c in conns] == ["🇦🇹 Austria", "🇫🇮 Finland"]
    assert not any(c.active for c in conns)


def test_connections_marks_active_from_keeper(tmp_path, monkeypatch):
    servers = [
        {"name": "🇩🇪 Germany 1", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇩🇪 Germany 4", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    keeper = {"status": "connected", "server": "🇩🇪 Germany 4"}
    _patch_env(monkeypatch, tmp_path, servers, ["happ-xray"], ["xray-core"], "x", keeper)
    conns = happ.HappProvider().connections()
    active = [c.name for c in conns if c.active]
    assert active == ["🇩🇪 Germany 4"]
    assert conns[1].interface == "happ-xray"


def test_connections_active_prefix_marks_only_exact(tmp_path, monkeypatch):
    # "Germany" must not light up just because "Germany 1" is connected.
    servers = [
        {"name": "🇩🇪 Germany", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇩🇪 Germany 1", "provider_id": "1", "provider_name": "P", "config": {}},
        {"name": "🇩🇪 Germany 11", "provider_id": "1", "provider_name": "P", "config": {}},
    ]
    keeper = {"status": "connected", "server": "🇩🇪 Germany 1"}
    _patch_env(monkeypatch, tmp_path, servers, ["happ-xray"], ["xray-core"], None, keeper)
    conns = happ.HappProvider().connections()
    active = [c.name for c in conns if c.active]
    assert active == ["🇩🇪 Germany 1"]


def test_connections_active_gui_name_without_emoji(tmp_path, monkeypatch):
    # Happ.conf lastServerName can lack the emoji prefix; the unique
    # substring candidate still gets marked.
    servers = [{"name": "🇪🇪 Estonia", "provider_id": "1", "provider_name": "P", "config": {}}]
    _patch_env(monkeypatch, tmp_path, servers, ["happ-xray"], ["xray-core"], "Estonia", None)
    conns = happ.HappProvider().connections()
    assert [c.name for c in conns if c.active] == ["🇪🇪 Estonia"]


def test_connections_empty_falls_back_to_last(tmp_path, monkeypatch):
    _patch_env(monkeypatch, tmp_path, [], [], [], "⭐Germany 9⭐", None)
    conns = happ.HappProvider().connections()
    assert len(conns) == 1 and conns[0].name == "⭐Germany 9⭐"


def test_tun_interface_name():
    cfg = {
        "inbounds": [
            {"protocol": "socks", "settings": {}},
            {"protocol": "tun", "settings": {"name": "happ-xray"}},
        ]
    }
    assert happ._tun_interface_name(cfg) == "happ-xray"
    assert happ._tun_interface_name({"inbounds": [{"protocol": "socks"}]}) is None


_CLASH = [
    {"name": "🇩🇪 Germany", "provider_id": "1", "provider_name": "P1", "config": {}},
    {"name": "🇩🇪 Germany", "provider_id": "2", "provider_name": "P2", "config": {}},
]


def test_connections_carry_subscription_identity(tmp_path, monkeypatch):
    _patch_env(monkeypatch, tmp_path, _CLASH, [], [], None, None)
    conns = happ.HappProvider().connections()
    assert [(c.subscription_id, c.subscription_name) for c in conns] == [("1", "P1"), ("2", "P2")]


def test_connections_name_clash_marks_only_keeper_provider(tmp_path, monkeypatch):
    keeper = {"status": "connected", "server": "🇩🇪 Germany", "provider_id": "2"}
    _patch_env(monkeypatch, tmp_path, _CLASH, ["happ-xray"], ["xray-core"], None, keeper)
    conns = happ.HappProvider().connections()
    assert [c.subscription_id for c in conns if c.active] == ["2"]


def test_connections_name_clash_without_provider_marks_one(tmp_path, monkeypatch):
    # old keeper state / GUI connect: no provider_id — never light up both
    keeper = {"status": "connected", "server": "🇩🇪 Germany"}
    _patch_env(monkeypatch, tmp_path, _CLASH, ["happ-xray"], ["xray-core"], None, keeper)
    conns = happ.HappProvider().connections()
    assert len([c for c in conns if c.active]) == 1


def test_run_keeper_resolves_and_records_provider(tmp_path, monkeypatch):
    import happmeta

    sock = FakeSock(_frame({"request-id": "wm-12345", "status": "started"}))
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, cfg)
    asked = []
    monkeypatch.setattr(
        happmeta, "resolve_config", lambda name, **kw: asked.append(kw.get("provider_id")) or cfg
    )

    happ.run_keeper("S", "2")

    assert asked == ["2"]
    connected = next(w for w in writes if w["status"] == "connected")
    assert connected["provider_id"] == "2"


def test_connect_passes_provider_to_resolve_and_keeper(tmp_path, monkeypatch):
    import happmeta
    from providers.base import ActionResult, VPNConnection

    asked = []
    monkeypatch.setattr(
        happmeta,
        "resolve_config",
        lambda name, **kw: asked.append(kw.get("provider_id")) or {"remarks": name},
    )
    prov = happ.HappProvider()
    monkeypatch.setattr(prov, "_stop_running", lambda: None)
    keeper_calls = []
    monkeypatch.setattr(
        prov,
        "_headless_connect",
        lambda name, provider_id=None: keeper_calls.append((name, provider_id))
        or ActionResult(True, "ok"),
    )
    conn = VPNConnection(name="S", provider="Happ", active=False, subscription_id="2")
    assert prov.connect(conn).success
    assert asked == ["2"]
    assert keeper_calls == [("S", "2")]


def test_headless_connect_passes_provider_on_command_line(tmp_path, monkeypatch):
    monkeypatch.setattr(happ, "KEEPER_STATE", tmp_path / "keeper.json")
    spawned = []

    def fake_popen(cmd, **kw):
        spawned.append(cmd)
        (tmp_path / "keeper.json").write_text(json.dumps({"status": "connected", "server": "S"}))

    monkeypatch.setattr(happ.subprocess, "Popen", fake_popen)
    assert happ.HappProvider()._headless_connect("S", "2").success
    assert spawned[0][-3:] == ["--happ-keeper", "S", "2"]


class _XrayRun:
    def __init__(self, returncode=0, output="Configuration OK.", exc=None):
        self.returncode, self.output, self.exc = returncode, output, exc
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append((cmd, kw))
        if self.exc:
            raise self.exc
        return subprocess.CompletedProcess(cmd, self.returncode, self.output, "")


def test_xray_config_error_reports_xray_reason_without_generic_prefix(monkeypatch):
    run = _XrayRun(
        23,
        "Xray 26.9.9\nFailed to start: main: failed to load config files: [stdin:] > "
        "infra/conf: failed to build outbound config with tag dns-out > "
        'common/errors: The feature outbound "proxySettings" has been removed',
    )
    monkeypatch.setattr(happ.subprocess, "run", run)
    err = happ.xray_config_error({"outbounds": []}, Path("/assets"))
    assert err.startswith("infra/conf: failed to build outbound config with tag dns-out")
    assert "proxySettings" in err
    cmd, kw = run.calls[0]
    assert cmd == [str(happ.XRAY_BIN), "run", "-test", "-c", "stdin:"]
    assert json.loads(kw["input"]) == {"outbounds": []}  # config never touches disk
    assert kw["env"]["XRAY_LOCATION_ASSET"] == "/assets"


def test_xray_config_error_none_when_config_ok(monkeypatch):
    monkeypatch.setattr(happ.subprocess, "run", _XrayRun())
    assert happ.xray_config_error({}, None) is None


@pytest.mark.parametrize(
    "exc", [FileNotFoundError("xray"), subprocess.TimeoutExpired("xray", 10)]
)
def test_xray_config_error_never_blocks_connect_when_check_itself_fails(monkeypatch, exc):
    # a missing/hung xray is happd's problem to report, not a config error
    monkeypatch.setattr(happ.subprocess, "run", _XrayRun(exc=exc))
    assert happ.xray_config_error({}, None) is None


def test_xray_config_error_ignores_failures_after_the_config_loaded(monkeypatch):
    # older xray (26.3.x) `-test` also instantiates the server, i.e. opens the
    # TUN device — unprivileged that fails although the config parsed fine;
    # blocking connect on it would reject every valid config
    run = _XrayRun(23, "Failed to start: main: failed to create server > operation not permitted")
    monkeypatch.setattr(happ.subprocess, "run", run)
    assert happ.xray_config_error({}, None) is None


def test_run_keeper_rejected_config_is_an_error_and_never_started(tmp_path, monkeypatch):
    sock = FakeSock(_frame({"request-id": "wm-12345", "status": "started"}))
    writes = _run_keeper_env(tmp_path, monkeypatch, sock, {"remarks": "S", "inbounds": []})
    monkeypatch.setattr(happ, "xray_config_error", lambda cfg, asset_dir: "bad field")

    happ.run_keeper("S")

    error = next(w for w in writes if w["status"] == "error")
    assert "bad field" in error["message"]  # shown by the menu as a critical notification
    assert b'"action": "start"' not in sock.sent


def test_keeper_notifies_when_tunnel_lost_after_rearms(tmp_path, monkeypatch):
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}

    def factory():
        return FakeSock(_frame({"request-id": "wm-12345", "status": "started"}), raise_timeout=True)

    _run_keeper_env_factory(tmp_path, monkeypatch, factory, cfg)
    notes = []
    monkeypatch.setattr(happ, "notify_failure", lambda title, message: notes.append(message))

    happ.run_keeper("S")

    assert len(notes) == 1 and "S" in notes[0]


def test_keeper_does_not_notify_on_user_disconnect(tmp_path, monkeypatch):
    sock = FakeSock(
        _frame({"request-id": "wm-12345", "status": "started"}) + _frame({"event": "stopped"})
    )
    cfg = {"remarks": "S", "inbounds": [{"protocol": "tun", "settings": {"name": "x"}}]}
    _run_keeper_env(tmp_path, monkeypatch, sock, cfg)
    notes = []
    monkeypatch.setattr(happ, "notify_failure", lambda title, message: notes.append(message))

    happ.run_keeper("S")

    assert notes == []


@pytest.mark.parametrize("mode, tunnel", [("tunnel", True), ("subscription", False)])
def test_run_keeper_builds_config_with_the_configured_dns_mode(tmp_path, monkeypatch, mode, tunnel):
    import config
    import happmeta

    seen = {}
    sock = FakeSock(_frame({"request-id": "wm-12345", "status": "started"}))
    _run_keeper_env(tmp_path, monkeypatch, sock, {"remarks": "S", "inbounds": []})
    monkeypatch.setattr(
        happmeta, "resolve_config", lambda name, **kw: seen.update(kw) or {"remarks": "S"}
    )
    monkeypatch.setattr(happ.config, "load_config", lambda: config.Config(dns_mode=mode))

    happ.run_keeper("S")

    assert seen["tunnel_dns"] is tunnel
