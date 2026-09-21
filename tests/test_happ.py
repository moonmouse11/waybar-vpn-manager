import json
import struct

import pytest

from providers import happ


def _frame(obj):
    payload = json.dumps(obj).encode()
    return struct.pack(">I", len(payload)) + payload


class FakeSock:
    """In-memory unix-socket stand-in for _send_frame/_recv_frame: recv()
    returns b"" (peer closed) once the scripted bytes run out."""

    def __init__(self, incoming: bytes = b""):
        self._in = incoming
        self.sent = b""
        self.closed = False

    def recv(self, n):
        if not self._in:
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
    monkeypatch.setattr(happmeta, "resolve_config", lambda name: cfg)
    monkeypatch.setattr(happ, "_open_session", lambda: sock)
    monkeypatch.setattr(happ, "_routing_asset_dir", lambda: None)
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
    monkeypatch.setattr(happmeta, "resolve_config", lambda name: _server(name) if name else None)
    monkeypatch.setattr(happ, "_happ_interfaces", lambda: interfaces)
    monkeypatch.setattr(happ, "_daemon_running_processes", lambda: processes)
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
