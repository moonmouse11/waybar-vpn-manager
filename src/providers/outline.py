"""Outline (Shadowsocks) provider — headless via happd.

Outline is plain Shadowsocks under the hood. Instead of launching the
electron AppImage (the old behaviour: GUI opens, user clicks, no import,
no ping), imported ss:// keys run as TUN-mode xray-core processes through
the same privileged happd daemon Happ uses — so Outline servers get menu
entries with ✓/✗ ping and killswitch "all" integration for free.

Key format: SIP002 `ss://base64(method:password)@host:port[/?query]#name`
(plus the legacy `ss://base64(json)` form). Keys with plugin=/prefix=
query params are rejected — xray's shadowsocks has no outline-sdk prefix
obfuscation support.
"""

import base64
import binascii
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

import happmeta
import logutil

from .base import ActionResult, VPNConnection, VPNProvider
from .happ import (
    XRAY_BIN,
    _daemon_request,
    _daemon_running_processes,
    _open_session,
    _recv_frame,
    _routing_asset_dir,
    _send_frame,
)

IFACE = "outline-tun0"
PROCESS_ID = "xray-outline"
STORE = Path.home() / ".config/vpn-manager/outline-servers.json"
KEEPER_STATE = Path.home() / ".local/state/vpn-manager/outline-keeper.json"
XRAY_TIMEOUT = 8  # seconds to wait for happd's start ack

# xray shadowsocks methods worth accepting at import time (anything else
# would fail at connect with a core error; better to say it right away)
METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}

_SS_RE = re.compile(r"ss://[^\s'\"]+")


# ── ss:// key parsing ─────────────────────────────────────────────────────────


def _loose_b64(text: str) -> bytes:
    """base64 decode tolerating missing padding and either alphabet."""
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return base64.b64decode(padded)


def _legacy_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"cannot decode legacy key JSON: {e}")
    if not isinstance(data, dict):
        raise ValueError("legacy key is not a JSON object")
    return data


def parse_ss_key(url: str) -> dict:
    """ss:// key -> {"name", "host", "port", "method", "password"}.

    Raises ValueError with a user-facing reason for anything unsupported."""
    rest = url.strip()
    if not rest.lower().startswith("ss://"):
        raise ValueError("not an ss:// key")
    rest = rest[5:]

    name = None
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = urllib.parse.unquote(frag).strip() or None

    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    if query:
        params = urllib.parse.parse_qs(query)
        if params.get("plugin"):
            raise ValueError("plugin= keys are not supported (xray has no such plugin)")
        if params.get("prefix"):
            raise ValueError("prefix-обфускация outline-sdk не поддерживается xray")

    userinfo_b64 = None
    hostpart = ""
    if "@" in rest:
        userinfo_b64, hostpart = rest.rsplit("@", 1)

    def _parse_host_port(text: str) -> tuple[str, int]:
        if text.startswith("["):
            end = text.find("]")
            if end == -1 or end + 1 >= len(text) or text[end + 1] != ":":
                raise ValueError("garbled host:port in key")
            h, p = text[1:end], text[end + 2 :]
        elif ":" in text:
            h, _, p = text.rpartition(":")
        else:
            raise ValueError("garbled host:port in key")
        if not h or not p.isdigit():
            raise ValueError("garbled host:port in key")
        port_n = int(p)
        if not 1 <= port_n <= 65535:
            raise ValueError("port out of range in key")
        return h, port_n

    host = ""
    port = 0
    method = password = ""
    if userinfo_b64 is not None:
        try:
            decoded = _loose_b64(userinfo_b64).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"cannot decode key credentials: {e}")
        if decoded.lstrip().startswith("{"):
            # legacy with explicit host: ss://base64(json)@host:port
            legacy = _legacy_json(decoded)
            method = str(legacy.get("method") or "")
            password = str(legacy.get("password") or "")
            if legacy.get("server"):
                host = str(legacy["server"])
                port = int(legacy.get("server_port") or 0)
            if not host and hostpart:
                host, port = _parse_host_port(hostpart)
        else:
            # SIP002: ss://base64(method:password)@host:port
            if ":" not in decoded:
                raise ValueError("key credentials lack method:password")
            method, password = decoded.split(":", 1)
            host, port = _parse_host_port(hostpart)
    else:
        # legacy: ss://base64(json) — host/port live inside the JSON
        try:
            raw = _loose_b64(rest).decode("utf-8", errors="replace")
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"cannot decode legacy key JSON: {e}")
        legacy = _legacy_json(raw)
        method = str(legacy.get("method") or "")
        password = str(legacy.get("password") or "")
        host = str(legacy.get("server") or "")
        port = int(legacy.get("server_port") or 0)

    if not host or not port or not 1 <= port <= 65535:
        raise ValueError("key has no usable server")

    method = method.lower().strip()
    if method not in METHODS:
        raise ValueError(f"unsupported method {method!r} (xray supports: {', '.join(sorted(METHODS))})")
    if not password:
        raise ValueError("empty password in key")

    return {
        "name": name or f"{host}:{port}",
        "host": host,
        "port": port,
        "method": method,
        "password": password,
    }


# ── Server store (keys carry passwords — keep it 0600) ───────────────────────


def _load_servers() -> list[dict]:
    try:
        data = json.loads(STORE.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    return [s for s in data if isinstance(s, dict) and s.get("host")]


def _save_servers(servers: list[dict]) -> None:
    STORE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE.with_suffix(".tmp")
    tmp.write_text(json.dumps(servers, ensure_ascii=False, indent=1))
    os.chmod(tmp, 0o600)
    tmp.replace(STORE)


def _server_id(server: dict) -> str:
    raw = f"{server['method']}:{server['password']}@{server['host']}:{server['port']}"
    return hashlib.sha1(raw.encode()).hexdigest()[:8]


def add_server(parsed: dict) -> ActionResult:
    """Store a parsed key; identical keys dedupe, same-name keys get a suffix."""
    servers = _load_servers()
    new_id = _server_id(parsed)
    if any(_server_id(s) == new_id for s in servers):
        return ActionResult(False, f"Already imported: {parsed['name']}")
    name = parsed["name"]
    if any(s["name"] == name for s in servers):
        n = 2
        while any(s["name"] == f"{name} ({n})" for s in servers):
            n += 1
        parsed["name"] = f"{name} ({n})"
    servers.append(parsed)
    _save_servers(servers)
    return ActionResult(True, f"Imported: {parsed['name']}")


def _find_server(name: str) -> dict | None:
    servers = _load_servers()
    exact = [s for s in servers if s["name"] == name]
    if exact:
        return exact[0]
    sub = [s for s in servers if name.lower() in s["name"].lower()]
    return sub[0] if len(sub) == 1 else None


# ── xray config ───────────────────────────────────────────────────────────────


def _build_xray_config(server: dict) -> dict:
    """Full TUN-mode xray config with a shadowsocks outbound, composed the
    same way Happ server configs are (shared inbounds/dns/routing)."""
    outbound = {
        "protocol": "shadowsocks",
        "settings": {
            "servers": [
                {
                    "address": server["host"],
                    "port": server["port"],
                    "method": server["method"],
                    "password": server["password"],
                }
            ]
        },
        "tag": "proxy",
    }
    cfg = happmeta.build_runtime_config({"remarks": server["name"], "outbounds": [outbound]})
    # distinct tun from Happ's "happ-xray" (172.19.0.1/30) so both can be
    # told apart and, where routing allows, coexist
    for inbound in cfg.get("inbounds", []):
        if inbound.get("protocol") == "tun":
            inbound["settings"]["name"] = IFACE
            inbound["settings"]["gateway"] = ["172.19.4.1/30"]
    return cfg


# ── Keeper: long-lived happd session owning the xray process ─────────────────


def _write_keeper_state(state: dict, own: bool = False) -> None:
    if own:
        current = _read_keeper_state()
        if current is not None and current.get("pid", state["pid"]) != state["pid"]:
            return  # a newer keeper owns the file
    try:
        KEEPER_STATE.parent.mkdir(parents=True, exist_ok=True)
        tmp = KEEPER_STATE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(KEEPER_STATE)
    except OSError:
        pass


def _read_keeper_state() -> dict | None:
    try:
        data = json.loads(KEEPER_STATE.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def run_keeper(server_id: str) -> None:
    """Send the start frame for one Outline server and hold the session
    open (happd reaps managed processes when the starting client
    disconnects). Mirrors providers.happ.run_keeper."""
    logutil.log(f"outline keeper: starting ({server_id})")
    state: dict = {"status": "connecting", "pid": os.getpid(), "server": server_id}
    _write_keeper_state(state)  # unconditional first claim
    sock: socket.socket | None = None
    try:
        server = next((s for s in _load_servers() if _server_id(s) == server_id), None)
        if server is None:
            state.update(status="error", message="server not found in store")
            _write_keeper_state(state)
            return
        cfg = _build_xray_config(server)
        sock = _open_session()
        request_id = f"wm-outline-{time.time_ns()}"
        params: dict = {
            "action": "start",
            "arguments": [],
            "executable": str(XRAY_BIN),
            "process-id": PROCESS_ID,
            "request-id": request_id,
            "stdin-data": json.dumps(cfg),
        }
        asset_dir = _routing_asset_dir()
        if asset_dir:
            params["environment"] = {"XRAY_LOCATION_ASSET": str(asset_dir)}
        _send_frame(sock, params)

        deadline = time.time() + XRAY_TIMEOUT
        while time.time() < deadline:
            frame = _recv_frame(sock)
            if frame and frame.get("request-id") == request_id:
                if frame.get("status") in ("started", "success"):
                    break
                state.update(status="error", message=frame.get("error", str(frame)))
                _write_keeper_state(state, own=True)
                return
        else:
            state.update(status="error", message="no response from happd")
            _write_keeper_state(state, own=True)
            return

        state.update(status="connected", server=server["name"])
        _write_keeper_state(state, own=True)
        logutil.log(f"outline keeper: connected ({server['name']})")

        sock.settimeout(15)
        while True:
            try:
                frame = _recv_frame(sock)
            except TimeoutError:
                if not Path(f"/sys/class/net/{IFACE}").exists():
                    break
                continue
            if frame and frame.get("event") == "stopped":
                break
    except (OSError, ConnectionError) as e:
        logutil.log(f"outline keeper: session error: {e}")
        if state.get("status") == "connecting":
            state.update(status="error", message=str(e))
            _write_keeper_state(state, own=True)
    except Exception as e:  # noqa: BLE001 - always record keeper failures
        logutil.log(f"outline keeper: unexpected error: {e}")
        state.update(status="error", message=str(e))
    finally:
        if sock:
            sock.close()
        state.update(status="exited")
        _write_keeper_state(state, own=True)
        logutil.log("outline keeper: exited")


# ── Provider ──────────────────────────────────────────────────────────────────


class OutlineProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "Outline"

    def connections(self) -> list[VPNConnection]:
        servers = _load_servers()
        if not servers:
            return []
        active_name = None
        if PROCESS_ID in _daemon_running_processes() or Path(f"/sys/class/net/{IFACE}").exists():
            state = _read_keeper_state()
            if state and state.get("status") in ("connected", "connecting"):
                active_name = state.get("server")
        return [
            VPNConnection(
                name=s["name"],
                provider=self.name,
                active=s["name"] == active_name,
                interface=IFACE if s["name"] == active_name else None,
            )
            for s in servers
        ]

    def ping_targets(self) -> list[tuple[str, str, int]]:
        return [(s["name"], s["host"], s["port"]) for s in _load_servers()]

    def connect(self, connection: VPNConnection) -> ActionResult:
        server = _find_server(connection.name)
        if server is None:
            return ActionResult(False, f"Unknown Outline server: {connection.name}")
        self._stop_running()  # one Outline server at a time
        return self._headless_connect(_server_id(server))

    def _headless_connect(self, server_id: str) -> ActionResult:
        KEEPER_STATE.unlink(missing_ok=True)
        manager = Path(__file__).resolve().parent.parent / "vpn_manager.py"
        subprocess.Popen(
            [sys.executable, str(manager), "--outline-keeper", server_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 12
        while time.time() < deadline:
            state = _read_keeper_state()
            if state:
                if state.get("status") == "connected":
                    return ActionResult(True, f"Connected: {state.get('server', 'Outline')}")
                if state.get("status") == "error":
                    return ActionResult(False, state.get("message", "keeper error"))
                if state.get("status") == "exited":
                    return ActionResult(False, "keeper exited before connecting — see log")
            time.sleep(0.2)
        return ActionResult(False, "keeper timeout — see log")

    def _stop_running(self) -> None:
        if PROCESS_ID not in _daemon_running_processes():
            return
        _daemon_request("stop", **{"process-id": PROCESS_ID})
        deadline = time.time() + 5
        while time.time() < deadline:
            if not Path(f"/sys/class/net/{IFACE}").exists():
                return
            time.sleep(0.3)

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        if PROCESS_ID not in _daemon_running_processes():
            return ActionResult(success=False, message="Outline is not connected")
        resp = _daemon_request("stop", **{"process-id": PROCESS_ID})
        if not resp or resp.get("status") not in ("stopping", "success"):
            error = resp.get("error", "no response") if resp else "happd unreachable"
            return ActionResult(success=False, message=f"Failed to stop: {error}")
        return ActionResult(success=True, message="Disconnected: outline-xray")

    def import_config(self, path: str) -> ActionResult:
        try:
            text = Path(path).read_text(errors="replace")
        except OSError as e:
            return ActionResult(False, f"Cannot read {path}: {e}")
        match = _SS_RE.search(text)
        if not match:
            return ActionResult(False, "No ss:// key found in the file")
        try:
            parsed = parse_ss_key(match.group(0))
        except ValueError as e:
            return ActionResult(False, f"Bad Outline key: {e}")
        return add_server(parsed)
