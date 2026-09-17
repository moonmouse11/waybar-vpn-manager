"""Happ (https://happ.su) provider.

Happ runs a privileged daemon (happd) that manages VPN core processes
(xray / sing-box / tun2proxy) over a length-prefixed JSON protocol on the
unix socket /tmp/happd.sock:

    frame  = 4-byte big-endian length + UTF-8 JSON payload

Client -> daemon actions:
    {"action": "get-privilege"} -> {"privilege-level": 2, ...}
    {"action": "list"} -> {"processes": [{"process-id": ..., "running": ...}]}
    {"action": "status", "process-id": "..."} -> {"running": bool, ...}
    {"action": "stop",   "process-id": "..."} -> graceful stop of a managed process
    {"action": "start",  "process-id": "...", "executable": "...",
     "arguments": [...], "stdin-data": "<core config JSON>",
     "environment": {...}}                      -> spawn a managed core process

Daemon -> client events (skipped): {"event": "started", ...}, {"event": "connected", ...}

Session ownership: happd reaps managed processes when the client connection
that started them disconnects (see "reclaim-session-processes" in the daemon
binary). A headless connect therefore needs a long-lived keeper process that
holds the socket open — see run_keeper() and the --happ-keeper entry point.

Headless connect: the GUI builds an xray config in memory and sends it as
"stdin-data" of a "start" frame. We replay captured configs instead — see
docs/happd-protocol.md and scripts/happd-extract-config.py. Disconnect and
status always work headless via happd.
"""

import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import logutil

from .base import ActionResult, VPNConnection, VPNProvider

HAPPD_SOCK = Path("/tmp/happd.sock")
GUI_BIN = Path("/usr/bin/happ")
GUI_CONFIG = Path.home() / ".config" / "Happ.conf"
IFACE_PREFIX = "happ-"
XRAY_BIN = Path("/opt/happ/bin/core/xray")
ROUTING_DIR = Path.home() / ".local/share/Happ/routing"

# xray configs captured from the GUI <-> happd protocol (see docs/happd-protocol.md
# and scripts/happd-extract-config.py): {server remarks: xray config}
CAPTURED_CONFIGS = Path.home() / ".config/happ-capture/xray-configs.json"

SOCKET_TIMEOUT = 1.5


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _daemon_request(action: str, **params) -> dict | None:
    """Send one framed JSON request to happd and return its response.

    Returns None if the daemon is unreachable or times out.
    """
    if not HAPPD_SOCK.exists():
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(SOCKET_TIMEOUT)
        sock.connect(str(HAPPD_SOCK))
    except OSError:
        return None

    def recv_frame() -> dict | None:
        hdr = b""
        while len(hdr) < 4:
            chunk = sock.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        (length,) = struct.unpack(">I", hdr)
        body = b""
        while len(body) < length:
            chunk = sock.recv(length - len(body))
            if not chunk:
                return None
            body += chunk
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return None

    try:
        payload = json.dumps({"action": action, **params}).encode()
        sock.sendall(struct.pack(">I", len(payload)) + payload)
        while True:
            resp = recv_frame()
            if resp is None:
                return None
            # skip daemon-initiated events (they have "event" and no "status")
            if "event" in resp and "status" not in resp:
                continue
            return resp
    except (TimeoutError, OSError):
        return None
    finally:
        sock.close()


def _daemon_running_processes() -> list[str]:
    resp = _daemon_request("list")
    if not resp or resp.get("status") != "success":
        return []
    return [
        p["process-id"]
        for p in resp.get("processes", [])
        if p.get("running") and p.get("process-id")
    ]


def _happ_interfaces() -> list[str]:
    code, out = _run(["ip", "-o", "link", "show"])
    if code != 0:
        return []
    interfaces = []
    for line in out.splitlines():
        parts = line.split(":", 2)
        if len(parts) >= 2 and parts[1].strip().startswith(IFACE_PREFIX):
            interfaces.append(parts[1].strip())
    return interfaces


def _gui_running() -> bool:
    for name in ("happ", "Happ"):
        code, _ = _run(["pgrep", "-x", name])
        if code == 0:
            return True
    return False


def _last_server_name() -> str | None:
    """Name of the last used server, as remembered by the Happ GUI."""
    try:
        for line in GUI_CONFIG.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("lastServerName="):
                name = line.split("=", 1)[1].strip()
                return name or None
    except OSError:
        pass
    return None


def _captured_config(server_name: str | None) -> dict | None:
    """Find a captured xray config for the given server name (fuzzy match)."""
    if not server_name:
        return None
    try:
        configs = json.loads(CAPTURED_CONFIGS.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(configs, dict):
        return None
    if server_name in configs:
        return configs[server_name]
    for name, cfg in configs.items():
        if server_name in name or name in server_name:
            return cfg
    return None


def _routing_asset_dir() -> Path | None:
    """Directory with geoip/geosite data passed as XRAY_LOCATION_ASSET."""
    try:
        for geo in sorted(ROUTING_DIR.glob("*/*/geoip.dat")):
            return geo.parent
    except OSError:
        pass
    return None


def _tun_interface_name(xray_config: dict) -> str | None:
    for inbound in xray_config.get("inbounds", []):
        if inbound.get("protocol") == "tun":
            return inbound.get("settings", {}).get("name")
    return None


# ── Headless connect via a long-lived keeper session ─────────────────────────

KEEPER_STATE = Path.home() / ".local/state/vpn-manager/happ-keeper.json"


def _write_keeper_state(state: dict) -> None:
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


def _open_session() -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect(str(HAPPD_SOCK))
    return sock


def _send_frame(sock: socket.socket, frame: dict) -> None:
    payload = json.dumps(frame).encode()
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_frame(sock: socket.socket) -> dict | None:
    """One framed JSON message; None on malformed payload. Raises OSError/
    socket.timeout on connection problems."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("happd closed the connection")
        hdr += chunk
    (length,) = struct.unpack(">I", hdr)
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise ConnectionError("happd closed the connection")
        body += chunk
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def run_keeper() -> None:
    """Long-lived happd session that owns the xray process.

    happd reaps managed processes when the starting client disconnects, so
    this process sends the "start" frame and then holds the socket open,
    monitoring daemon events, until the tunnel goes away (user disconnect,
    daemon restart). Progress is reported via KEEPER_STATE; the menu action
    polls that file for the outcome.
    """
    logutil.log("keeper: starting")
    state: dict = {"status": "connecting"}
    _write_keeper_state(state)
    sock: socket.socket | None = None
    try:
        cfg = _captured_config(_last_server_name())
        if cfg is None:
            state.update(status="error", message="no captured xray config")
            _write_keeper_state(state)
            return

        iface = _tun_interface_name(cfg)
        sock = _open_session()
        request_id = f"wm-{time.time_ns()}"
        params: dict = {
            "action": "start",
            "arguments": [],
            "executable": str(XRAY_BIN),
            "process-id": "xray-core",
            "request-id": request_id,
            "stdin-data": json.dumps(cfg),
        }
        asset_dir = _routing_asset_dir()
        if asset_dir:
            params["environment"] = {"XRAY_LOCATION_ASSET": str(asset_dir)}
        _send_frame(sock, params)

        deadline = time.time() + 8
        while time.time() < deadline:
            frame = _recv_frame(sock)
            if frame and frame.get("request-id") == request_id:
                if frame.get("status") in ("started", "success"):
                    break
                state.update(status="error", message=frame.get("error", str(frame)))
                _write_keeper_state(state)
                return
        else:
            state.update(status="error", message="no response from happd")
            _write_keeper_state(state)
            return

        state.update(status="connected", server=cfg.get("remarks"))
        _write_keeper_state(state)
        logutil.log(f"keeper: connected ({state['server']})")

        # Hold the session open; exit when the tunnel disappears.
        sock.settimeout(15)
        while True:
            try:
                frame = _recv_frame(sock)
            except TimeoutError:
                if iface and not Path(f"/sys/class/net/{iface}").exists():
                    break
                continue
            if frame and frame.get("event") == "stopped":
                break
    except (OSError, ConnectionError) as e:
        logutil.log(f"keeper: session error: {e}")
        if state.get("status") == "connecting":
            state.update(status="error", message=str(e))
            _write_keeper_state(state)
    except Exception as e:  # noqa: BLE001 - always record keeper failures
        logutil.log(f"keeper: unexpected error: {e}")
        state.update(status="error", message=str(e))
        _write_keeper_state(state)
    finally:
        if sock:
            sock.close()
        state.update(status="exited")
        _write_keeper_state(state)
        logutil.log("keeper: exited")


class HappProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "Happ"

    def connections(self) -> list[VPNConnection]:
        interfaces = _happ_interfaces()
        processes = _daemon_running_processes()

        if interfaces or processes:
            # several happ-* interfaces belong to a single connection — collapse them
            return [
                VPNConnection(
                    name=self._connection_name(interfaces, processes),
                    provider=self.name,
                    active=True,
                    interface=interfaces[0] if interfaces else None,
                )
            ]

        return [
            VPNConnection(
                name=_last_server_name() or "Happ",
                provider=self.name,
                active=False,
            )
        ]

    @staticmethod
    def _connection_name(interfaces: list[str], processes: list[str]) -> str:
        """Prefer the server name from the Happ GUI; fall back to interface/process."""
        if name := _last_server_name():
            return name
        if interfaces:
            return interfaces[0].removeprefix(IFACE_PREFIX)
        if processes:
            return processes[0].removeprefix("happ-")
        return "Happ"

    def connect(self, connection: VPNConnection) -> ActionResult:
        if _gui_running():
            return ActionResult(
                success=False,
                message="Happ is already running — press «Connect» in the Happ window",
            )

        # Prefer headless connect: replay the captured xray config through
        # happd with a long-lived keeper session (no GUI needed).
        # Falls back to launching the GUI.
        if _captured_config(_last_server_name()) is not None:
            result = self._headless_connect()
            if result.success:
                return result
            logutil.log(f"happ headless connect failed, falling back to GUI: {result.message}")

        if not GUI_BIN.exists():
            return ActionResult(success=False, message=f"Happ not found at {GUI_BIN}")

        subprocess.Popen(
            [str(GUI_BIN)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return ActionResult(
            success=True,
            message="Happ started — connecting to last used server…",
        )

    def _headless_connect(self) -> ActionResult:
        """Spawn the keeper process and wait for its verdict (max ~6 s)."""
        KEEPER_STATE.unlink(missing_ok=True)
        manager = Path(__file__).resolve().parent.parent / "vpn_manager.py"
        subprocess.Popen(
            [sys.executable, str(manager), "--happ-keeper"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 6
        while time.time() < deadline:
            state = _read_keeper_state()
            if state:
                if state.get("status") == "connected":
                    return ActionResult(True, f"Connected: {state.get('server', 'Happ')}")
                if state.get("status") == "error":
                    return ActionResult(False, state.get("message", "keeper error"))
                if state.get("status") == "exited":
                    return ActionResult(False, "keeper exited before connecting — see log")
            time.sleep(0.2)
        return ActionResult(False, "keeper timeout — see log")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        processes = _daemon_running_processes()
        if not processes:
            return ActionResult(success=False, message="Happ is not connected")

        stopped = []
        for process_id in processes:
            resp = _daemon_request("stop", **{"process-id": process_id})
            if resp and resp.get("status") in ("stopping", "success"):
                stopped.append(process_id)
            else:
                error = resp.get("error", "no response") if resp else "happd unreachable"
                return ActionResult(
                    success=False,
                    message=f"Failed to stop {process_id}: {error}",
                )

        return ActionResult(success=True, message=f"Disconnected: {', '.join(stopped)}")

    def import_config(self, path: str) -> ActionResult:
        return ActionResult(
            success=False,
            message="Happ does not support config import — manage subscriptions in the Happ app",
        )
