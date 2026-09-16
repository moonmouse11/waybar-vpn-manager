"""Happ (https://happ.su) provider.

Happ runs a privileged daemon (happd) that manages VPN core processes
(xray / sing-box / tun2proxy) over a length-prefixed JSON protocol on the
unix socket /tmp/happd.sock:

    frame  = 4-byte big-endian length + UTF-8 JSON payload

Client -> daemon actions:
    {"action": "list"} -> {"processes": [{"process-id": ..., "running": ...}]}
    {"action": "status", "process-id": "..."} -> {"running": bool, ...}
    {"action": "stop",   "process-id": "..."} -> graceful stop of a managed process

Daemon -> client events (skipped): {"event": "connected", ...}, {"event": "push-token", ...}

The GUI (Happ) itself owns connection state (server choice, config generation),
so "connect" is only possible by launching the GUI — once running, the user
has to press «Connect» there. Disconnect and status work headless via happd.
"""

import json
import socket
import struct
import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider

HAPPD_SOCK = Path("/tmp/happd.sock")
GUI_BIN = Path("/usr/bin/happ")
GUI_CONFIG = Path.home() / ".config" / "Happ.conf"
IFACE_PREFIX = "happ-"

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
