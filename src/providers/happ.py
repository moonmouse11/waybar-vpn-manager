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
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

import config
import happmeta
import logutil

from .base import ActionResult, VPNConnection, VPNProvider

HAPPD_SOCK = Path("/tmp/happd.sock")
GUI_BIN = Path("/usr/bin/happ")
GUI_CONFIG = Path.home() / ".config" / "Happ.conf"
IFACE_PREFIX = "happ-"
XRAY_BIN = Path("/opt/happ/bin/core/xray")
ROUTING_DIR = Path.home() / ".local/share/Happ/routing"

SOCKET_TIMEOUT = 1.5
XRAY_TIMEOUT = 20  # seconds to wait for happd's start ack
# --status polls happd several times per tick (one per happd-backed provider);
# a short file cache cuts that churn — happd logs show constant connect noise.
PROCS_CACHE = Path.home() / ".cache/vpn-manager/happd-procs.json"
PROCS_CACHE_TTL = 3.0  # seconds


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


def _daemon_running_processes(fresh: bool = False) -> list[str]:
    """happd's running managed process ids, with a short cross-process file
    cache (each --status tick is a fresh python process and would otherwise
    open a happd session per happd-backed provider). Pass fresh=True on
    action paths (connect/disconnect) to bypass the cache entirely."""
    if not fresh:
        try:
            cached = json.loads(PROCS_CACHE.read_text())
            if (
                isinstance(cached, dict)
                and isinstance(cached.get("at"), (int, float))
                and isinstance(cached.get("procs"), list)
                and time.time() - cached.get("at", 0) < PROCS_CACHE_TTL
            ):
                return [str(p) for p in cached["procs"]]
        except (OSError, json.JSONDecodeError):
            pass
    resp = _daemon_request("list")
    if not resp or resp.get("status") != "success":
        return []
    procs = [
        p["process-id"]
        for p in resp.get("processes", [])
        if p.get("running") and p.get("process-id")
    ]
    if not fresh:
        try:
            PROCS_CACHE.parent.mkdir(parents=True, exist_ok=True)
            tmp = PROCS_CACHE.with_suffix(".tmp")
            tmp.write_text(json.dumps({"at": time.time(), "procs": procs}))
            os.chmod(tmp, 0o600)
            tmp.replace(PROCS_CACHE)
        except OSError:
            pass
    return procs


KEYS_PROCESS_PREFIX = "xray-keys-"


def _happ_processes(fresh: bool = False) -> list[str]:
    """Happ's own managed processes. The keys providers run their xray
    through the same happd — those must not count as 'Happ connected'
    (phantom server in the menu) nor get stopped by a Happ disconnect."""
    return [p for p in _daemon_running_processes(fresh=fresh) if not p.startswith(KEYS_PROCESS_PREFIX)]


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


def _write_own_keeper_state(state: dict) -> None:
    """Write keeper state only while no other keeper owns the state file.

    On a server switch a stale keeper can exit (or fail) after a new keeper
    already wrote its own state — it must not clobber the newer keeper's
    "connected" with its own "exited"/"error". Ownership is the keeper pid
    recorded in the state; a file without a pid predates this scheme and is
    freely replaceable. (Read-check-write is not atomic; the window is a
    menu-action timescale race, acceptable here.)"""
    current = _read_keeper_state()
    if current is not None and current.get("pid", state["pid"]) != state["pid"]:
        return
    _write_keeper_state(state)


def _open_session() -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.connect(str(HAPPD_SOCK))
    return sock


def _send_frame(sock: socket.socket, frame: dict) -> None:
    payload = json.dumps(frame).encode()
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


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


def run_keeper(server_name: str | None = None) -> None:
    """Long-lived happd session that owns the xray process.

    happd reaps managed processes when the starting client disconnects, so
    this process sends the "start" frame and then holds the socket open,
    monitoring daemon events, until the tunnel goes away (user disconnect,
    daemon restart). Progress is reported via KEEPER_STATE; the menu action
    polls that file for the outcome.
    """
    logutil.log(f"keeper: starting ({server_name or 'last server'})")
    state: dict = {"status": "connecting", "pid": os.getpid()}
    # Unconditional claim: _headless_connect just unlinked KEEPER_STATE and
    # designated this process, so a stale keeper's error/"exited" writes must
    # not win the file in the gap between unlink and this first write —
    # otherwise every later state of ours gets dropped (guarded by pid).
    _write_keeper_state(state)
    try:
        cfg = happmeta.resolve_config(server_name or (_last_server_name() or ""))
        if cfg is None:
            state.update(status="error", message="no config for this server")
            _write_own_keeper_state(state)
            return

        iface = _tun_interface_name(cfg)

        # happd occasionally kills the managed xray without telling us (observed
        # after ~1-9 min, no journal trace). Re-arm the start a few times on an
        # unexpected tunnel death — but never on "happd sent stopped": that is
        # the user's own disconnect and must not be fought.
        max_attempts = 3
        backoff = 3.0
        attempts = 0
        exit_reason = "unknown"
        while True:
            attempts += 1
            sock = _open_session()
            try:
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

                deadline = time.time() + XRAY_TIMEOUT
                while time.time() < deadline:
                    try:
                        frame = _recv_frame(sock)
                    except TimeoutError:
                        # slow happd: a socket timeout must consume the ack
                        # budget, not kill the keeper
                        continue
                    if frame and frame.get("request-id") == request_id:
                        if frame.get("status") in ("started", "success"):
                            break
                        state.update(status="error", message=frame.get("error", str(frame)))
                        _write_own_keeper_state(state)
                        return
                else:
                    state.update(status="error", message="no response from happd")
                    _write_own_keeper_state(state)
                    return

                state.update(status="connected", server=cfg.get("remarks"))
                _write_own_keeper_state(state)
                logutil.log(
                    f"keeper: connected ({state['server']})"
                    + (f", re-arm {attempts}/{max_attempts}" if attempts > 1 else "")
                )

                # Hold the session open; exit when the tunnel disappears.
                sock.settimeout(15)
                exit_reason = "unknown"
                while True:
                    try:
                        frame = _recv_frame(sock)
                    except TimeoutError:
                        if iface and not _iface_exists(iface):
                            exit_reason = f"iface {iface} gone"
                            break
                        continue
                    if frame and frame.get("event") == "stopped":
                        exit_reason = "happd sent stopped"
                        break
            finally:
                sock.close()
            logutil.log(f"keeper: tunnel ended: {exit_reason}")
            if exit_reason != f"iface {iface} gone" or attempts >= max_attempts:
                break
            logutil.log(f"keeper: xray died unexpectedly, re-arming in {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 3, 30)
            current = _read_keeper_state()
            if current is None or current.get("pid") != os.getpid():
                # a disconnect/new keeper removed or replaced the state file
                # while we slept — this keeper no longer owns the session
                logutil.log("keeper: ownership lost, aborting re-arm")
                break
    except (OSError, ConnectionError) as e:
        logutil.log(f"keeper: session error: {e}")
        if state.get("status") == "connecting":
            state.update(status="error", message=str(e))
            _write_own_keeper_state(state)
    except Exception as e:  # noqa: BLE001 - always record keeper failures
        logutil.log(f"keeper: unexpected error: {e}")
        state.update(status="error", message=str(e))
        _write_own_keeper_state(state)
    finally:
        state.update(status="exited")
        _write_own_keeper_state(state)
        logutil.log("keeper: exited")


class HappProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "Happ"

    def connections(self) -> list[VPNConnection]:
        interfaces = _happ_interfaces()
        processes = _happ_processes()
        is_active = bool(interfaces or processes)

        # Full server list from provider subscriptions (+ captured extras).
        # Cache-only on this hot path: --status runs every 3 s and must never
        # block on the network; a background worker refreshes stale caches.
        happmeta.request_subscription_update()
        servers = happmeta.all_servers(allow_fetch=False)
        if not servers:
            return [
                VPNConnection(
                    name=_last_server_name() or "Happ",
                    provider=self.name,
                    active=is_active,
                    interface=interfaces[0] if interfaces else None,
                )
            ]

        # Which server is active? The keeper state knows best.
        active_name = None
        if is_active:
            state = _read_keeper_state()
            if state and state.get("status") == "connected":
                active_name = state.get("server")
            if not active_name:
                active_name = _last_server_name()

        # Exact match, or the unique substring match (GUI names can lack
        # the emoji prefix); ambiguous prefixes mark nothing.
        matched = happmeta.match_server(active_name, servers) if active_name else None
        conns = []
        for server in servers:
            name = server["name"]
            conn_active = matched is not None and name == matched["name"]
            conns.append(
                VPNConnection(
                    name=name,
                    provider=self.name,
                    active=conn_active,
                    interface=interfaces[0] if conn_active and interfaces else None,
                )
            )
        return conns

    @staticmethod
    def _connection_name(interfaces: list[str], processes: list[str]) -> str:
        """Prefer the server name from the keeper state / Happ GUI."""
        state = _read_keeper_state()
        if state and state.get("status") == "connected" and state.get("server"):
            return state["server"]
        if name := _last_server_name():
            return name
        if interfaces:
            return interfaces[0].removeprefix(IFACE_PREFIX)
        if processes:
            return processes[0].removeprefix("happ-")
        return "Happ"

    def connect(self, connection: VPNConnection) -> ActionResult:
        # Headless connect works even while the GUI is running: the GUI just
        # observes the same happd state. Configs come from the provider
        # subscription (merged like the GUI does) or from captures.
        cfg = happmeta.resolve_config(connection.name)
        headless_error = None
        if cfg is not None:
            self._stop_running()  # switch servers if something else is up
            result = self._headless_connect(cfg.get("remarks") or connection.name)
            if result.success:
                return result
            headless_error = result.message
            logutil.log(f"happ headless connect failed, falling back to GUI: {result.message}")

        if _gui_running():
            detail = f" — {headless_error}" if headless_error else ""
            return ActionResult(
                success=False,
                message=f"No captured config / connect failed{detail} — press «Connect» in Happ",
            )
        if not GUI_BIN.exists():
            return ActionResult(success=False, message=f"Happ not found at {GUI_BIN}")
        if not config.load_config().happ_gui_fallback:
            detail = f": {headless_error}" if headless_error else ""
            return ActionResult(
                success=False,
                message=f"Headless connect failed{detail} "
                '("happ_gui_fallback": true in the config launches the GUI instead)',
            )

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

    def _stop_running(self) -> None:
        """Stop managed processes and wait for the tunnel to come down
        (used when switching servers)."""
        processes = _happ_processes(fresh=True)
        if not processes:
            return
        for process_id in processes:
            _daemon_request("stop", **{"process-id": process_id})
        deadline = time.time() + 5
        while time.time() < deadline:
            if not _happ_interfaces():
                return
            time.sleep(0.3)

    def _headless_connect(self, server_name: str) -> ActionResult:
        """Spawn the keeper process and wait for its verdict.

        The keeper allows 20 s for happd's start ack before it reports an
        error, so poll a while longer (25 s) before giving up ourselves."""
        KEEPER_STATE.unlink(missing_ok=True)
        manager = Path(__file__).resolve().parent.parent / "vpn_manager.py"
        subprocess.Popen(
            [sys.executable, str(manager), "--happ-keeper", server_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 25  # happd can be slow to ack
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
        # Unlinking KEEPER_STATE (all branches) aborts a keeper that is
        # sleeping between re-arm attempts — do it FIRST so even a failed
        # stop cannot leave a sleeping keeper behind to resurrect.
        KEEPER_STATE.unlink(missing_ok=True)
        processes = _happ_processes(fresh=True)
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
