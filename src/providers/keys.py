"""Manual key providers — Shadowsocks (ss://) and VLESS (vless://) servers.

Imported keys run as TUN-mode xray-core processes through the same
privileged happd daemon Happ uses, so these servers get menu entries with
✓/✗ ping and killswitch "all" integration for free. Replaces the old
Outline AppImage launcher (the Outline GUI rejects vless keys and legacy
shadowsocks ciphers outright). One provider instance per protocol, both
backed by the same store; each kind gets its own happd process id, tun
interface and keeper state.

ss:// SIP002 `ss://base64(method:password)@host:port[/?query]#name` (plus
the legacy base64-JSON form); keys with plugin=/prefix= are rejected —
xray has no outline-sdk prefix obfuscation.

vless:// `vless://uuid@host:port?security=…&type=…#name` with the standard
share-link query params (reality/tls, grpc/ws/tcp).
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

IFACES = {"ss": "keys-ss-tun0", "vless": "keys-vless-tun0"}  # ≤15 chars (kernel IFNAMSIZ)
LABELS = {"ss": "Shadowsocks", "vless": "VLESS"}
STORE = Path.home() / ".config/vpn-manager/keys.json"
KEEPER_STATE_DIR = Path.home() / ".local/state/vpn-manager"
XRAY_TIMEOUT = 20  # seconds to wait for happd's start ack


def _kind_meta(kind: str) -> tuple[str, str, Path]:
    """(happd process-id, tun interface, keeper state path) for a kind."""
    return (
        f"xray-keys-{kind}",
        IFACES[kind],
        KEEPER_STATE_DIR / f"keys-keeper-{kind}.json",
    )

# xray 26 shadowsocks methods — AEAD only; the legacy stream ciphers
# (aes-*-cfb/ctr, chacha20, salsa20, rc4-md5) were REMOVED from the core,
# so OutlineKeys-style cfb keys are unusable on any modern core
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

_KEY_RE = re.compile(r"(?:ss|vless)://[^\s'\"]+")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


# ── key parsing ───────────────────────────────────────────────────────────────


def _loose_b64(text: str) -> bytes:
    """base64 decode tolerating missing padding and either alphabet."""
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return base64.b64decode(padded)


def _parse_host_port(text: str) -> tuple[str, int]:
    if text.startswith("["):
        end = text.find("]")
        if end == -1 or end + 1 >= len(text) or text[end + 1] != ":":
            raise ValueError("garbled host:port in key")
        host, port_s = text[1:end], text[end + 2 :]
    elif ":" in text:
        host, _, port_s = text.rpartition(":")
    else:
        raise ValueError("garbled host:port in key")
    if not host or not port_s.isdigit():
        raise ValueError("garbled host:port in key")
    port = int(port_s)
    if not 1 <= port <= 65535:
        raise ValueError("port out of range in key")
    return host, port


def _split_fragment_query(rest: str) -> tuple[str, str, str | None]:
    """rest -> (rest, query, name) splitting off #fragment and ?query.
    Key-shop names carry a site attribution suffix ("Canada #41259 /
    OutlineKeys.com") — drop it, it makes menu rows unreadable."""
    name = None
    if "#" in rest:
        rest, frag = rest.split("#", 1)
        name = urllib.parse.unquote(frag).strip() or None
        if name and " / " in name:
            name = name.split(" / ", 1)[0].strip() or None
    query = ""
    if "?" in rest:
        rest, query = rest.split("?", 1)
    return rest, query, name


def _legacy_json(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"cannot decode legacy key JSON: {e}")
    if not isinstance(data, dict):
        raise ValueError("legacy key is not a JSON object")
    return data


def parse_ss_key(url: str) -> dict:
    """ss:// key -> {"kind": "ss", "name", "host", "port", "method", "password"}.

    Raises ValueError with a user-facing reason for anything unsupported."""
    rest = url.strip()
    if not rest.lower().startswith("ss://"):
        raise ValueError("not an ss:// key")
    rest, query, name = _split_fragment_query(rest[5:])

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
        "kind": "ss",
        "name": name or f"{host}:{port}",
        "host": host,
        "port": port,
        "method": method,
        "password": password,
    }


def parse_vless_key(url: str) -> dict:
    """vless:// share link -> server dict (kind "vless", outbound params)."""
    rest = url.strip()
    if not rest.lower().startswith("vless://"):
        raise ValueError("not a vless:// key")
    rest, query, name = _split_fragment_query(rest[8:])
    rest = rest.split("/", 1)[0]  # tolerate trailing junk after host:port
    if "@" not in rest:
        raise ValueError("garbled vless key (no @)")
    uuid, hostpart = rest.rsplit("@", 1)
    uuid = uuid.strip()
    if not _UUID_RE.match(uuid):
        raise ValueError("vless key has an invalid UUID")
    host, port = _parse_host_port(hostpart)

    params = urllib.parse.parse_qs(query)

    def p(key: str) -> str | None:
        return params.get(key, [None])[0]

    encryption = (p("encryption") or "none").lower()
    if encryption not in ("none", "zero"):
        raise ValueError(f"unsupported vless encryption {encryption!r} (xray: none)")
    security = (p("security") or "none").lower()
    if security not in ("none", "tls", "xtls", "reality"):
        raise ValueError(f"unsupported vless security {security!r}")
    if security == "reality" and not p("pbk"):
        raise ValueError("vless reality требует pbk (public key)")
    network = (p("type") or "tcp").lower()
    if network not in ("tcp", "grpc", "ws"):
        raise ValueError(f"unsupported vless transport {network!r} (supported: tcp, grpc, ws)")

    return {
        "kind": "vless",
        "name": name or f"{host}:{port}",
        "host": host,
        "port": port,
        "id": uuid,
        "flow": p("flow"),
        "security": security,
        "sni": p("sni") or p("peer"),
        "fp": p("fp"),
        "pbk": p("pbk"),
        "sid": p("sid"),
        "spx": p("spx"),
        "network": network,
        "serviceName": p("serviceName"),
        "mode": p("mode"),
        "authority": p("authority"),
        "path": p("path"),
        "ws_host": p("host"),
        "headerType": p("headerType"),
    }


def parse_key(url: str) -> dict:
    """Any supported key scheme -> server dict."""
    lowered = url.strip().lower()
    if lowered.startswith("ss://"):
        return parse_ss_key(url)
    if lowered.startswith("vless://"):
        return parse_vless_key(url)
    raise ValueError("unsupported key scheme (supported: ss://, vless://)")


# ── server store (keys carry passwords/UUIDs — keep it 0600) ──────────────────


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
    secret = server.get("password") or server.get("id") or ""
    raw = f"{server['kind']}:{server.get('method', '')}:{secret}@{server['host']}:{server['port']}"
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


def _ss_outbound(server: dict) -> dict:
    return {
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


def _vless_outbound(server: dict) -> dict:
    user = {"id": server["id"], "encryption": "none"}
    if server.get("flow"):
        user["flow"] = server["flow"]
    stream: dict = {"network": server.get("network") or "tcp", "security": server.get("security") or "none"}
    security = stream["security"]
    if security == "reality":
        reality = {
            "serverName": server.get("sni") or server["host"],
            "fingerprint": server.get("fp") or "chrome",
        }
        if server.get("pbk"):
            reality["publicKey"] = server["pbk"]
        if server.get("sid"):
            reality["shortId"] = server["sid"]
        if server.get("spx"):
            reality["spiderX"] = server["spx"]
        stream["realitySettings"] = reality
    elif security in ("tls", "xtls"):
        tls: dict = {"serverName": server.get("sni") or server["host"]}
        if server.get("fp"):
            tls["fingerprint"] = server["fp"]
        stream["tlsSettings"] = tls
    network = stream["network"]
    if network == "grpc":
        grpc: dict = {"serviceName": server.get("serviceName") or ""}
        if server.get("mode") == "multi":
            grpc["multiMode"] = True
        if server.get("authority"):
            grpc["authority"] = server["authority"]
        stream["grpcSettings"] = grpc
    elif network == "ws":
        ws: dict = {"path": server.get("path") or "/"}
        if server.get("ws_host"):
            ws["headers"] = {"Host": server["ws_host"]}
        stream["wsSettings"] = ws
    elif network == "tcp" and server.get("headerType"):
        stream["tcpSettings"] = {"header": {"type": server["headerType"]}}
    return {
        "protocol": "vless",
        "settings": {"vnext": [{"address": server["host"], "port": server["port"], "users": [user]}]},
        "streamSettings": stream,
        "tag": "proxy",
    }


def _build_xray_config(server: dict) -> dict:
    """Full TUN-mode xray config with the key's outbound, composed the same
    way Happ server configs are (shared inbounds/dns/routing)."""
    outbound = _ss_outbound(server) if server["kind"] == "ss" else _vless_outbound(server)
    cfg = happmeta.build_runtime_config({"remarks": server["name"], "outbounds": [outbound]})
    # distinct tun from Happ's "happ-xray" (172.19.0.1/30) so both can be
    # told apart and, where routing allows, coexist
    for inbound in cfg.get("inbounds", []):
        if inbound.get("protocol") == "tun":
            inbound["settings"]["name"] = IFACES[server["kind"]]
            inbound["settings"]["gateway"] = ["172.19.4.1/30"]
    return cfg


# ── Keeper: long-lived happd session owning the xray process ─────────────────


def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def _write_keeper_state(state_path: Path, state: dict, own: bool = False) -> None:
    if own:
        current = _read_keeper_state(state_path)
        if current is not None and current.get("pid", state["pid"]) != state["pid"]:
            return  # a newer keeper owns the file
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state))
        tmp.replace(state_path)
    except OSError:
        pass


def _read_keeper_state(state_path: Path) -> dict | None:
    try:
        data = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def run_keeper(kind: str, server_id: str) -> None:
    """Send the start frame for one key server and hold the session open
    (happd reaps managed processes when the starting client disconnects).
    Mirrors providers.happ.run_keeper."""
    process_id, iface, state_path = _kind_meta(kind)
    logutil.log(f"keys keeper: starting ({kind} {server_id})")
    state: dict = {"status": "connecting", "pid": os.getpid(), "server": server_id}
    _write_keeper_state(state_path, state)  # unconditional first claim
    attempts = 0
    exit_reason = "unknown"
    try:
        server = next((s for s in _load_servers() if _server_id(s) == server_id), None)
        if server is None:
            state.update(status="error", message="server not found in store")
            _write_keeper_state(state_path, state)
            return
        cfg = _build_xray_config(server)

        # happd occasionally kills the managed xray without telling us (observed
        # after ~1-9 min, no journal trace). Re-arm the start a few times on an
        # unexpected tunnel death — but never on "happd sent stopped": that is
        # the user's own disconnect and must not be fought.
        max_attempts = 3
        backoff = 3.0
        while True:
            attempts += 1
            sock = _open_session()
            try:
                request_id = f"wm-keys-{time.time_ns()}"
                params: dict = {
                    "action": "start",
                    "arguments": [],
                    "executable": str(XRAY_BIN),
                    "process-id": process_id,
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
                        _write_keeper_state(state_path, state, own=True)
                        return
                else:
                    state.update(status="error", message="no response from happd")
                    _write_keeper_state(state_path, state, own=True)
                    return

                state.update(status="connected", server=server["name"])
                _write_keeper_state(state_path, state, own=True)
                logutil.log(
                    f"keys keeper: connected ({server['name']})"
                    + (f", re-arm {attempts}/{max_attempts}" if attempts > 1 else "")
                )

                sock.settimeout(15)
                exit_reason = "unknown"
                while True:
                    try:
                        frame = _recv_frame(sock)
                    except TimeoutError:
                        if not _iface_exists(iface):
                            exit_reason = f"iface {iface} gone"
                            break
                        continue
                    if frame and frame.get("event") == "stopped":
                        exit_reason = "happd sent stopped"
                        break
            finally:
                sock.close()
            logutil.log(f"keys keeper: tunnel ended: {exit_reason}")
            if exit_reason != f"iface {iface} gone" or attempts >= max_attempts:
                break
            logutil.log(f"keys keeper: xray died unexpectedly, re-arming in {backoff:.0f}s")
            time.sleep(backoff)
            backoff = min(backoff * 3, 30)
            current = _read_keeper_state(state_path)
            if current is None or current.get("pid") != os.getpid():
                # a disconnect/new keeper removed or replaced the state file
                # while we slept — this keeper no longer owns the session
                logutil.log("keys keeper: ownership lost, aborting re-arm")
                break
    except (OSError, ConnectionError) as e:
        logutil.log(f"keys keeper: session error: {e}")
        if state.get("status") == "connecting":
            state.update(status="error", message=str(e))
            _write_keeper_state(state_path, state, own=True)
    except Exception as e:  # noqa: BLE001 - always record keeper failures
        logutil.log(f"keys keeper: unexpected error: {e}")
        state.update(status="error", message=str(e))
        _write_keeper_state(state_path, state, own=True)
    finally:
        state.update(status="exited")
        _write_keeper_state(state_path, state, own=True)
        logutil.log("keys keeper: exited")


# ── Provider ──────────────────────────────────────────────────────────────────


class KeysProvider(VPNProvider):
    """One protocol's view of the shared key store (kind: "ss" | "vless")."""

    def __init__(self, kind: str):
        self._kind = kind

    @property
    def name(self) -> str:
        return LABELS[self._kind]

    @property
    def tunnel_iface(self) -> str:
        return IFACES[self._kind]

    def connections(self) -> list[VPNConnection]:
        process_id, iface, state_path = _kind_meta(self._kind)
        servers = [s for s in _load_servers() if s.get("kind") == self._kind]
        if not servers:
            return []
        active_name = None
        if process_id in _daemon_running_processes() or Path(f"/sys/class/net/{iface}").exists():
            state = _read_keeper_state(state_path)
            if state and state.get("status") in ("connected", "connecting"):
                active_name = state.get("server")
        return [
            VPNConnection(
                name=s["name"],
                provider=self.name,
                active=s["name"] == active_name,
                interface=iface if s["name"] == active_name else None,
            )
            for s in servers
        ]

    def ping_targets(self) -> list[tuple[str, str, int]]:
        return [
            (s["name"], s["host"], s["port"])
            for s in _load_servers()
            if s.get("kind") == self._kind
        ]

    def connect(self, connection: VPNConnection) -> ActionResult:
        server = _find_server(connection.name)
        if server is None or server.get("kind") != self._kind:
            return ActionResult(False, f"Unknown {self.name} server: {connection.name}")
        self._stop_running()  # one server per protocol at a time
        return self._headless_connect(_server_id(server))

    def _headless_connect(self, server_id: str) -> ActionResult:
        _, _, state_path = _kind_meta(self._kind)
        state_path.unlink(missing_ok=True)
        manager = Path(__file__).resolve().parent.parent / "vpn_manager.py"
        subprocess.Popen(
            [sys.executable, str(manager), "--keys-keeper", self._kind, server_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + 25  # happd can be slow to ack
        while time.time() < deadline:
            state = _read_keeper_state(state_path)
            if state:
                if state.get("status") == "connected":
                    return ActionResult(True, f"Connected: {state.get('server', self.name)}")
                if state.get("status") == "error":
                    return ActionResult(False, state.get("message", "keeper error"))
                if state.get("status") == "exited":
                    return ActionResult(False, "keeper exited before connecting — see log")
            time.sleep(0.2)
        return ActionResult(False, "keeper timeout — see log")

    def _stop_running(self) -> None:
        process_id, iface, _ = _kind_meta(self._kind)
        if process_id not in _daemon_running_processes(fresh=True):
            return
        _daemon_request("stop", **{"process-id": process_id})
        deadline = time.time() + 5
        while time.time() < deadline:
            if not Path(f"/sys/class/net/{iface}").exists():
                return
            time.sleep(0.3)

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        # Unlinking the keeper state file (all branches) aborts a keeper
        # that is sleeping between re-arm attempts — do it FIRST so even a
        # failed stop cannot leave a sleeping keeper behind to resurrect.
        process_id, _, state_path = _kind_meta(self._kind)
        state_path.unlink(missing_ok=True)
        if process_id not in _daemon_running_processes(fresh=True):
            return ActionResult(success=False, message=f"{self.name} is not connected")
        resp = _daemon_request("stop", **{"process-id": process_id})
        if not resp or resp.get("status") not in ("stopping", "success"):
            error = resp.get("error", "no response") if resp else "happd unreachable"
            return ActionResult(success=False, message=f"Failed to stop: {error}")
        return ActionResult(success=True, message=f"Disconnected: {self.name}")

    def import_config(self, path: str) -> ActionResult:
        # the walker input may be a pasted key itself, not a file path
        text = path.strip()
        if text.lower().startswith(("ss://", "vless://")):
            try:
                return add_server(parse_key(text))
            except ValueError as e:
                return ActionResult(False, f"Bad key: {e}")
        try:
            text = Path(path).read_text(errors="replace")
        except OSError as e:
            return ActionResult(False, f"Cannot read {path}: {e}")
        match = _KEY_RE.search(text)
        if not match:
            return ActionResult(False, "No ss:// or vless:// key found in the file")
        try:
            parsed = parse_key(match.group(0))
        except ValueError as e:
            return ActionResult(False, f"Bad key: {e}")
        return add_server(parsed)
