import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider, read_config_text

WG_DIR = Path("/etc/wireguard")


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _active_interfaces() -> list[str]:
    code, out = _run(["ip", "-o", "link", "show", "type", "wireguard"])
    if code != 0 or not out:
        return []
    interfaces = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            interfaces.append(parts[1].strip())
    return interfaces


def _split_host_port(value: str, default_port: int) -> tuple[str, int] | None:
    """'host:port' / '[v6]:port' / bare v6 or hostname (default port).

    A port must be all-digits and <= 65535 — socket.create_connection
    raises OverflowError beyond that, which would abort a whole ping
    sweep. Tolerant of junk after ']' ('[v6]51820' -> host, default port)."""
    v = value.strip()
    if not v:
        return None
    if v.startswith("["):
        end = v.find("]")
        if end == -1:
            return None
        host = v[1:end]
        rest = v[end + 1 :]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
            return (host, port) if host and port <= 65535 else None
        return (host, default_port) if host else None
    if v.count(":") > 1:  # bare IPv6, no port
        return v, default_port
    if ":" in v:
        host, _, port = v.rpartition(":")
        if not host or not port.isdigit():
            return None
        port = int(port)
        return (host, port) if port <= 65535 else None
    return v, default_port


def wg_endpoint(conf_path) -> tuple[str, int] | None:
    """(host, port) of a config's [Peer] Endpoint, None when absent/garbled."""
    text = read_config_text(conf_path)
    if text is None:
        return None
    in_peer = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            in_peer = s[1:-1].strip().lower() == "peer"
            continue
        if not in_peer or "=" not in s:
            continue
        key, _, val = s.partition("=")
        if key.strip().lower() == "endpoint":
            return _split_host_port(val, 51820)
    return None


class WireGuardProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "WireGuard"

    def connections(self) -> list[VPNConnection]:
        active = _active_interfaces()
        result = []

        if not WG_DIR.exists():
            return result

        for conf in sorted(WG_DIR.glob("*.conf")):
            profile = conf.stem
            is_active = profile in active
            result.append(
                VPNConnection(
                    name=profile,
                    provider=self.name,
                    active=is_active,
                    interface=profile if is_active else None,
                    config_path=str(conf),
                )
            )

        # Include active interfaces that have no config file (edge case)
        known = {c.name for c in result}
        for iface in active:
            if iface not in known:
                result.append(
                    VPNConnection(
                        name=iface,
                        provider=self.name,
                        active=True,
                        interface=iface,
                    )
                )

        return result

    def ping_targets(self) -> list[tuple[str, str, int]]:
        targets = []
        for conn in self.connections():
            if not conn.config_path:
                continue
            ep = wg_endpoint(conn.config_path)
            if ep:
                targets.append((conn.name, ep[0], ep[1]))
        return targets

    def connect(self, connection: VPNConnection) -> ActionResult:
        code, out = _run(["sudo", "wg-quick", "up", connection.name])
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        iface = connection.interface or connection.name
        code, out = _run(["sudo", "wg-quick", "down", iface])
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Disconnected: {iface}")

    def autostart_enabled(self, profile: str) -> bool:
        code, _ = _run(["systemctl", "is-enabled", f"wg-quick@{profile}"])
        return code == 0

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        unit = f"wg-quick@{connection.name}"
        if self.autostart_enabled(connection.name):
            code, out = _run(["sudo", "systemctl", "disable", unit])
            if code != 0:
                return ActionResult(False, f"Failed to disable {unit}: {out}")
            return ActionResult(True, f"Autostart disabled: {connection.name}")
        code, out = _run(["sudo", "systemctl", "enable", unit])
        if code != 0:
            return ActionResult(False, f"Failed to enable {unit}: {out}")
        return ActionResult(True, f"Autostart enabled: {connection.name}")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        if connection.active:
            return ActionResult(False, f"Disconnect {connection.name} first")
        path = Path(connection.config_path or WG_DIR / f"{connection.name}.conf")
        if not path.exists():
            return ActionResult(False, f"Config not found: {path}")
        code, out = _run(["sudo", "rm", "-f", str(path)])
        if code != 0:
            return ActionResult(False, f"Failed to delete {path}: {out}")
        return ActionResult(True, f"Deleted: {path.name}")

    def import_config(self, path: str) -> ActionResult:
        src = Path(path)
        if not src.exists():
            return ActionResult(success=False, message=f"File not found: {path}")
        if src.suffix != ".conf":
            return ActionResult(success=False, message="File must have .conf extension")

        dest = WG_DIR / src.name
        if dest.exists():
            return ActionResult(success=False, message=f"Config already exists: {dest.name}")

        code, out = _run(["sudo", "cp", str(src), str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to copy: {out}")

        code, out = _run(["sudo", "chmod", "600", str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to set permissions: {out}")

        return ActionResult(success=True, message=f"Imported: {src.name}")
