import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider, read_config_text

OVPN_DIR = Path("/etc/openvpn/client")
PID_DIR = Path("/run/openvpn")


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _pid_file(profile: str) -> Path:
    return PID_DIR / f"client-{profile}.pid"


def _is_running(profile: str) -> bool:
    pid_file = _pid_file(profile)
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        return Path(f"/proc/{pid}").exists()
    except (ValueError, OSError):
        return False


def ovpn_endpoint(conf_path) -> tuple[str, int] | None:
    """(host, port) of the first valid 'remote host port' directive.

    A remote without a numeric port, or commented out (; or #), yields None.
    The port must be <= 65535 — socket.create_connection raises
    OverflowError beyond that, which would abort a whole ping sweep."""
    text = read_config_text(conf_path)
    if text is None:
        return None
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith((";", "#")):
            continue
        parts = s.split()
        if parts[0].lower() != "remote":
            continue
        if len(parts) < 3 or not parts[2].isdigit():
            return None  # first remote unusable -> no endpoint for this config
        port = int(parts[2])
        return (parts[1], port) if port <= 65535 else None
    return None


class OpenVPNProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "OpenVPN"

    def connections(self) -> list[VPNConnection]:
        result = []

        if not OVPN_DIR.exists():
            return result

        for conf in sorted(OVPN_DIR.glob("*.conf")) + sorted(OVPN_DIR.glob("*.ovpn")):
            profile = conf.stem
            is_active = _is_running(profile)
            result.append(
                VPNConnection(
                    name=profile,
                    provider=self.name,
                    active=is_active,
                    interface="tun0" if is_active else None,
                    config_path=str(conf),
                )
            )

        return result

    def ping_targets(self) -> list[tuple[str, str, int]]:
        targets = []
        for conn in self.connections():
            if not conn.config_path:
                continue
            ep = ovpn_endpoint(conn.config_path)
            if ep:
                targets.append((conn.name, ep[0], ep[1]))
        return targets

    def connect(self, connection: VPNConnection) -> ActionResult:
        _run(["sudo", "mkdir", "-p", str(PID_DIR)])
        pid_file = _pid_file(connection.name)
        config = connection.config_path or str(OVPN_DIR / f"{connection.name}.conf")
        code, out = _run(
            [
                "sudo",
                "openvpn",
                "--config",
                config,
                "--daemon",
                "--writepid",
                str(pid_file),
            ]
        )
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        pid_file = _pid_file(connection.name)
        if not pid_file.exists():
            return ActionResult(success=False, message=f"Not running: {connection.name}")

        try:
            pid = int(pid_file.read_text().strip())
        except (ValueError, OSError) as e:
            return ActionResult(success=False, message=f"Cannot read PID: {e}")

        code, out = _run(["sudo", "kill", str(pid)])
        _run(["sudo", "rm", "-f", str(pid_file)])

        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Disconnected: {connection.name}")

    def import_config(self, path: str) -> ActionResult:
        src = Path(path)
        if not src.exists():
            return ActionResult(success=False, message=f"File not found: {path}")
        if src.suffix not in (".conf", ".ovpn"):
            return ActionResult(success=False, message="File must have .conf or .ovpn extension")

        dest = OVPN_DIR / src.name
        if dest.exists():
            return ActionResult(success=False, message=f"Config already exists: {dest.name}")

        code, out = _run(["sudo", "cp", str(src), str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to copy: {out}")

        code, out = _run(["sudo", "chmod", "600", str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to set permissions: {out}")

        return ActionResult(success=True, message=f"Imported: {src.name}")
