import subprocess
from pathlib import Path

from .base import VPNProvider, VPNConnection, ActionResult

OVPN_DIR = Path("/etc/openvpn/client")


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _active_profiles() -> set[str]:
    code, out = _run(["systemctl", "list-units", "--state=active", "--no-legend", "openvpn-client@*.service"])
    if code != 0 or not out:
        return set()
    profiles = set()
    for line in out.splitlines():
        # e.g. "openvpn-client@myvpn.service"
        unit = line.split()[0]
        profile = unit.removeprefix("openvpn-client@").removesuffix(".service")
        profiles.add(profile)
    return profiles


class OpenVPNProvider(VPNProvider):

    @property
    def name(self) -> str:
        return "OpenVPN"

    def connections(self) -> list[VPNConnection]:
        active = _active_profiles()
        result = []

        if not OVPN_DIR.exists():
            return result

        for conf in sorted(OVPN_DIR.glob("*.conf")) + sorted(OVPN_DIR.glob("*.ovpn")):
            profile = conf.stem
            is_active = profile in active
            result.append(VPNConnection(
                name=profile,
                provider=self.name,
                active=is_active,
                interface="tun0" if is_active else None,
                config_path=str(conf),
            ))

        # Include active services with no config file (edge case)
        known = {c.name for c in result}
        for profile in active:
            if profile not in known:
                result.append(VPNConnection(
                    name=profile,
                    provider=self.name,
                    active=True,
                    interface="tun0",
                ))

        return result

    def connect(self, connection: VPNConnection) -> ActionResult:
        code, out = _run(["sudo", "systemctl", "start", f"openvpn-client@{connection.name}.service"])
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        code, out = _run(["sudo", "systemctl", "stop", f"openvpn-client@{connection.name}.service"])
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
