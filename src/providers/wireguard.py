import subprocess
import shutil
from pathlib import Path

from .base import VPNProvider, VPNConnection, ActionResult

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
            result.append(VPNConnection(
                name=profile,
                provider=self.name,
                active=is_active,
                interface=profile if is_active else None,
                config_path=str(conf),
            ))

        # Include active interfaces that have no config file (edge case)
        known = {c.name for c in result}
        for iface in active:
            if iface not in known:
                result.append(VPNConnection(
                    name=iface,
                    provider=self.name,
                    active=True,
                    interface=iface,
                ))

        return result

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
