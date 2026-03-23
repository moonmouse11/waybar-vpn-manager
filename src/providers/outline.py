import subprocess
from pathlib import Path

from .base import VPNProvider, VPNConnection, ActionResult

OUTLINE_IFACE = "outline-tun0"
OUTLINE_BIN = Path("/opt/outline-client/Outline-Client.AppImage")


def _interface_up(name: str) -> bool:
    result = subprocess.run(
        ["ip", "link", "show", name],
        capture_output=True, text=True
    )
    return result.returncode == 0


class OutlineProvider(VPNProvider):

    @property
    def name(self) -> str:
        return "Outline"

    def connections(self) -> list[VPNConnection]:
        active = _interface_up(OUTLINE_IFACE)
        return [VPNConnection(
            name="Outline",
            provider=self.name,
            active=active,
            interface=OUTLINE_IFACE if active else None,
        )]

    def connect(self, connection: VPNConnection) -> ActionResult:
        if not OUTLINE_BIN.exists():
            return ActionResult(success=False, message=f"Outline not found at {OUTLINE_BIN}")
        subprocess.Popen(
            [str(OUTLINE_BIN)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ActionResult(success=True, message="Outline starting...")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        result = subprocess.run(
            ["pkill", "-f", "Outline-Client.AppImage"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return ActionResult(success=False, message="Outline is not running")
        return ActionResult(success=True, message="Outline stopped")

    def import_config(self, path: str) -> ActionResult:
        return ActionResult(success=False, message="Outline does not support config import")
