import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path


def read_config_text(path) -> str | None:
    """Text of a provider config: direct read first, else 'sudo -n cat'.

    Configs imported through the menu are copied root:0600, so the
    unprivileged background ping sweep cannot read them directly — the
    sudoers rule grants NOPASSWD cat for the config globs. None when both
    attempts fail (missing file, no cached sudo credentials)."""
    p = Path(path)
    try:
        return p.read_text(errors="replace")
    except OSError:
        pass
    try:
        result = subprocess.run(
            ["sudo", "-n", "cat", str(p)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout
    except (OSError, subprocess.SubprocessError):
        pass
    return None


@dataclass
class VPNConnection:
    name: str
    provider: str
    active: bool
    interface: str | None = None
    config_path: str | None = None
    uuid: str | None = None  # NetworkManager connection UUID


@dataclass
class ActionResult:
    success: bool
    message: str


def human_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


def iface_traffic(iface: str) -> str | None:
    """RX/TX totals for an interface via `ip -s link` (no root needed).

    Returns "↓ 1.2 MiB  ↑ 3.4 MiB" or None if stats are unavailable.
    """
    result = subprocess.run(
        ["ip", "-s", "link", "show", "dev", iface],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    lines = result.stdout.splitlines()
    rx = tx = None
    for i, line in enumerate(lines):
        if "RX:" in line and i + 1 < len(lines):
            rx = int(lines[i + 1].split()[0])
        if "TX:" in line and i + 1 < len(lines):
            tx = int(lines[i + 1].split()[0])
    if rx is None or tx is None:
        return None
    return f"↓ {human_bytes(rx)}  ↑ {human_bytes(tx)}"


class VPNProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Display name of the provider, e.g. 'WireGuard'"""
        ...

    @abstractmethod
    def connections(self) -> list[VPNConnection]:
        """Return all known connections (active and inactive)"""
        ...

    @abstractmethod
    def connect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def disconnect(self, connection: VPNConnection) -> ActionResult: ...

    @abstractmethod
    def import_config(self, path: str) -> ActionResult:
        """Import a config file and register it as a new connection"""
        ...

    def ping_targets(self) -> list[tuple[str, str, int]]:
        """(connection name, host, port) for availability/ping measurement.
        Providers with a measurable endpoint (WireGuard, OpenVPN) override
        this; the shared ping cache and ✓/✗ labels are name-keyed."""
        return []

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: autostart not supported")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        return ActionResult(False, f"{self.name}: config delete not supported")
