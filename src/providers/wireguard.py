import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider, read_config_text

WG_DIR = Path("/etc/wireguard")
AMNEZIA_DIR = Path("/etc/amnezia/amneziawg")


def _run(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True)
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def _active_interfaces(link_type: str = "wireguard") -> list[str]:
    code, out = _run(["ip", "-o", "link", "show", "type", link_type])
    if code != 0 or not out:
        return []
    interfaces = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 2:
            interfaces.append(parts[1].strip())
    return interfaces


def _net_iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


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
    """Base for wg-quick-style providers; AmneziaWG subclasses with the
    awg tools and its own config dir."""

    provider_name = "WireGuard"
    config_dir = WG_DIR
    quick_bin = "wg-quick"  # sudoers grants this; AmneziaWG uses awg-quick
    systemd_prefix = "wg-quick"
    link_type = "wireguard"
    #: profiles living in another provider's config dir are not ours even
    #: if the kernel reports them under our link type (amneziawg vs
    #: wireguard module overlap) — e.g. a leftover *.conf under /etc/wireguard
    #: meant for awg-quick must not also show up as a plain WireGuard profile
    other_config_dirs: tuple[Path, ...] = (AMNEZIA_DIR,)

    @property
    def name(self) -> str:
        return self.provider_name

    def _extra_active(self) -> set[str]:
        """Profiles that are up but `ip link show type` does not report —
        AmneziaWG overrides (its link type may be unknown to ip(8))."""
        return set()

    def connections(self) -> list[VPNConnection]:
        active = set(_active_interfaces(self.link_type)) | self._extra_active()
        result = []

        if not self.config_dir.exists():
            return result

        for conf in sorted(self.config_dir.glob("*.conf")):
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

        # Include active interfaces that have no config file of ours (edge
        # case) — except ones claimed by another provider's config dir:
        # kernel link-type overlap (amneziawg vs wireguard module builds
        # that share a kind) can misattribute an active interface to us
        # even though its profile actually lives under the other provider.
        known = {c.name for c in result}
        excluded = {p.stem for d in self.other_config_dirs for p in d.glob("*.conf")}
        for iface in active:
            if iface not in known and iface not in excluded:
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
        code, out = _run(["sudo", self.quick_bin, "up", connection.name])
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        iface = connection.interface or connection.name
        code, out = _run(["sudo", self.quick_bin, "down", iface])
        if code != 0:
            return ActionResult(success=False, message=out)
        return ActionResult(success=True, message=f"Disconnected: {iface}")

    def autostart_enabled(self, profile: str) -> bool:
        code, _ = _run(["systemctl", "is-enabled", f"{self.systemd_prefix}@{profile}"])
        return code == 0

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        unit = f"{self.systemd_prefix}@{connection.name}"
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
        path = Path(connection.config_path or self.config_dir / f"{connection.name}.conf")
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

        dest = self.config_dir / src.name
        if dest.exists():
            return ActionResult(success=False, message=f"Config already exists: {dest.name}")

        code, out = _run(["sudo", "cp", str(src), str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to copy: {out}")

        code, out = _run(["sudo", "chmod", "600", str(dest)])
        if code != 0:
            return ActionResult(success=False, message=f"Failed to set permissions: {out}")

        return ActionResult(success=True, message=f"Imported: {src.name}")


class AmneziaWGProvider(WireGuardProvider):
    """AmneziaWG (obfuscated WireGuard fork) via awg-quick.

    Configs use the same [Interface]/[Peer] syntax plus obfuscation keys
    (Jc/Jmin/Jmax/S1/S2/H1-4) that plain wg-quick rejects, so they live in
    their own directory rather than /etc/wireguard.
    """

    provider_name = "AmneziaWG"
    config_dir = AMNEZIA_DIR
    quick_bin = "awg-quick"
    systemd_prefix = "awg-quick"
    link_type = "amneziawg"  # kernel module's rtnl_link_ops.kind (DKMS build name)
    other_config_dirs = (WG_DIR,)

    def _extra_active(self) -> set[str]:
        """Userspace awg-go builds don't register under the kernel link
        type (no amneziawg netlink family) — fall back to checking whether
        each configured profile's interface node exists at all."""
        if not self.config_dir.exists():
            return set()
        return {p.stem for p in self.config_dir.glob("*.conf") if _net_iface_exists(p.stem)}
