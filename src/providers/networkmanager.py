"""NetworkManager VPN connections (nmcli).

Covers VPN types managed by NetworkManager: openvpn, wireguard, vpnc, ikev2,
l2tp, pptp, openconnect, fortisslvpn and friends. Connect/disconnect go through
`nmcli connection up/down` — no sudo needed (polkit grants active sessions
control over their own connections).
"""

import shutil
import subprocess
from pathlib import Path

from .base import ActionResult, VPNConnection, VPNProvider

# nmcli connection types that are VPNs (anything else — ethernet, wifi,
# bridge, loopback... — is ignored)
VPN_TYPES = {
    "vpn",  # generic NM VPN plugin (openvpn/vpnc/... via D-Bus service)
    "wireguard",
    "openvpn",
    "openvpn3",
    "vpnc",
    "ikev2",
    "pptp",
    "l2tp",
    "openconnect",
    "fortisslvpn",
    "libreswan",
    "sstp",
    "iodine",
}

TIMEOUT = 6


def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        return 1, f"timeout after {TIMEOUT}s: {' '.join(cmd)}"
    return result.returncode, (result.stdout + result.stderr).strip()


def _terse_lines(output: str) -> list[list[str]]:
    """Parse `nmcli -t` output, honouring the '\\:' escape for ':'."""
    lines = []
    for line in output.splitlines():
        fields: list[str] = []
        current = ""
        i = 0
        while i < len(line):
            char = line[i]
            if char == "\\" and i + 1 < len(line) and line[i + 1] == ":":
                current += ":"
                i += 2
                continue
            if char == ":":
                fields.append(current)
                current = ""
            else:
                current += char
            i += 1
        fields.append(current)
        lines.append(fields)
    return lines


class NetworkManagerProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "NetworkManager"

    def _available(self) -> bool:
        return shutil.which("nmcli") is not None

    def connections(self) -> list[VPNConnection]:
        if not self._available():
            return []

        code, out = _run(["nmcli", "-t", "-f", "NAME,UUID,TYPE", "connection", "show"])
        if code != 0:
            return []

        active: dict[str, str] = {}
        code, out_a = _run(["nmcli", "-t", "-f", "UUID,DEVICE", "connection", "show", "--active"])
        if code == 0:
            for fields in _terse_lines(out_a):
                if len(fields) >= 2 and fields[0]:
                    active[fields[0]] = fields[1]

        result = []
        for fields in _terse_lines(out):
            if len(fields) < 3:
                continue
            conn_name, uuid, conn_type = fields[0], fields[1], fields[2]
            if conn_type.lower() not in VPN_TYPES:
                continue
            device = active.get(uuid)
            result.append(
                VPNConnection(
                    name=conn_name,
                    provider=self.name,
                    active=uuid in active,
                    interface=device or None,
                    uuid=uuid,
                )
            )
        return result

    def connect(self, connection: VPNConnection) -> ActionResult:
        if not connection.uuid:
            return ActionResult(False, "Missing connection UUID")
        code, out = _run(["nmcli", "connection", "up", "uuid", connection.uuid])
        if code != 0:
            return ActionResult(False, out.splitlines()[-1] if out else "nmcli failed")
        return ActionResult(True, f"Connected: {connection.name}")

    def disconnect(self, connection: VPNConnection) -> ActionResult:
        if not connection.uuid:
            return ActionResult(False, "Missing connection UUID")
        code, out = _run(["nmcli", "connection", "down", "uuid", connection.uuid])
        if code != 0:
            return ActionResult(False, out.splitlines()[-1] if out else "nmcli failed")
        return ActionResult(True, f"Disconnected: {connection.name}")

    def toggle_autostart(self, connection: VPNConnection) -> ActionResult:
        """Toggle NM 'autoconnect' flag."""
        if not connection.uuid:
            return ActionResult(False, "Missing connection UUID")
        code, out = _run(
            [
                "nmcli",
                "-g",
                "connection.autoconnect",
                "connection",
                "show",
                "uuid",
                connection.uuid,
            ]
        )
        if code != 0:
            return ActionResult(False, f"Cannot read autoconnect flag: {out}")
        enabled = out.strip() == "yes"
        new_value = "no" if enabled else "yes"
        code, out = _run(
            [
                "nmcli",
                "connection",
                "modify",
                "uuid",
                connection.uuid,
                "connection.autoconnect",
                new_value,
            ]
        )
        if code != 0:
            return ActionResult(False, f"Cannot set autoconnect: {out}")
        state = "disabled" if enabled else "enabled"
        return ActionResult(True, f"Autoconnect {state}: {connection.name}")

    def delete_config(self, connection: VPNConnection) -> ActionResult:
        if connection.active:
            return ActionResult(False, f"Disconnect {connection.name} first")
        if not connection.uuid:
            return ActionResult(False, "Missing connection UUID")
        code, out = _run(["nmcli", "connection", "delete", "uuid", connection.uuid])
        if code != 0:
            return ActionResult(False, out.splitlines()[-1] if out else "nmcli failed")
        return ActionResult(True, f"Deleted: {connection.name}")

    def import_config(self, path: str) -> ActionResult:
        src = Path(path)
        if not src.exists():
            return ActionResult(False, f"File not found: {path}")
        try:
            content = src.read_text(errors="replace")
        except OSError as e:
            return ActionResult(False, f"Cannot read {path}: {e}")

        # Sniff the config type: [Interface] is WireGuard, 'remote' is OpenVPN
        if "[Interface]" in content:
            import_type = "wireguard"
        elif "remote " in content:
            import_type = "openvpn"
        else:
            return ActionResult(False, "Unknown config format (need [Interface] or remote)")

        code, out = _run(["nmcli", "connection", "import", "type", import_type, "file", str(src)])
        if code != 0:
            return ActionResult(False, out.splitlines()[-1] if out else "nmcli import failed")
        return ActionResult(True, f"Imported ({import_type}): {src.name}")
