# waybar-vpn-manager

A VPN manager plugin for [Waybar](https://github.com/Alexays/Waybar) with support for WireGuard, OpenVPN, and Outline.
Built for Arch Linux with Hyprland / [Omarchy](https://omarchy.org/).

## Features

- Status icon with active provider name
- Connect / disconnect from walker dmenu
- Import WireGuard (`.conf`) and OpenVPN (`.conf` / `.ovpn`) config files
- Easy to extend with new VPN providers

## Requirements

- Arch Linux
- Waybar
- Walker
- `python` `wireguard-tools` `openvpn` `openresolv` `socat`

## Install

```bash
git clone https://github.com/your-username/waybar-vpn-manager
cd waybar-vpn-manager
make install
```

The installer will:
1. Install dependencies via `pacman`
2. Create a `sudoers` rule for `wg-quick` (no password prompt when connecting)
3. Fix `/etc/wireguard` permissions
4. Copy files to `~/.config/waybar/vpn-manager/`
5. Install wrapper scripts to `~/.config/waybar/scripts/`

Then add to `~/.config/waybar/config.jsonc`:

```jsonc
"custom/vpn": {
  "exec": "~/.config/waybar/scripts/vpn-status.sh",
  "return-type": "json",
  "interval": 3,
  "signal": 11,
  "on-click": "~/.config/waybar/scripts/vpn-menu.sh",
},
```

And restart Waybar:
```bash
omarchy-restart-waybar
# or: pkill waybar && waybar &
```

## Uninstall

```bash
make uninstall
```

## Adding a new VPN provider

Create `src/providers/myprovider.py` implementing the `VPNProvider` base class:

```python
from .base import VPNProvider, VPNConnection, ActionResult

class MyProvider(VPNProvider):
    @property
    def name(self) -> str:
        return "MyVPN"

    def connections(self) -> list[VPNConnection]: ...
    def connect(self, connection) -> ActionResult: ...
    def disconnect(self, connection) -> ActionResult: ...
    def import_config(self, path) -> ActionResult: ...
```

Then register it in `src/providers/__init__.py`:

```python
from .myprovider import MyProvider

ALL_PROVIDERS = [
    WireGuardProvider(),
    OutlineProvider(),
    OpenVPNProvider(),
    MyProvider(),
]
```
