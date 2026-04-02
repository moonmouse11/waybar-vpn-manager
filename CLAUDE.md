# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Install / Uninstall

```bash
make install    # runs install.sh — installs deps via pacman, sets up sudoers, copies files
make uninstall  # removes installed files and sudoers rule
```

Files are installed to `~/.config/waybar/vpn-manager/src/` and wrapper scripts to `~/.config/waybar/scripts/`.

## Running manually (without installing)

```bash
python3 src/vpn_manager.py --status   # outputs Waybar JSON
python3 src/vpn_manager.py --menu     # opens walker dmenu
```

## Architecture

The project is a Python backend (`src/`) invoked by two thin bash wrappers (`waybar/vpn-status.sh`, `waybar/vpn-menu.sh`) that Waybar calls on a 3-second interval and on click.

**Provider pattern** — all VPN backends implement `VPNProvider` (ABC in `src/providers/base.py`):
- `connections() -> list[VPNConnection]` — enumerate all known connections with their active state
- `connect / disconnect(connection)` — return `ActionResult(success, message)`
- `import_config(path)` — copy a config file into the system directory

**Provider registry** — `src/providers/__init__.py` defines `ALL_PROVIDERS`, the ordered list iterated at runtime. Add new providers here.

**Current providers:**
| Provider | Config dir | Active detection |
|---|---|---|
| `WireGuardProvider` | `/etc/wireguard/*.conf` | `ip link show type wireguard` |
| `OpenVPNProvider` | `/etc/openvpn/client/*.conf|.ovpn` | PID file in `/run/openvpn/` |
| `OutlineProvider` | n/a (AppImage at `/opt/outline-client/`) | `ip link show outline-tun0` |

**Menu flow** — `vpn_manager.py:run_menu()` builds `(label, callable)` pairs, pipes labels to `walker -d`, then calls the matched action and sends a `notify-send` notification. After any action, Waybar is refreshed via `pkill -RTMIN+11 waybar`.

## Adding a new provider

1. Create `src/providers/myprovider.py` implementing `VPNProvider`
2. Register it in `src/providers/__init__.py` by adding to `ALL_PROVIDERS`
3. If the provider supports config import, add a label entry in `vpn_manager.py:build_menu_items()` (see the WireGuard/OpenVPN pattern there)

## System dependencies

`sudo` access (passwordless via sudoers) is required for `wg-quick`, `openvpn`, `kill`, `mkdir`, `rm`, `cp`, `chmod`. The installer creates `/etc/sudoers.d/vpn-manager` for this.
