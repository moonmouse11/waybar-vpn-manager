# waybar-vpn-manager

A VPN manager plugin for [Waybar](https://github.com/Alexays/Waybar) with support for
**WireGuard, OpenVPN, Outline, Happ** and any VPN managed by **NetworkManager**.
Built for Arch Linux with Hyprland / [Omarchy](https://omarchy.org/).

Two-level walker menu (omarchy-style): pick a provider → pick a connection.
Opens with a **SUPER+V** shortcut or a waybar click.

## Features

- **Status module** — active provider/connection in the bar, per-provider CSS classes
  (`vpn-wireguard`, `vpn-happ`, …), tooltip with per-interface traffic stats and
  exit IP + country flag
- **Two-level menu** — providers with `(active/total)` counters → connections;
  `Disconnect ALL`, killswitch toggle and import/manage actions where supported
- **Happ headless** — full server list straight from the provider subscriptions,
  configs generated like the GUI does; connect/switch any server **without opening
  the Happ GUI** (it keeps working in parallel, state is shared via happd)
- **Ping + info in labels** — background-measured TCP ping, non-standard protocols
  shown next to server names
- **Killswitch (Happ TUN)** — nftables rules: no tunnel → no internet at all;
  auto-suspends for other providers, auto-resumes on the next Happ connect
- **Config import** — WireGuard/OpenVPN (system dirs) and via `nmcli connection import`
- **Profile management** — autostart toggle (systemd `wg-quick@` / NM autoconnect),
  config delete, all from the menu
- **User config** — hide providers, auto-killswitch mode, exit-IP refresh interval
  (`~/.config/vpn-manager/config.json`)
- **NetworkManager provider** — shows/controls any VPN connection NM manages
  (openvpn, wireguard, vpnc, ikev2, openconnect, …)

## Requirements

- Arch Linux, Waybar, Walker, Hyprland
- `python` `wireguard-tools` `openvpn` `openresolv` (`nftables` for the killswitch)
- Happ, Outline — optional, detected at runtime

## Install

```bash
git clone https://github.com/your-username/waybar-vpn-manager
cd waybar-vpn-manager
make install
```

The installer:
1. Installs dependencies via `pacman`
2. Writes a narrowed `sudoers` rule (commands used by the providers only, validated
   with `visudo -cf`)
3. Installs the `happ-killswitch` script root-owned to `/usr/local/bin`
4. Copies sources to `~/.config/waybar/vpn-manager/`, wrappers to `~/.config/waybar/scripts/`
5. Inserts the `custom/vpn` module into `~/.config/waybar/config.jsonc` (skipped if present)
6. Appends a `SUPER+V` binding to `~/.config/hypr/bindings.conf` (idempotent)

Then restart:

```bash
omarchy restart waybar
hyprctl reload
```

### Happ setup (one-time, for headless)

Happ subscriptions are fetched directly with the app's own request headers
(remote answers plain curl with a stub). Capture them once — see
[`docs/happd-protocol.md`](docs/happd-protocol.md) — and save to
`~/.config/happ-capture/headers.json`. After that the full server list, generated
configs, ping and headless connect work out of the box; new servers from the
provider appear automatically.

## Usage

- **SUPER+V** or waybar click → menu
- Status tooltip: traffic, exit IP + country
- Logs: `~/.local/state/vpn-manager/vpn-manager.log`
- Caches: `~/.cache/vpn-manager/` (exit IP, pings, subscriptions)

### User config (`~/.config/vpn-manager/config.json`)

```jsonc
{
  "providers": {"outline": false},      // hide providers from menu/status
  "killswitch_mode": "happ",            // "off" | "happ" — auto-manage killswitch
  "exit_ip": {"enabled": true, "max_age_seconds": 600}
}
```

## Killswitch

`happ-killswitch on` blocks all outbound traffic except the `happ-*` tunnel,
local networks and the Happ server IPs (whitelist refreshed on connect via
`happ-killswitch detect`). Menu toggle persists the preference; connecting a
non-Happ provider suspends it for the duration. Rollback: `happ-killswitch off`
(rules don't survive reboot anyway).

## Architecture

```
waybar --(3 s)--> vpn_manager.py --status --> JSON (aggregated, cached exit IP)
waybar click --> vpn_manager.py --menu --> walker (2-level) --> provider actions
Happ connect --> --happ-keeper (long-lived happd session owning xray)
              --> happd (root daemon) --> xray (TUN)

src/
  vpn_manager.py      entry point: status, menu, background workers
  config.py           user config load/save
  ipinfo.py           exit IP cache (+ --update-ip worker)
  happmeta.py         Happ subscriptions, config merge, ping cache
  killswitch.py       nft killswitch wrapper (mode-aware)
  logutil.py          file logging
  providers/          provider registry + implementations
docs/happd-protocol.md   Happ daemon protocol RE notes
scripts/              dev/research tools (subscription intercept, strace capture, …)
tests/                pytest suite
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install pytest ruff
.venv/bin/pytest          # 43 tests
ruff check src/ tests/    # lint
ruff format src/ tests/   # format
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
    # optional: toggle_autostart(), delete_config()
```

Register it in `src/providers/__init__.py`. Optional niceties: per-provider CSS
class appears automatically (`vpn-<provider-lowercase>`).

## Uninstall

```bash
make uninstall
```

Removes installed files and the sudoers rule. The waybar module block and the
SUPER+V binding are left in place (remove manually if wanted).
