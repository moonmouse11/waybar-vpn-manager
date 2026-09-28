# waybar-vpn-manager

A VPN manager plugin for [Waybar](https://github.com/Alexays/Waybar) with support for
**WireGuard, AmneziaWG, OpenVPN, Shadowsocks (ss://), VLESS (vless://), Happ** and any VPN managed by **NetworkManager**.
Built for Arch Linux with Hyprland / [Omarchy](https://omarchy.org/).

Two-level walker menu (omarchy-style): pick a provider → pick a connection.
Opens with a **SUPER+Shift+V** shortcut or a waybar click.

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
- **Killswitch** — nftables rules: no tunnel → no internet at all; three modes
  (off / auto-with-Happ-only / auto-with-every-provider), see [Killswitch](#killswitch)
- **IPv6 leak guard** — none of the providers tunnel IPv6, so a live IPv6 route
  (including IPv6 DNS) would otherwise bypass every tunnel entirely; disabled
  system-wide for as long as any connection is active, restored once idle
- **Config import** — WireGuard/OpenVPN (system dirs) and via `nmcli connection import`
- **Profile management** — autostart toggle (systemd `wg-quick@` / NM autoconnect),
  config delete, all from the menu
- **User config** — hide providers, auto-killswitch mode, exit-IP refresh interval
  (`~/.config/vpn-manager/config.json`)
- **NetworkManager provider** — shows/controls any VPN connection NM manages
  (openvpn, wireguard, vpnc, ikev2, openconnect, …)
- **🛠 Tools submenu** — DNS Leak Test, IP Info, Speed Test, Refresh All,
  Clear Caches, Settings and Killswitch, grouped off the main menu
- **Pluggable IP sources** — multi-source exit-IP/reputation lookups (free
  sources on by default; keyed sources like AbuseIPDB/IPQualityScore once an
  API key is configured), managed from the same `~/.config/vpn-manager/config.json`
- **Interactive setup wizard** — `--configure` (or the in-menu ⚙ Settings action)
  walks through providers, tools and IP sources; runs automatically as the last
  step of `make install`

## Requirements

**Core (menu, status, WireGuard/OpenVPN):**

- Arch Linux with Hyprland, [Omarchy](https://omarchy.org/) conventions
- `python` (stdlib only, no pip packages)
- `waybar` — status bar module (exec `vpn-status.sh` on a 3 s interval)
- `walker` — dmenu picker for the menus
- `wireguard-tools` (`wg-quick`), `openvpn`, `openresolv`
- `iproute2` (`ip`, `ss`), `nftables` (killswitch), `sudo` (NOPASSWD rules from `install.sh`)
- `libnotify` (`notify-send`), `curl`, `procps-ng` (`pgrep`/`pkill`)

**Optional providers, detected at runtime:**

- `Happ` (`/opt/happ`, `happd`) — Happ subscriptions **and** the shared xray-core
  (`/opt/happ/bin/core/xray`) that headless-runs imported `ss://`/`vless://` keys
- `networkmanager` (`nmcli`) — OpenConnect/IKEv2/L2TP/… via NM plugins
- Keys providers (`Shadowsocks`, `VLESS`) need the Happ installation for the xray binary
- `AmneziaWG` (`amneziawg-tools` + `amneziawg-dkms`, not installed by `make install` —
  dkms needs matching `linux-headers`) — obfuscated WireGuard via `awg-quick`,
  configs under `/etc/amnezia/amneziawg/`

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
6. Appends a `SUPER+Shift+V` binding to `~/.config/hypr/bindings.conf` (idempotent)
7. Runs the interactive configuration wizard (`--configure`) — pick which providers,
   tools and IP sources to show, and optionally set IP-source API keys; safe to
   Ctrl-C or skip (e.g. non-interactive installs), re-run any time with:
   `python3 ~/.config/waybar/vpn-manager/vpn_manager.py --configure`, or via the
   in-menu ⚙ Settings action

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

- **SUPER+Shift+V** or waybar click → menu
- Status tooltip: traffic, exit IP + country
- Logs: `~/.local/state/vpn-manager/vpn-manager.log`
- Caches: `~/.cache/vpn-manager/` (exit IP, pings, subscriptions)

### User config (`~/.config/vpn-manager/config.json`)

```jsonc
{
  "providers": {"outline": false},      // hide providers from menu/status
  "killswitch_mode": "happ",            // "off" | "happ" | "all" — auto-manage killswitch
  "exit_ip": {"enabled": true, "max_age_seconds": 600},
  "ip_sources": {                       // 🛠 Tools → IP Info source configuration
    "abuseipdb": {"api_key": "..."},    // keyed sources: enabled by setting api_key
    "ipwhois": {"enabled": true}        // free sources: enabled by default, opt-out here
  },
  "tools_visible": {"dns_leak_test": true, "killswitch": true}  // hide 🛠 Tools entries
}
```

Run the interactive wizard (`--configure`, or ⚙ Settings in the 🛠 Tools menu) instead of
hand-editing `ip_sources`/`tools_visible` if you'd rather be walked through it.

## Killswitch

`happ-killswitch on` blocks all outbound traffic except the tunnel interface(s),
DNS, local networks and the VPN server IPs (whitelist refreshed on connect via
`happ-killswitch detect` plus any resolved endpoint IPs). Three modes
(`killswitch_mode` in config, or the 🛠 Tools → Killswitch toggle):

- **off** — managed manually from the menu, no auto behaviour
- **happ** — auto-enabled alongside Happ only; suspended while any other
  provider is connected, re-arms on the next Happ connect
- **all** — auto-enabled for every connect; WireGuard/AmneziaWG/OpenVPN/
  VLESS/Shadowsocks endpoints are resolved from their configs and
  whitelisted too (NetworkManager isn't parsed yet — suspended for it)

Rollback: `happ-killswitch off` (rules don't survive reboot anyway).

## Architecture

```
waybar --(3 s)--> vpn_manager.py --status --> JSON (aggregated, cached exit IP)
waybar click --> vpn_manager.py --menu --> walker (2-level) --> provider actions
Happ connect --> --happ-keeper (long-lived happd session owning xray)
              --> happd (root daemon) --> xray (TUN)

src/
  vpn_manager.py      entry point: status, menu, Tools submenu, configure wizard
  config.py           user config load/save (providers, tools_visible, ip_sources, …)
  ipinfo.py           exit IP cache (+ --update-ip worker)
  happmeta.py         Happ subscriptions, config merge, ping cache
  killswitch.py       nft killswitch wrapper (mode-aware)
  ipv6guard.py        disables IPv6 system-wide while any tunnel is active (leak guard)
  reputation.py       exit-IP reputation orchestrator over ipsources/
  dnsleak.py          DNS leak test (dnsleaktest.com protocol, no external script)
  speedtest.py        single-measurement tunnel throughput (Cloudflare)
  logutil.py          file logging
  providers/          VPN backend registry + implementations (VPNProvider ABC)
  ipsources/          IP-intelligence source registry + implementations (IPInfoSource ABC)
docs/happd-protocol.md   Happ daemon protocol RE notes
scripts/              dev/research tools (subscription intercept, strace capture, …)
tests/                pytest suite
```

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest          # test suite
ruff check src tests      # lint
ruff format src tests     # format
```

The test suite mocks every `subprocess`/socket call it's aware of (`happd`,
`wg-quick`, `awg-quick`, `nmcli`, …), so it never needs real network or a real
VPN connection — it's testing the plugin's own logic, not real connectivity.
If you're running it on a machine with a live Happ/VPN connection you care
about and want a hard guarantee against a mocking gap reaching real system
state, run it containerized instead — no host `/tmp`/`/run`/`/etc/wireguard`
mounts, no network:

```bash
make test-docker-build   # once, or after pyproject.toml's dev deps change
make test-docker         # every run after that
```

CI (`.github/workflows/`) runs on GitHub-hosted runners, which have none of
your local VPN/happd state to begin with — it uses the plain venv path, not
Docker. `Dockerfile.test` / `make test-docker*` are dev-only; installing the
plugin (`make install`) never touches Docker.

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

## Adding a new IP-intelligence source

Same shape, for `🛠 Tools → ℹ️ IP Info` and the background reputation sweep.
Create `src/ipsources/mysource.py` implementing `IPInfoSource`:

```python
from ipsources import base

class MySource(base.IPInfoSource):
    key = "mysource"
    name = "My Source"
    needs_api_key = False  # True reads config.json's ip_sources[key]["api_key"]

    def lookup(self, ip: str) -> base.IPFinding | None: ...
```

Register it in `src/ipsources/__init__.py`'s `ALL_SOURCES`. Keyed sources are
used only by the on-demand IP Info action, never by the daily background
sweep — a present `api_key` in config *is* "enabled", no separate flag needed.

## Uninstall

```bash
make uninstall
```

Removes installed files and the sudoers rule. The waybar module block and the
SUPER+Shift+V bindings are left in place (remove manually if wanted).
