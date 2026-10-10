# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versions 0.1.0 and 0.2.0 predate release tags; their entries are reconstructed
from the git history.

## [Unreleased]

### Added

- **Progress for DNS Leak Test, Speed Test and IP Info:** one notification,
  updated in place step by step, since the menu window can't change while a
  tool runs. A `notify-send` without `-p` / `-r` shows the steps as separate
  notifications instead.
- **Happ: headless operation.** Subscriptions are fetched directly and turned
  into runnable xray configs, so every server can be listed and connected
  without the Happ GUI — through the `happd` daemon, with server switching,
  per-server ping and info, and a submenu per subscription. Servers are
  identified by subscription + name, so two subscriptions' "🇩🇪 Germany"
  no longer collide ([#6]).
- **Providers:** AmneziaWG, NetworkManager, and imported VLESS / Shadowsocks
  keys (`vless://`, `ss://`).
- **Killswitch** (nftables) with `off` / `happ` / `all` modes. xray's own
  traffic is allowed by socket mark rather than by guessing server IPs.
- **IPv6 leak guard:** none of the tunnels carry IPv6, so it is disabled
  system-wide while any connection is up and restored afterwards.
- **🛠 Tools submenu:** DNS Leak Test, IP Info, Speed Test, Refresh All,
  Clear Caches and Settings, each individually hideable ([#3]).
- **Pluggable IP-intelligence sources** for exit-IP and server reputation:
  ipwho.is and ip-api.com (keyless), AbuseIPDB and IPQualityScore (API key)
  ([#3]).
- **Configuration wizard** (`vpn_manager.py --configure`), run as the last
  step of `make install` and available in-menu as ⚙ Settings ([#3]).
- **DNS Leak Test checks of its own** on top of bash.ws: resolvers tagged by
  ASN / country, the exit country compared with the connected server, and the
  IPv6 state ([#5]).
- **Speed Test:** preset services (Cloudflare, OVH, Hetzner) plus remembered
  custom URLs, an "all services" comparison, results in Mbit/s in a walker
  window; works with no VPN connected ([#9], [#12]).
- **xray config preflight:** before starting a tunnel the config is checked
  with `xray run -test`; a rejected config fails the connect with xray's own
  error in a critical notification instead of a silent "connected" with no
  tunnel ([#10]).
- **Critical notification when a tunnel dies** and automatic re-arming gives
  up ([#10]).
- **xray compatibility tests** against pinned upstream xray releases (latest
  stable, the one Happ ships, newest pre-release), including a run of the real
  generated config that checks where DNS is routed; CI runs them on every pull
  request and weekly against the newest upstream release ([#10], [#13]).
- **Offline test container** (`make test-docker`): no network and no host
  state, so a gap in the test suite's mocking cannot touch a live VPN
  connection.
- **`dns_mode` option** in `config.json` and the wizard: `"tunnel"` (default)
  always sends xray's DNS through the tunnel; `"subscription"` keeps the
  subscription's own DNS routing ([#14]).

### Changed

- **⚙ Settings is one list** in a small floating terminal instead of a chain
  of Yes / No windows, keyboard-driven like omarchy's own TUIs: every setting
  is a row showing its value (✅ / ⬜), Space / Enter changes it in place, `s`
  saves, `q` / Esc quits (asking first about unsaved changes). A second click
  focuses the open window. The terminal `--configure` wizard is unchanged.
- Menus open in one fixed-size window instead of growing and shrinking with
  the rows on screen.
- The DNS Leak Test expects the exit country from the flag in the server name
  instead of the server's entry IP: most subscription servers enter through a
  Russian relay and exit abroad, which used to flag about half of them as
  leaks. 🇪🇺 accepts any EU member state, and a mismatch is cross-checked with a
  second geo database before it is reported ([#14]).
- Menu and status markers are plain text. Reputation tags (RU / DC / PROXY) are
  no longer shown on server rows: nearly every VPN server is in a data centre.
- The interface and documentation are English only ([#7]).
- CI: `actions/checkout` 7.0.1 ([#2]), `sonarqube-scan-action` 8.2.2 ([#1]).

### Removed

- The Outline provider, superseded by imported Shadowsocks keys.
- The Subdomain Search tool: a passive certificate-log lookup with no bearing
  on the tunnel's state.

### Fixed

- **Old Happ / Keys keepers never exited after a server switch** with Happ
  4.5.2: its daemon no longer sends a "stopped" event, and the new tunnel
  reuses the interface name, so every previous connection's keeper lingered
  ("two connections at once"). Keepers now also exit as soon as a newer one
  owns the connection.
- **A disconnected tunnel kept showing as connected — under another server's
  name.** For up to 3 s after a disconnect, a stale process list made the
  plugin name the tunnel after the Happ GUI's last-used server, so Waybar
  showed it and the menu's "↻" row reconnected *that* server. The cache is
  now dropped on every connect / disconnect / switch, and the GUI's last
  server only names a tunnel while the GUI itself is running.
- **Failed tools now say why.** DNS Leak Test, Speed Test and IP Info used to
  end with a generic "no network?"; the critical notification now names the
  step and the cause (e.g. a TLS handshake timeout through a slow VPN exit).
- **Headless Happ connect broke after updating to Happ 4.5.2:** its xray
  26.9.x rejects the outbound `proxySettings` field the generated config used,
  so xray never started ([#10]).
- **DNS leak:** xray's resolver sent every lookup straight out of the real
  network interface from the real IP, whatever the tunnel ([#13]). Some
  subscriptions also route their own resolvers `direct`; in `"tunnel"` mode
  that is now overridden ([#14]).
- The IPv6 leak guard switched IPv6 **on** right after connecting, because it
  re-checked the tunnel before xray had created its interface ([#14]).
- OpenVPN ignored DNS servers pushed by the server.
- The Happ menu no longer blocks for up to 15 s on the network when a
  subscription cache is stale.
- Speed Test failed on HTTPS services and measured connection setup instead
  of throughput ([#9], [#12]).

### Security

- Files holding keys, passwords and API keys are written atomically and
  created with `0600` permissions, never briefly world-readable ([#8]).
- `/tmp/happd.sock` is used only if it is a socket owned by root or the user,
  not a file planted by another local user.
- Subscription identifiers are sanitised before being used in cache paths.
- Notification text is cleaned before reaching `notify-send`: leading dashes,
  control characters and markup from server names or daemon errors are
  stripped or escaped.

## [0.2.0] - 2026-09-17

### Added

- Happ provider, driving the Happ GUI.
- Killswitch groundwork.
- `pyproject.toml` with the package metadata and development dependencies.

### Fixed

- OpenVPN connection handling and installer issues.

## [0.1.0] - 2026-03-24

### Added

- Waybar status module and walker menu for VPN connections.
- WireGuard, OpenVPN and Outline providers.
- `make install` / `make uninstall`, with a passwordless sudoers rule for the
  VPN commands.

[Unreleased]: https://github.com/moonmouse11/waybar-vpn-manager/compare/2d19494...HEAD
[0.2.0]: https://github.com/moonmouse11/waybar-vpn-manager/compare/e73f3fa...2d19494
[0.1.0]: https://github.com/moonmouse11/waybar-vpn-manager/commit/e73f3fa
[#1]: https://github.com/moonmouse11/waybar-vpn-manager/pull/1
[#2]: https://github.com/moonmouse11/waybar-vpn-manager/pull/2
[#3]: https://github.com/moonmouse11/waybar-vpn-manager/pull/3
[#5]: https://github.com/moonmouse11/waybar-vpn-manager/pull/5
[#6]: https://github.com/moonmouse11/waybar-vpn-manager/pull/6
[#7]: https://github.com/moonmouse11/waybar-vpn-manager/pull/7
[#8]: https://github.com/moonmouse11/waybar-vpn-manager/pull/8
[#9]: https://github.com/moonmouse11/waybar-vpn-manager/pull/9
[#10]: https://github.com/moonmouse11/waybar-vpn-manager/pull/10
[#12]: https://github.com/moonmouse11/waybar-vpn-manager/pull/12
[#13]: https://github.com/moonmouse11/waybar-vpn-manager/pull/13
[#14]: https://github.com/moonmouse11/waybar-vpn-manager/pull/14
