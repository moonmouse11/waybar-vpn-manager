# Pluggable IP-intelligence sources, Tools submenu, install-time config wizard

Status: draft, pending user review
Date: 2026-09-28

## Motivation

This session found and fixed a real DNS leak and an IPv6 leak in the Happ/xray
path, then built diagnostic menu actions (`🔍 DNS Leak Test`, `ℹ️ IP Info`) and
a server-reputation feature (`src/reputation.py`) that flags Happ/WireGuard/
OpenVPN/Keys connections whose exit IP looks Russian-registered or
datacenter/proxy-flagged. That reputation check currently hardcodes exactly
two free, keyless data sources (`ipwho.is`, `ip-api.com`) as plain module
functions inside `reputation.py`.

The user wants to add more IP-intelligence sources going forward, including
ones that need a paid API key (AbuseIPDB, IPQualityScore, and eventually
others such as MaxMind, which isn't even a REST API — it's a local binary
GeoIP2 database). The current code has no abstraction for "one interface,
multiple backends" here, unlike the VPN side of this project, which already
solves exactly that shape with `providers/base.py`'s `VPNProvider` ABC and
`providers/__init__.py`'s `ALL_PROVIDERS` registry.

Separately, the menu has accumulated three always-visible top-level rows
(`🔍 DNS Leak Test`, `ℹ️ IP Info`, the killswitch toggle) that belong under a
single "Tools" submenu, plus a new one (subdomain search via `crt.name`,
found useful during this session). And the user wants `make install` to
optionally walk through the resulting configuration surface interactively.

## Goals

- Turn `reputation.py`'s two hardcoded lookups into a pluggable source
  registry, so adding AbuseIPDB/IPQualityScore/future sources is "write one
  file + register it," matching the `ALL_PROVIDERS` pattern.
- Support sources that need a user-supplied API key, configured via
  `config.json` and/or an in-menu prompt, without forcing every source
  through the same auth shape (headers vs. query param vs. local file all
  need to work).
- Keyed/paid sources are used **only** by the on-demand `ℹ️ IP Info` action
  (a single lookup), never by the daily background sweep across 100+ Happ
  servers (`write_reputations`) — free sources keep doing that job, so a
  paid source's monthly quota is never at risk from routine menu use.
- Reorganize `🔍 DNS Leak Test`, `ℹ️ IP Info`, the killswitch toggle, and four
  new entries — `🔎 Subdomain Search` (crt.name), `⚡ Speed Test`,
  `🔄 Refresh All`, `🗑 Clear Caches`, `⚙ Settings` — under one `🛠 Tools`
  submenu.
- Let `config.json` control which VPN providers, which Tools entries, and
  which IP sources are active — the provider-hiding piece already exists
  (`cfg.providers`); this adds the equivalent for Tools and IP sources.
- `make install` can walk through this configuration interactively,
  without ever clobbering an existing `config.json` (including API keys)
  unless the user explicitly asks to reconfigure — and the same walk is
  reachable later from `🛠 Tools → ⚙ Settings`, without reinstalling.
- Confirmed during review: ping/dead-connection status (`happmeta.
  ping_mark`) already covers every provider, not just Happ, via the shared
  `PING_CACHE` and `_collect_ping_targets()` — no gap, just the marker
  itself (`✗` → `⛔`) gets easier to spot in a busy list.

## Non-goals

- Not implementing MaxMind or any other specific future source now — the
  two concrete keyed examples (AbuseIPDB, IPQualityScore) exist to prove the
  interface handles real, differently-shaped auth (header key vs.
  query-param key), not to be an exhaustive source list.
- Not changing how the *free* sources behave in the background sweep beyond
  moving their code into the new package — `write_reputations()`'s caching,
  pacing, and dedupe-by-host logic are unchanged.
- Not adding arbitrary free-form settings editing — the in-menu `⚙ Settings`
  action runs the exact same fixed walk as `--configure` (providers, tools,
  sources/keys); it is not a general config.json editor.

## Architecture: `src/ipsources/`

New package, mirroring `src/providers/`:

```
src/ipsources/
    __init__.py     # ALL_SOURCES registry
    base.py         # IPInfoSource ABC, IPFinding dataclass
    ipwhois.py      # free, keyless — moved from reputation.py as-is
    ipapi.py        # free, keyless — moved from reputation.py as-is
    abuseipdb.py    # keyed
    ipqualityscore.py  # keyed
```

`base.py`:

```python
@dataclass
class IPFinding:
    source: str                    # display name, e.g. "AbuseIPDB"
    ip: str | None = None          # the address this finding is actually about
    country_code: str | None = None
    country_name: str | None = None
    org: str | None = None
    domain: str | None = None      # ASN-owner domain, when the source has one
    hosting: bool | None = None
    proxy: bool | None = None
    mobile: bool | None = None
    abuse_score: int | None = None # 0-100, AbuseIPDB-style; other sources leave it None
    raw: dict = field(default_factory=dict)  # source-specific extras for display only

class IPInfoSource(ABC):
    key: str            # config key, e.g. "abuseipdb"
    name: str           # display name, e.g. "AbuseIPDB"
    needs_api_key: bool = False

    def is_enabled(self) -> bool:
        """Reads config.load_config() itself — same style as killswitch.mode()
        reading config internally rather than being passed it. A keyed source
        is enabled by having a non-empty api_key (no separate on/off flag —
        an "enabled but keyless" state can't happen and needs no toggle); a
        keyless source defaults to enabled, opt-out via config."""
        cfg = config.load_config()
        src_cfg = cfg.ip_sources.get(self.key, {})
        if self.needs_api_key:
            return bool(src_cfg.get("api_key"))
        return bool(src_cfg.get("enabled", True))

    @abstractmethod
    def lookup(self, ip: str) -> IPFinding | None:
        """None on any failure (network, bad key, rate limit) — one source
        failing must never break the others, mirroring how
        write_reputations() already tolerates a bad host. A keyed source's
        own lookup() reads its api_key the same way is_enabled() does
        (config.load_config().ip_sources[self.key]["api_key"]) — callers
        never pass a key in; is_enabled() already guarantees one exists by
        the time lookup() runs."""
        ...
```

`__init__.py`:

```python
ALL_SOURCES = [
    IpWhoIsSource(),
    IpApiSource(),
    AbuseIPDBSource(),
    IPQualityScoreSource(),
]
```

Plain instances, like `ALL_PROVIDERS` — no factory, no plugin loading.
Adding a new source is: write the file, implement `lookup()`, add one line
here. (Documented in CLAUDE.md's existing "Adding a new provider" section,
extended with an "Adding a new IP source" counterpart.)

### `reputation.py` becomes an orchestrator

It stops calling `ipwho.is`/`ip-api.com` directly. `is_suspicious(entry:
dict)` / `_reason_tags(entry: dict)` **keep their current single-dict
signature unchanged** — `ipinfo.py`'s `status_line()` and
`vpn_manager._dns_leak_server_row()` both call these today with an ad-hoc
dict built from an unrelated data source (ipinfo's own exit-IP cache,
bash.ws's per-server entries respectively), neither of which goes through
`ipsources` at all, and touching either is out of scope here. New,
separate functions handle the findings-list case the new orchestration
actually produces:

```python
def _enabled_sources(include_keyed: bool) -> list[IPInfoSource]:
    return [s for s in ipsources.ALL_SOURCES
            if s.is_enabled() and (include_keyed or not s.needs_api_key)]

def combined_tags(findings: list[IPFinding]) -> list[str]:
    """Union of _reason_tags(dataclasses.asdict(f)) over every finding, in
    first-seen order — reuses the existing single-dict logic per finding
    instead of duplicating the RU/DC/PROXY rules."""
    ...

def is_flagged(findings: list[IPFinding]) -> bool:
    return bool(combined_tags(findings))

def _detect_own_ip() -> str | None:
    """One shared bootstrap so every source in lookup_self() is asked
    about the SAME address, rather than each keyless "self-detect" source
    potentially reporting a different one. Reuses ipinfo.py's existing
    ipwho.is/ifconfig.me fallback chain — no new network dependency."""
    ...

def lookup_host(host: str, include_keyed: bool) -> list[IPFinding]:
    """Resolves host once, queries every enabled source with that one IP
    (thread-guarded per-source exactly like today's single _lookup()),
    returns whatever findings came back (partial success is fine)."""
    ...

def lookup_self(include_keyed: bool = True) -> list[IPFinding]:
    """On-demand 'IP Info': _detect_own_ip() once, then every enabled
    source (keyed included) against that address."""
    ip = _detect_own_ip()
    if not ip:
        return []
    return [f for s in _enabled_sources(include_keyed) if (f := s.lookup(ip))]

def write_reputations(targets) -> None:
    """Unchanged pacing/dedupe/cache-write logic, but each per-host lookup
    now calls lookup_host(host, include_keyed=False) — free sources only.
    Cache entries store combined_tags(findings) under "tags", same field
    mark() already reads."""
    ...
```

The `IPInfoSource.lookup(ip)` interface stays single-method (no separate
"look up my own IP" method per source) — `_detect_own_ip()` is the one
place that decides what "my own IP" means, every source just answers
"what do you know about this address."

No cache schema migration needed beyond what already happened this
session (the `"tags"` key was already added to `reputation.json`; old
entries without it already degrade gracefully to `mark() == ""` until the
next sweep overwrites them).

### Why not other shapes

- **Data-driven source list** (a list of dicts: URL template + field
  mapping, no classes) — breaks down immediately once sources have
  different auth (AbuseIPDB: header; IPQualityScore: key embedded in the
  URL path) or aren't HTTP at all (MaxMind: local binary DB, different
  library entirely). Rejected.
- **Fully config-driven generic HTTP source** (URL/header/JSONPath mapping
  all in `config.json`, zero source-specific code) — maximally flexible but
  nobody is going to hand-write JSONPath mappings in JSON, and it still
  can't express MaxMind. Overengineered for the actual need. Rejected.

## Config schema (`src/config.py`)

New `Config` fields:

```python
ip_sources: dict[str, dict] = field(default_factory=dict)
# {"abuseipdb": {"api_key": "..."}, "ipapi": {"enabled": false}, ...}

tools_visible: dict[str, bool] = field(default_factory=dict)
# {"dns_leak_test": true, "ip_info": true, "killswitch": true, "subdomain_search": true}

def tool_visible(self, key: str) -> bool:
    return self.tools_visible.get(key, True)
```

Mirrors the existing `providers: dict[str, bool]` / `provider_visible()`
pair exactly. `load_config()`/`save_config()` gain the matching
read/validate/write blocks (same style as the existing `exit_ip` block —
tolerate a missing or malformed key by falling back to the default).

## Menu changes (`src/vpn_manager.py`)

`menu_loop()` drops its three separate rows for DNS Leak Test / IP Info /
killswitch. One row replaces them:

```python
items.append(("🛠 Tools", tools_menu))
```

```python
# single source of truth for both tools_menu()'s rows and the configure
# wizard's questions (key, label, action) — killswitch is handled
# separately in both places since its row reflects live on/off state
# (_killswitch_item()), not a fixed action function.
TOOLS = [
    ("dns_leak_test", "🔍 DNS Leak Test", dns_leak_test_menu),
    ("ip_info", "ℹ️ IP Info", ip_info_menu),
    ("subdomain_search", "🔎 Subdomain Search", subdomain_search_menu),
    ("speed_test", "⚡ Speed Test", speed_test_menu),
    ("refresh_all", "🔄 Refresh All", refresh_all_menu),
    ("clear_caches", "🗑 Clear Caches", clear_caches_menu),
    ("settings", "⚙ Settings", settings_menu),
]

def tools_menu() -> ActionResult:
    cfg = config.load_config()
    items = [(label, fn) for key, label, fn in TOOLS if cfg.tool_visible(key)]
    if cfg.tool_visible("killswitch"):
        items.append(_killswitch_item())
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt="Tools")
    return ActionResult(True, "")
```

New `tools_visible` keys, defaulting to `true` like the rest: `speed_test`,
`refresh_all`, `clear_caches`, `settings` (alongside the existing
`dns_leak_test`, `ip_info`, `killswitch`, `subdomain_search`).

`ip_info_menu()` changes from two hardcoded rows to one row group per
enabled source:

```python
findings = reputation.lookup_self(include_keyed=True)
if not findings:
    return ActionResult(False, "Не удалось получить информацию об IP — нет сети?")
items = [(f"IP: {findings[0].ip}", noop)]
for f in findings:
    parts = [p for p in (f.country_name, f.org) if p]
    items.append((f"{f.source}: {' · '.join(parts)}" if parts else f.source, noop))
# hosting/proxy/mobile rows: True if any finding says so (any(f.hosting for f in findings), etc.)
```

(`noop = lambda: ActionResult(True, "")`, already the pattern for
informational rows.)

### New: Subdomain Search (`crt.name`)

`crt.name` has a real, free, keyless JSON endpoint:
`GET https://crt.name/v1/search?apex=<domain>` → `[{"sub": "..."}, ...]`,
rate-limited (~100/window, observed via `X-RateLimit-*` response headers).
Purely on-demand, no background polling, so the rate limit is a non-issue
for normal use. New tiny module `src/crtname.py`, mirroring `dnsleak.py`'s
shape: `search(domain: str) -> list[str] | None` — `None` on any network
failure, else the flat list of subdomain strings (possibly empty).

```python
def subdomain_search_menu() -> ActionResult:
    domain = walker_input("Domain (apex)")   # same -I pattern as import_config_file
    if not domain:
        return ActionResult(True, "")
    subs = crtname.search(domain)  # new tiny module, mirrors dnsleak.py's shape
    if subs is None:
        return ActionResult(False, "Не удалось выполнить поиск — нет сети?")
    items = [(s, noop) for s in subs] or [("No subdomains found", noop)]
    items.append(("‹ Back", back_to_main))
    run_items(_unique_labels(items), prompt=f"Subdomains: {domain}")
    return ActionResult(True, "")
```

`walker_input()` is a tiny refactor extracting the existing single-field
`walker -d -I -p ...` invocation out of `import_config_file()` so both
call sites share it (it already gets `WALKER_WIDTH`/`WALKER_MAXWIDTH`).

### New: Dead-connection marker (all providers)

`happmeta.ping_mark(name)` already exists and already covers every
provider, not just Happ — confirmed during spec review:
`_collect_ping_targets()` (`vpn_manager.py`) combines `happmeta.
ping_targets()` with every `ALL_PROVIDERS` member's own `ping_targets()`
(WireGuard/AmneziaWG/OpenVPN/Keys all implement it), into the one shared
`PING_CACHE` that `ping_mark()`/`server_info_suffix()` read regardless of
which provider's menu is asking. No gap here, just a display tweak:

```python
def ping_mark(name: str) -> str:
    entry = _fresh_ping_entry(name)
    if entry is None:
        return ""
    if entry.get("ms") is None:
        return "⛔"   # was "✗" — more visible in a busy server list
    return f"✓ {entry['ms']:.0f} ms"
```

One function, so every caller (`provider_menu()`, `happ_provider_menu()`)
picks it up automatically.

### New: Refresh All

```python
def refresh_all_menu() -> ActionResult:
    """Force a ping sweep (every provider) + Happ subscription sync now,
    bypassing PING_MAX_AGE/SUB_MAX_AGE — request_ping_update()/
    request_subscription_update() are staleness-gated and would otherwise
    no-op if the last sweep was recent. Reputation is deliberately excluded
    (its own daily cadence + IPAPI_PACE already make it a multi-minute
    background job; forcing it from a menu click isn't 'refresh now', it's
    'wait a while', which belongs to its own timer, not this button)."""
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-ping"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    subprocess.Popen(
        [sys.executable, str(MANAGER), "--update-subs"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    return ActionResult(True, "Обновление запущено в фоне")
```

Unconditional spawn (no staleness check) is exactly what makes this
different from what already happens automatically — the point is "do it
now," not "do it now if it wasn't already about to happen."

### New: Clear Caches

Every cache this project writes already lives under one directory,
confirmed by reading each module's cache path constant: `happmeta.
PING_CACHE`, `happmeta.PROVIDERS_CACHE`, `happmeta.SUB_CACHE_DIR` (holds
`subscription-*.json`), `reputation.CACHE`, `ipinfo.CACHE_PATH`,
`providers/base.py`'s `RATE_CACHE` — all `~/.cache/vpn-manager/<file>.json`.
`~/.config/happ-capture/` is **not** touched — that's captured server data,
not a cache.

```python
def clear_caches_menu() -> ActionResult:
    cache_dir = Path.home() / ".cache/vpn-manager"
    removed = 0
    for f in cache_dir.glob("*.json"):
        with contextlib.suppress(OSError):
            f.unlink()
            removed += 1
    return ActionResult(True, f"Кэш очищен ({removed} файлов) — пересоберётся сам")
```

Everything that reads these caches already tolerates a missing file
(`json.loads(path.read_text())` wrapped in `except (OSError,
json.JSONDecodeError): return {}` is the established pattern in every
module here) — deleting them is safe by construction, no new fallback
code needed.

### New: Speed Test

Single-measurement download throughput against Cloudflare's public speed
test endpoint (no auth, this is the same endpoint speed.cloudflare.com's
own page uses): `https://speed.cloudflare.com/__down?bytes=10000000` (10
MB). New tiny module `src/speedtest.py`:

```python
def measure() -> float | None:
    """MB/s over a single 10 MB download through the current default
    route (i.e. through the tunnel if one is up), or None on failure."""
    url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        t0 = time.perf_counter()
        with urllib.request.urlopen(url, timeout=20) as resp:
            n = len(resp.read())
        dt = time.perf_counter() - t0
    except (OSError, ValueError):
        return None
    return (n / 1_000_000) / dt if dt > 0 else None
```

`speed_test_menu()` notifies "Тест запущен…" (a 10 MB download over a
slow/throttled VPN could take several seconds), then shows the result —
synchronous is fine here the same way `dns_leak_test_menu()` already
accepts a few seconds of blocking for an explicit, user-initiated click.

### New: Settings (in-menu, no reinstall)

Same wizard as `--configure` (see below), reachable without re-running
`make install`. The wizard's actual settings walk (which providers, which
tools, which sources/keys) must not be written twice — it's authored once
against a small `Prompter` interface, with a terminal implementation for
install-time and a walker implementation for in-menu use:

```python
class Prompter(ABC):
    def confirm(self, question: str, default: bool) -> bool: ...
    def text(self, question: str) -> str: ...  # "" means skipped/cancelled

class TerminalPrompter(Prompter):
    def confirm(self, question, default):
        suffix = "[Y/n]" if default else "[y/N]"
        answer = input(f"{question} {suffix} ").strip().lower()
        return default if not answer else answer in ("y", "yes", "д", "да")
    def text(self, question):
        return input(f"{question}: ").strip()

class WalkerPrompter(Prompter):
    def confirm(self, question, default):
        selected = walker_select(["Да", "Нет"], prompt=question)
        return (selected == "Да") if selected else default
    def text(self, question):
        return walker_input(question)

def run_configure_wizard(prompter: Prompter) -> None:
    ...  # the walk itself (providers/tools/sources), calling prompter.confirm()/text()
    config.save_config(cfg)
```

`--configure` (CLI) constructs `TerminalPrompter()`; `settings_menu()`
(Tools) constructs `WalkerPrompter()` and runs the identical walk — one
list of questions, two front ends. The existing-config confirmation gate
(`config.json` already exists → ask before touching it) applies to both,
since `settings_menu()` is exactly as capable of overwriting saved API
keys as a second `make install` run is.

## Install-time configuration wizard

New CLI flag on `vpn_manager.py`: `--configure` (a user-facing interactive
flag, distinct from the internal `--update-*` ones). `install.sh` calls it
as the last step:

```bash
echo "==> Configuration..."
python3 "$REPO_DIR/src/vpn_manager.py" --configure
```

which is just:

```python
elif args.configure:
    run_configure_wizard(TerminalPrompter())
```

`run_configure_wizard(prompter)` — the actual walk, shared with the
in-menu `⚙ Settings` action (`WalkerPrompter()`, see above):

```python
def run_configure_wizard(prompter: Prompter) -> None:
    if config.CONFIG_PATH.exists():
        if not prompter.confirm("Конфиг уже существует. Перенастроить?", default=False):
            return
        cfg = config.load_config()   # existing values as the starting point
    else:
        cfg = config.Config()

    # 1. VPN providers to show
    for provider in ALL_PROVIDERS:
        visible = prompter.confirm(f"Показывать {provider.name}?",
                                    default=cfg.provider_visible(provider.name))
        cfg.providers[provider.name.lower()] = visible

    # 2. Tools to show (killswitch included — it's not in TOOLS since its
    # row reflects live state, but its visibility is still a plain toggle)
    for key, label, _fn in [*TOOLS, ("killswitch", "Killswitch", None)]:
        visible = prompter.confirm(f"Показывать инструмент «{label}»?",
                                    default=cfg.tool_visible(key))
        cfg.tools_visible[key] = visible

    # 3. IP-intelligence sources
    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            existing = cfg.ip_sources.get(source.key, {}).get("api_key", "")
            key = prompter.text(f"API-ключ {source.name} (Enter — оставить как есть/пропустить)")
            if key:
                cfg.ip_sources.setdefault(source.key, {})["api_key"] = key
            elif existing:
                pass  # keep what was already there
        else:
            enabled = prompter.confirm(f"Использовать {source.name}?",
                                        default=source.is_enabled())
            cfg.ip_sources.setdefault(source.key, {})["enabled"] = enabled

    config.save_config(cfg)
```

`make install` runs interactively in a real terminal already (the user
answers `sudo` prompts during the same run), so `TerminalPrompter` needs no
new I/O plumbing. Never runs unless the user opts in via the confirm gate
on re-install; always runs once, uninterrupted, on a fresh install (no
existing `config.json` to protect).

## Testing

- `tests/test_ipsources.py` (new): one test per source's `lookup()` against
  a mocked `urlopen`/response (happy path + failure-returns-None), plus
  `is_enabled()` for both the keyed and keyless cases (present/absent key,
  explicit `enabled: false`).
- `tests/test_reputation.py`: rewritten around the new orchestration
  functions (`lookup_host`, `lookup_self`, `combined_tags`/`is_flagged` over
  a list of findings) — mocks `ipsources.ALL_SOURCES` with fake source
  instances rather than mocking `urllib.request.urlopen` directly, since
  the network detail now lives one layer down in `ipsources/`. The
  existing single-dict `is_suspicious`/`_reason_tags` tests are unaffected
  (that function's signature doesn't change). `write_reputations`'s
  dedupe/pacing tests are otherwise unchanged.
- `tests/test_menu.py`: `tools_menu()` row visibility per `cfg.tools_visible`
  (mirroring the existing provider-visibility tests), `ip_info_menu()`
  rebuilt for N mocked findings instead of 2 hardcoded dicts,
  `subdomain_search_menu()` happy path + no-results + network-failure,
  `refresh_all_menu()` spawns both subprocesses unconditionally (mocked
  `Popen`, assert called regardless of cache freshness — the whole point
  is bypassing the staleness gate), `clear_caches_menu()` against a
  `tmp_path` standing in for the cache dir (asserts it only touches
  `*.json` there, leaves an unrelated file alone), `speed_test_menu()`
  with `speedtest.measure` mocked (happy path + `None`/network-failure).
- `tests/test_speedtest.py` (new): `measure()` against a mocked `urlopen`
  (known byte count + controlled elapsed time via a monkeypatched
  `time.perf_counter` → exact expected MB/s; failure returns `None`).
- `tests/test_crtname.py` (new): `search()` against a mocked `urlopen`
  (happy path parses `{"sub": ...}` entries into a flat list; failure and
  malformed-JSON both return `None`).
- `tests/test_config.py`: `ip_sources`/`tools_visible` round-trip
  (load/save), including a keyed source's `api_key` surviving a save/load
  cycle and an old config file (missing these keys entirely) still loading
  with the documented defaults.
- `tests/test_configure_wizard.py` (new): `run_configure_wizard()` against
  a fake in-memory `Prompter` (canned `confirm`/`text` answers fed in
  order) — asserts the resulting `Config` matches, and that an existing
  `config.json` is left untouched when the reconfigure gate answers no.
  `TerminalPrompter`/`WalkerPrompter` each get one thin test of their own
  (`confirm`/`text` map to `input()` / `walker_select()`/`walker_input()`
  correctly) — the wizard's *logic* is tested once, against the fake,
  not duplicated per front-end. `make install` itself is still never
  executed by the test suite (real system installer, same as today).

## Migration / rollout notes

- `~/.cache/vpn-manager/reputation.json` needs no explicit migration —
  entries without the current `"tags"` key already degrade to a silent
  `mark() == ""` until the next sweep overwrites them (this was already
  true before this change).
- `~/.config/vpn-manager/config.json` gains two new optional keys
  (`ip_sources`, `tools_visible`); an existing file without them loads with
  documented defaults (everything visible/enabled as today), so this is a
  non-breaking, purely additive change to the config format.
- `CLAUDE.md`'s "Adding a new provider" section gets a sibling "Adding a new
  IP-intelligence source" section once this lands.
