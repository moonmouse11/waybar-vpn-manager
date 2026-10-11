"""⚙ Settings window: one list in a small floating terminal.

walker can't do this: it shows a list, returns the picked line and closes —
no way to change a row while it's open or reopen with the cursor on a given
row (2.17's -c only marks one, by index). So the list jumped on every Enter.
Here a row changes in place, the way omarchy's own TUIs (bluetui, impala,
wiremix) work — keys, not buttons, with the keys listed on the bottom line:
↑/↓ (j/k) move, Space/Enter toggles a ✅/⬜ row, cycles the killswitch mode
or edits an API key, `s` saves and closes, `q`/Esc closes (asking first
when there are unsaved changes).

`SettingsState` is the whole behaviour (draft, cursor, actions) and knows
nothing about curses; `run()` only draws it and feeds it keys.
"""

import contextlib
import copy
import curses
import locale
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import config
import ipsources

CHECKED, UNCHECKED = "✅", "⬜"
# VS16 (U+FE0F): bare U+1F6E1 / U+2714 render as thin text glyphs
KILLSWITCH_ICON = "🛡️"
KILLSWITCH_MODES = {
    "off": "manual, Tools toggle only",
    "happ": "with Happ, suspended for other providers",
    "all": "with every provider",
}


@dataclass
class Row:
    text: str
    kind: str  # header | toggle | key
    change: Callable[[config.Config], None] | None = None  # toggle: edits the draft
    source: Any = None  # key: the ipsources source whose API key it edits

    @property
    def selectable(self) -> bool:
        return self.kind != "header"


def _checkbox(on: bool) -> str:
    return CHECKED if on else UNCHECKED


def _source_on(draft: config.Config, source) -> bool:
    # the draft's view, not source.is_enabled() — that reads the saved file
    entry = draft.ip_sources.get(source.key, {})
    if source.needs_api_key:
        return bool(entry.get("api_key"))
    return bool(entry.get("enabled", True))


def build_rows(
    draft: config.Config, providers: list[str], tools: list[tuple[str, str]]
) -> list[Row]:
    """Every row, labelled from the draft. The order and count never depend
    on the draft's values, so the cursor index stays on the same setting."""

    def toggle_dns(d):
        d.dns_mode = "subscription" if d.dns_mode == "tunnel" else "tunnel"

    def toggle_exit_ip(d):
        d.exit_ip_enabled = not d.exit_ip_enabled

    def toggle_empty(d):
        d.show_empty_providers = not d.show_empty_providers

    def toggle_gui(d):
        d.happ_gui_fallback = not d.happ_gui_fallback

    def next_killswitch_mode(d):
        modes = list(KILLSWITCH_MODES)
        d.killswitch_mode = modes[(modes.index(d.killswitch_mode) + 1) % len(modes)]

    mode = draft.killswitch_mode
    rows = [
        Row("── General ──", "header"),
        Row(
            f"{_checkbox(draft.dns_mode == 'tunnel')} DNS always through the VPN tunnel",
            "toggle",
            toggle_dns,
        ),
        Row(f"{_checkbox(draft.exit_ip_enabled)} Exit IP in the tooltip", "toggle", toggle_exit_ip),
        Row(
            f"{_checkbox(draft.show_empty_providers)} Providers with no connections",
            "toggle",
            toggle_empty,
        ),
        Row(
            f"{_checkbox(draft.happ_gui_fallback)} Open the Happ app if headless connect fails",
            "toggle",
            toggle_gui,
        ),
        Row(
            f"{KILLSWITCH_ICON} Killswitch mode: {mode} ({KILLSWITCH_MODES[mode]})",
            "toggle",
            next_killswitch_mode,
        ),
        Row("── Providers ──", "header"),
    ]
    for name in providers:

        def toggle_provider(d, name=name):
            d.providers[name.lower()] = not d.provider_visible(name)

        rows.append(
            Row(f"{_checkbox(draft.provider_visible(name))} {name}", "toggle", toggle_provider)
        )

    rows.append(Row("── Tools ──", "header"))
    for key, label in tools:

        def toggle_tool(d, key=key):
            d.tools_visible[key] = not d.tool_visible(key)

        rows.append(Row(f"{_checkbox(draft.tool_visible(key))} {label}", "toggle", toggle_tool))

    rows.append(Row("── IP sources ──", "header"))
    for source in ipsources.ALL_SOURCES:
        if source.needs_api_key:
            state = "API key set" if _source_on(draft, source) else "no API key"
            rows.append(Row(f"🔑 {source.name}: {state}", "key", source=source))
            continue

        def toggle_source(d, key=source.key):
            entry = d.ip_sources.setdefault(key, {})
            entry["enabled"] = not entry.get("enabled", True)  # keyless default: on

        rows.append(
            Row(f"{_checkbox(_source_on(draft, source))} {source.name}", "toggle", toggle_source)
        )

    return rows


class SettingsState:
    def __init__(self, providers: list[str], tools: list[tuple[str, str]]):
        self.providers, self.tools = providers, tools
        self.saved = config.load_config()
        self.draft = copy.deepcopy(self.saved)
        self.cursor = next(i for i, row in enumerate(self.rows()) if row.selectable)

    def rows(self) -> list[Row]:
        return build_rows(self.draft, self.providers, self.tools)

    @property
    def dirty(self) -> bool:
        return self.draft != self.saved

    @property
    def current(self) -> Row:
        return self.rows()[self.cursor]

    def move(self, delta: int) -> None:
        """Step over headers; stop at either end (no wrap, like a TUI list:
        wrapping would hide where the list ends)."""
        rows = self.rows()
        i = self.cursor
        step = 1 if delta > 0 else -1
        for _ in range(abs(delta)):
            j = i + step
            while 0 <= j < len(rows) and not rows[j].selectable:
                j += step
            if not 0 <= j < len(rows):
                break
            i = j
        self.cursor = i

    def activate(self) -> str | None:
        """Space/Enter on the current row. Toggles act at once and return
        None; "key" asks the caller for input (then set_api_key)."""
        row = self.current
        if row.kind == "toggle" and row.change is not None:
            row.change(self.draft)
            return None
        return "key" if row.kind == "key" else None

    def has_api_key(self, source) -> bool:
        return _source_on(self.draft, source)

    def set_api_key(self, source, value: str | None) -> None:
        """None (Esc): unchanged. "": remove. Anything else: the new key."""
        if value is None:
            return
        entry = self.draft.ip_sources.setdefault(source.key, {})
        if value:
            entry["api_key"] = value
        else:
            entry.pop("api_key", None)

    def save(self) -> bool:
        """True if anything was written."""
        if not self.dirty:
            return False
        config.save_config(self.draft)
        self.saved = copy.deepcopy(self.draft)
        return True


# ── curses front end ──────────────────────────────────────────────────────────

KEY_ESC = 27
# letters also on a Russian layout (j/k/s/q are о/л/ы/й there)
KEYS_UP = (curses.KEY_UP, ord("k"), ord("л"))
KEYS_DOWN = (curses.KEY_DOWN, ord("j"), ord("о"))
KEYS_TOGGLE = (curses.KEY_ENTER, 10, 13, ord(" "))
KEYS_SAVE = (ord("s"), ord("S"), ord("ы"), ord("Ы"), 19)  # 19: Ctrl+S
KEYS_QUIT = (KEY_ESC, ord("q"), ord("Q"), ord("й"), ord("Й"))
HINT = [("↑↓", "move"), ("space", "toggle"), ("s", "save"), ("q", "quit")]


def _put(win, y: int, x: int, text: str, attr: int = 0) -> None:
    # writing into the last cell raises; emoji widths can push a line there
    with contextlib.suppress(curses.error):
        win.addnstr(y, x, text, max(0, win.getmaxyx()[1] - x - 1), attr)


def _draw(win, state: SettingsState, top: int, prompt: str | None = None) -> None:
    win.erase()
    height, width = win.getmaxyx()
    title = "VPN Settings" + (" • unsaved" if state.dirty else "")
    _put(win, 0, 2, title, curses.A_BOLD)
    rows = state.rows()
    for line, i in enumerate(range(top, min(len(rows), top + height - 3)), start=2):
        row = rows[i]
        attr = curses.A_DIM | curses.A_BOLD if row.kind == "header" else 0
        if i == state.cursor:
            attr |= curses.A_REVERSE
            _put(win, line, 0, " " * (width - 1), attr)
        _put(win, line, 2, row.text, attr)
    if prompt is not None:
        _put(win, height - 1, 2, prompt, curses.A_BOLD)
    else:
        x = 2
        for key, action in HINT:  # bluetui-style: key bold, action dim
            _put(win, height - 1, x, key, curses.A_BOLD)
            _put(win, height - 1, x + len(key) + 1, action, curses.A_DIM)
            x += len(key) + len(action) + 4
    win.refresh()


def _read_line(win, state: SettingsState, top: int, label: str) -> str | None:
    """Masked one-line input on the hint line. Enter returns the text (""
    included), Esc returns None."""
    curses.curs_set(1)
    text = ""
    try:
        while True:
            _draw(win, state, top, f"{label}: {'•' * len(text)}")
            ch = win.get_wch()
            if ch in ("\n", "\r", curses.KEY_ENTER):
                return text.strip()
            if ch == "\x1b":
                return None
            if ch in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                text = text[:-1]
            elif isinstance(ch, str) and ch.isprintable():
                text += ch
    finally:
        curses.curs_set(0)


def _ask_unsaved(win, state: SettingsState, top: int) -> str | None:
    """Quitting with changes: "save", "discard", or None to stay."""
    while True:
        _draw(win, state, top, "Unsaved changes — s save · d discard · Esc back")
        ch = win.get_wch()
        if ch in ("s", "S", "\x13", "ы", "Ы"):  # ы: the s key on a Russian layout
            return "save"
        if ch in ("d", "D", "в", "В"):
            return "discard"
        if ch == "\x1b":
            return None


def run(win, state: SettingsState) -> bool:
    """The key loop. True if the draft was saved."""
    curses.curs_set(0)
    curses.use_default_colors()
    win.keypad(True)
    top = 0
    while True:
        height = win.getmaxyx()[0]
        visible = max(1, height - 3)
        top = min(max(top, state.cursor - visible + 1), state.cursor)
        rows = state.rows()
        while top > 0 and not rows[top - 1].selectable and state.cursor - top + 1 < visible:
            top -= 1  # scrolling up: show the section header above the cursor too
        _draw(win, state, top)
        ch = win.get_wch()
        key = ord(ch) if isinstance(ch, str) and len(ch) == 1 else ch
        if key in KEYS_UP:
            state.move(-1)
        elif key in KEYS_DOWN:
            state.move(1)
        elif key == curses.KEY_PPAGE:
            state.move(-visible)
        elif key == curses.KEY_NPAGE:
            state.move(visible)
        elif key in KEYS_SAVE:
            return state.save()
        elif key in KEYS_QUIT:
            if not state.dirty:
                return False
            answer = _ask_unsaved(win, state, top)
            if answer == "save":
                return state.save()
            if answer == "discard":
                return False
        elif key in KEYS_TOGGLE and state.activate() == "key":
            source = state.current.source
            hint = (
                "Enter — empty removes it, Esc keeps it"
                if state.has_api_key(source)
                else "Esc — skip"
            )
            state.set_api_key(
                source, _read_line(win, state, top, f"{source.name} API key ({hint})")
            )


def main(providers: list[str], tools: list[tuple[str, str]]) -> bool:
    os.environ.setdefault("ESCDELAY", "25")  # Esc reacts at once, not after 1 s
    locale.setlocale(locale.LC_ALL, "")  # ncursesw needs it for emoji / Cyrillic
    return curses.wrapper(run, SettingsState(providers, tools))
