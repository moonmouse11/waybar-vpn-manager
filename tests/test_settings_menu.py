"""⚙ Settings: a list in a floating terminal. Space/Enter changes a row in
place (cursor and order stay), `s` saves the draft, `q`/Esc drops it."""

from types import SimpleNamespace

import pytest

import config
import ipsources
import settings_tui
import vpn_manager
from settings_tui import SettingsState

TOOLS = [("dns_leak_test", "🔍 DNS Leak Test"), ("killswitch", "🛡️ Killswitch")]


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    return SettingsState(["WireGuard", "Happ"], TOOLS)


def _go(state, text):
    """Put the cursor on the row whose text starts with `text`."""
    state.cursor = next(i for i, r in enumerate(state.rows()) if r.text.startswith(text))


def _texts(state):
    return [r.text for r in state.rows()]


def test_one_list_with_sections_and_no_button_rows(state):
    texts = _texts(state)
    assert texts[-1] == "🔑 IPQualityScore: no API key"  # save/quit are keys, not rows
    for header in ("── General ──", "── Providers ──", "── Tools ──", "── IP sources ──"):
        assert header in texts
    assert "✅ WireGuard" in texts
    assert "✅ 🔍 DNS Leak Test" in texts


def test_cursor_starts_on_the_first_setting_not_a_header(state):
    assert state.current.text == "✅ DNS always through the VPN tunnel"


def test_enter_changes_the_row_in_place(state):
    _go(state, "✅ Happ")
    before = _texts(state)
    cursor = state.cursor
    assert state.activate() is None
    after = _texts(state)
    assert state.cursor == cursor  # cursor stays
    assert after[cursor] == "⬜ Happ"
    # nothing else moved or changed
    assert [t for i, t in enumerate(after) if i != cursor] == [
        t for i, t in enumerate(before) if i != cursor
    ]
    assert state.dirty


def test_nothing_is_written_before_accept(state):
    _go(state, "✅ DNS always")
    state.activate()
    assert not config.CONFIG_PATH.exists()
    assert state.save() is True
    assert config.load_config().dns_mode == "subscription"


def test_toggling_back_is_not_a_change(state):
    _go(state, "✅ DNS always")
    state.activate()
    state.activate()
    assert not state.dirty
    assert state.save() is False
    assert not config.CONFIG_PATH.exists()


def test_killswitch_mode_cycles(state):
    _go(state, f"{settings_tui.KILLSWITCH_ICON} Killswitch mode: off")
    state.activate()
    assert state.current.text.startswith(f"{settings_tui.KILLSWITCH_ICON} Killswitch mode: happ")
    state.activate()
    state.activate()
    assert state.draft.killswitch_mode == "off"


def test_move_skips_headers_and_stops_at_the_ends(state):
    state.move(-1)
    assert state.current.text.startswith("✅ DNS always")  # top: no wrap
    _go(state, "⬜ Open the Happ app")
    state.move(2)  # killswitch mode, then over "── Providers ──"
    assert state.current.text == "✅ WireGuard"
    state.move(100)
    assert state.current.text == "🔑 IPQualityScore: no API key"  # bottom: no wrap
    state.move(-1)
    assert state.current.text == "🔑 AbuseIPDB: no API key"


def test_keyless_source_toggles(state):
    _go(state, "✅ ipwho.is")
    state.activate()
    state.save()
    assert config.load_config().ip_sources["ipwhois"]["enabled"] is False


def test_api_key_set_kept_and_removed(state):
    abuse = next(s for s in ipsources.ALL_SOURCES if s.key == "abuseipdb")
    _go(state, "🔑 AbuseIPDB: no API key")
    assert state.activate() == "key"
    state.set_api_key(abuse, "secret")
    assert state.current.text == "🔑 AbuseIPDB: API key set"
    state.set_api_key(abuse, None)  # Esc
    assert state.draft.ip_sources["abuseipdb"]["api_key"] == "secret"
    state.set_api_key(abuse, "")  # empty Enter
    assert "api_key" not in state.draft.ip_sources["abuseipdb"]


def test_row_order_never_depends_on_values(state):
    """The cursor is an index: a value change must not shift any row."""
    count = len(state.rows())
    for i, row in enumerate(state.rows()):
        if row.kind == "toggle":
            state.cursor = i
            state.activate()
    assert len(state.rows()) == count


def test_settings_cannot_hide_itself():
    keys = [key for key, _label in vpn_manager._settings_tool_keys()]
    assert "settings" not in keys
    assert "killswitch" in keys


def test_settings_menu_opens_a_floating_terminal_without_omarchy(monkeypatch):
    launched = []
    monkeypatch.setattr(vpn_manager.shutil, "which", lambda name: None)
    monkeypatch.setattr(
        vpn_manager.subprocess, "Popen", lambda cmd, **kw: launched.append((cmd, kw))
    )
    result = vpn_manager.settings_menu()
    assert result.success and result.message == ""
    cmd, kw = launched[0]
    assert cmd[0] == "xdg-terminal-exec"
    assert f"--app-id={vpn_manager.SETTINGS_WINDOW_CLASS}" in cmd
    assert cmd[-1] == "--settings"
    assert kw["start_new_session"] is True


def test_settings_menu_focuses_an_open_window_on_omarchy(monkeypatch):
    launched = []
    monkeypatch.setattr(vpn_manager.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(vpn_manager.subprocess, "Popen", lambda cmd, **kw: launched.append(cmd))
    vpn_manager.settings_menu()
    cmd = launched[0]
    assert cmd[:2] == ["omarchy-launch-or-focus", vpn_manager.SETTINGS_WINDOW_TITLE]
    # one string — launch-or-focus eval's it
    assert cmd[2].startswith("uwsm-app -- xdg-terminal-exec ")
    assert cmd[2].endswith(" --settings")


def test_settings_menu_reports_a_missing_terminal_launcher(monkeypatch):
    monkeypatch.setattr(vpn_manager.shutil, "which", lambda name: None)

    def missing(cmd, **kw):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr(vpn_manager.subprocess, "Popen", missing)
    result = vpn_manager.settings_menu()
    assert not result.success
    assert "--settings" in result.message


def test_settings_window_notifies_only_when_saved(monkeypatch):
    notes = []
    monkeypatch.setattr(vpn_manager, "notify", lambda *a, **k: notes.append(a))
    monkeypatch.setattr(vpn_manager, "refresh_waybar", lambda: notes.append("refresh"))
    monkeypatch.setattr(vpn_manager.settings_tui, "main", lambda providers, tools: False)
    vpn_manager.run_settings_window()
    assert notes == []
    monkeypatch.setattr(vpn_manager.settings_tui, "main", lambda providers, tools: True)
    vpn_manager.run_settings_window()
    assert notes == [("VPN", "Settings saved"), "refresh"]


def test_walker_select_pins_window_size(monkeypatch):
    captured = {}
    result = SimpleNamespace(stdout="a\n")
    monkeypatch.setattr(
        vpn_manager.subprocess, "run", lambda cmd, **kw: captured.update(cmd=cmd) or result
    )
    vpn_manager.walker_select(["a", "b"])
    cmd = captured["cmd"]
    for flag, value in [
        ("--minwidth", vpn_manager.WALKER_MAXWIDTH),
        ("--maxwidth", vpn_manager.WALKER_MAXWIDTH),
        ("--minheight", vpn_manager.WALKER_LIST_HEIGHT),
        ("--maxheight", vpn_manager.WALKER_LIST_HEIGHT),
    ]:
        assert cmd[cmd.index(flag) + 1] == str(value)


# ── curses front end, driven through a fake window ───────────────────────────


class FakeWin:
    """Scripted keys in, drawn text out. `screen` maps line -> text of the
    last frame; running out of keys fails the test instead of hanging."""

    def __init__(self, keys, height=40, width=100, fail_on_line=None):
        self.keys = list(keys)
        self.height, self.width = height, width
        self.fail_on_line = fail_on_line
        self.screen: dict[int, str] = {}
        self.prompts: list[str] = []

    def getmaxyx(self):
        return self.height, self.width

    def erase(self):
        self.screen = {}

    def addnstr(self, y, x, text, n, attr=0):
        if y == self.fail_on_line:
            raise settings_tui.curses.error("addnstr")
        line = self.screen.get(y, "")
        self.screen[y] = (line.ljust(x) + text[:n]).rstrip()

    def refresh(self):
        self.prompts.append(self.screen.get(self.height - 1, ""))

    def keypad(self, flag):
        pass

    def get_wch(self):
        assert self.keys, "ran out of scripted keys"
        return self.keys.pop(0)

    def rows(self):
        return [self.screen[y].strip() for y in sorted(self.screen) if 1 < y < self.height - 1]


@pytest.fixture
def tui(state, monkeypatch):
    monkeypatch.setattr(settings_tui.curses, "curs_set", lambda n: None)
    monkeypatch.setattr(settings_tui.curses, "use_default_colors", lambda: None)

    def run(*keys, **win_kw):
        win = FakeWin(keys, **win_kw)
        return settings_tui.run(win, state), win

    return run


DOWN, UP = settings_tui.curses.KEY_DOWN, settings_tui.curses.KEY_UP
PGDN, PGUP = settings_tui.curses.KEY_NPAGE, settings_tui.curses.KEY_PPAGE


def test_tui_space_toggles_in_place_and_s_saves(state, tui):
    saved, win = tui(DOWN, DOWN, " ", "s")
    assert saved is True
    assert config.load_config().show_empty_providers is True
    assert "✅ Providers with no connections" in win.rows()
    assert win.screen[0].strip() == "VPN Settings • unsaved"  # last frame before save


def test_tui_hint_line_lists_the_keys(state, tui):
    _saved, win = tui("q")
    assert win.prompts[0].split() == ["↑↓", "move", "space", "toggle", "s", "save", "q", "quit"]


def test_tui_quit_without_changes_asks_nothing(state, tui):
    saved, win = tui("q")
    assert saved is False
    assert not any("Unsaved" in p for p in win.prompts)


def test_tui_quit_with_changes_can_go_back_then_discard(state, tui):
    saved, win = tui(" ", "q", "\x1b", "q", "d")
    assert saved is False
    assert not config.CONFIG_PATH.exists()
    assert sum("Unsaved changes" in p for p in win.prompts) == 2


def test_tui_quit_with_changes_can_save(state, tui):
    saved, _win = tui(" ", "\x1b", "s")
    assert saved is True
    assert config.load_config().dns_mode == "subscription"


def test_tui_russian_layout_keys(state, tui):
    # о = j (down), л = k (up), ы = s (save)
    saved, _win = tui("о", "о", "л", " ", "ы")
    assert saved is True
    assert config.load_config().exit_ip_enabled is False


def test_tui_scrolls_to_keep_the_cursor_visible(state, tui):
    _saved, win = tui(PGDN, PGDN, PGDN, "q", height=12)
    assert win.rows()[-1] == "🔑 IPQualityScore: no API key"
    assert state.current.text == "🔑 IPQualityScore: no API key"
    _saved, win = tui(PGUP, PGUP, PGUP, UP, "q", height=12)
    assert win.rows()[0] == "── General ──"


def test_tui_api_key_input_masked_set_kept_removed(state, tui):
    abuse = "🔑 AbuseIPDB"
    # to the bottom, up one: AbuseIPDB; type "ab", backspace, "c", Enter
    tui(PGDN, PGDN, PGDN, UP, "\n", "a", "b", "\x7f", "c", "\n", "q", "d")
    assert state.current.text == f"{abuse}: API key set"
    assert state.draft.ip_sources["abuseipdb"]["api_key"] == "ac"

    _saved, win = tui("\n", "x", "\x1b", "s")  # Esc keeps the old key
    assert any("empty removes it" in p and "•" in p for p in win.prompts)
    assert config.load_config().ip_sources["abuseipdb"]["api_key"] == "ac"

    tui("\n", "\n", "s")  # empty Enter removes it
    assert "api_key" not in config.load_config().ip_sources["abuseipdb"]


def test_tui_survives_writing_into_the_last_cell(state, tui):
    saved, _win = tui("q", fail_on_line=2)  # curses.error on a row is swallowed
    assert saved is False


def test_main_runs_the_loop_in_curses_wrapper(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.delenv("ESCDELAY", raising=False)
    monkeypatch.setattr(settings_tui.locale, "setlocale", lambda *a: None)
    seen = {}

    def fake_wrapper(fn, state):
        seen["state"] = state
        return "result"

    monkeypatch.setattr(settings_tui.curses, "wrapper", fake_wrapper)
    assert settings_tui.main(["WireGuard"], TOOLS) == "result"
    assert settings_tui.os.environ["ESCDELAY"] == "25"
    assert seen["state"].providers == ["WireGuard"]
