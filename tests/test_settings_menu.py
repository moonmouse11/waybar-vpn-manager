"""⚙ Settings: a list in a floating terminal. Enter changes a row in place
(cursor and order stay), ✔️ Accept saves the draft, Cancel / Esc drops it."""

from types import SimpleNamespace

import pytest

import config
import ipsources
import settings_tui
import vpn_manager
from settings_tui import ACCEPT_LABEL, CANCEL_LABEL, SettingsState

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


def test_one_list_with_sections_and_accept_cancel_last(state):
    texts = _texts(state)
    assert texts[-2:] == [ACCEPT_LABEL, CANCEL_LABEL]
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
    _go(state, ACCEPT_LABEL)
    assert state.activate() == "accept"
    assert state.save() is True
    assert config.load_config().dns_mode == "subscription"


def test_toggling_back_is_not_a_change(state):
    _go(state, "✅ DNS always")
    state.activate()
    state.activate()
    assert not state.dirty
    assert state.save() is False
    assert not config.CONFIG_PATH.exists()


def test_cancel_ends_without_saving(state):
    _go(state, "✅ Happ")
    state.activate()
    _go(state, CANCEL_LABEL)
    assert state.activate() == "cancel"
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
    assert state.current.text == CANCEL_LABEL
    state.move(-1)
    assert state.current.text == ACCEPT_LABEL


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


def test_settings_menu_opens_a_floating_terminal(monkeypatch):
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
