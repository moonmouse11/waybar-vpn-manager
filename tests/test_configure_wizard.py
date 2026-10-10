import config
import vpn_manager
from providers.base import ActionResult  # noqa: F401


class FakePrompter(vpn_manager.Prompter):
    """Feeds canned answers in call order — confirms and texts are two
    separate queues since the wizard interleaves them by section."""

    def __init__(self, confirms, texts=()):
        self._confirms = iter(confirms)
        self._texts = iter(texts)

    def confirm(self, question, default):
        return next(self._confirms, default)

    def text(self, question):
        return next(self._texts, "")


def test_terminal_prompter_confirm_default_on_empty_answer(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is True
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is False


def test_terminal_prompter_confirm_explicit_answer(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "y")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is True
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is False


def test_terminal_prompter_text_strips_input(monkeypatch):
    # text() now goes through getpass.getpass (not input()) so a typed API
    # key doesn't echo to the terminal/scrollback.
    monkeypatch.setattr(vpn_manager.getpass, "getpass", lambda prompt: "  secret-key  ")
    assert vpn_manager.TerminalPrompter().text("Key?") == "secret-key"


def test_terminal_prompter_confirm_returns_default_on_eof_and_interrupt(monkeypatch):
    """A non-interactive --configure (e.g. under install.sh's set -e) must
    not turn a successful install into a reported failure: EOFError and
    KeyboardInterrupt on input() fall back to the question's default."""

    def raise_eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", raise_eof)
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is True
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is False

    def raise_interrupt(prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", raise_interrupt)
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=True) is True
    assert vpn_manager.TerminalPrompter().confirm("Q?", default=False) is False


def test_terminal_prompter_text_returns_empty_on_eof_and_interrupt(monkeypatch):
    """Same guard for getpass-based text(): an interrupted API-key prompt
    yields "" (keep existing / skip), not an exception."""

    def raise_eof(prompt):
        raise EOFError

    monkeypatch.setattr(vpn_manager.getpass, "getpass", raise_eof)
    assert vpn_manager.TerminalPrompter().text("Key?") == ""

    def raise_interrupt(prompt):
        raise KeyboardInterrupt

    monkeypatch.setattr(vpn_manager.getpass, "getpass", raise_interrupt)
    assert vpn_manager.TerminalPrompter().text("Key?") == ""


def test_walker_prompter_confirm_maps_selection(monkeypatch):
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": "Yes")
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=False) is True
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": "No")
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=True) is False
    monkeypatch.setattr(vpn_manager, "walker_select", lambda options, prompt="VPN": None)
    assert vpn_manager.WalkerPrompter().confirm("Q?", default=True) is True  # escaped -> default


def test_walker_prompter_text_delegates_to_walker_input(monkeypatch):
    monkeypatch.setattr(vpn_manager, "walker_input", lambda prompt: "example.com")
    assert vpn_manager.WalkerPrompter().text("Domain?") == "example.com"


def test_run_configure_wizard_writes_config_from_scratch(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])  # keep the answer sequence short
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [])

    # No providers, no sources -> 6 TOOLS rows + killswitch
    prompter = FakePrompter(confirms=[True] * 7)  # 6 TOOLS rows + killswitch
    assert vpn_manager.run_configure_wizard(prompter) is True

    loaded = config.load_config()
    assert loaded.tools_visible["dns_leak_test"] is True
    assert loaded.tools_visible["killswitch"] is True


def test_run_configure_wizard_respects_existing_config_refusal(tmp_path, monkeypatch):
    p = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_PATH", p)
    original = config.Config(killswitch_mode="happ")
    config.save_config(original)

    prompter = FakePrompter(confirms=[False])  # "reconfigure?" -> no
    assert vpn_manager.run_configure_wizard(prompter) is False

    assert config.load_config().killswitch_mode == "happ"  # untouched


def test_run_configure_wizard_collects_api_keys(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])

    class FakeSource:
        def __init__(self, key, name, needs_api_key):
            self.key, self.name, self.needs_api_key = key, name, needs_api_key

        def is_enabled(self):
            return False

    keyed = FakeSource("abuseipdb", "AbuseIPDB", True)
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [keyed])

    prompter = FakePrompter(confirms=[True] * 7, texts=["secret-key-123"])
    assert vpn_manager.run_configure_wizard(prompter) is True

    loaded = config.load_config()
    assert loaded.ip_sources["abuseipdb"]["api_key"] == "secret-key-123"


def test_settings_menu_runs_wizard_with_walker_prompter(monkeypatch):
    called = {}
    monkeypatch.setattr(
        vpn_manager,
        "run_configure_wizard",
        lambda prompter: called.update(kind=type(prompter)) or True,
    )
    result = vpn_manager.settings_menu()
    assert result.success
    assert called["kind"] is vpn_manager.WalkerPrompter


def test_settings_menu_reports_no_op_when_wizard_declined(monkeypatch):
    monkeypatch.setattr(vpn_manager, "run_configure_wizard", lambda prompter: False)
    result = vpn_manager.settings_menu()
    assert result.success is True
    assert "unchanged" in result.message


def test_run_configure_wizard_asks_dns_mode_last(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [])

    # 6 TOOLS rows + killswitch, then "force DNS through the tunnel?" -> no
    assert vpn_manager.run_configure_wizard(FakePrompter(confirms=[True] * 7 + [False]))
    assert config.load_config().dns_mode == "subscription"


def test_run_configure_wizard_dns_mode_defaults_to_tunnel(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(vpn_manager, "ALL_PROVIDERS", [])
    monkeypatch.setattr(vpn_manager.ipsources, "ALL_SOURCES", [])

    assert vpn_manager.run_configure_wizard(FakePrompter(confirms=[True] * 7))  # Enter -> default
    assert config.load_config().dns_mode == "tunnel"
