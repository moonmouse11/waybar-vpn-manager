from providers import wireguard
from providers.wireguard import WireGuardProvider


def _provider(tmp_path, monkeypatch, run_result=(0, "")):
    provider = WireGuardProvider()
    provider.config_dir = tmp_path / "dest"
    provider.config_dir.mkdir()
    monkeypatch.setattr(wireguard, "_run", lambda cmd: run_result)
    return provider


def test_import_warns_when_dns_missing(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text("[Interface]\nPrivateKey = x\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n")

    result = provider.import_config(str(src))
    assert result.success
    assert "no DNS=" in result.message


def test_import_silent_when_dns_present(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text(
        "[Interface]\nPrivateKey = x\nDNS = 10.0.0.1\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n"
    )

    result = provider.import_config(str(src))
    assert result.success
    assert "no DNS=" not in result.message


def test_import_dns_key_lookup_is_case_insensitive(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    src.write_text("[Interface]\ndns = 10.0.0.1\n\n[Peer]\nEndpoint = 1.2.3.4:51820\n")

    result = provider.import_config(str(src))
    assert "no DNS=" not in result.message


def test_import_ignores_dns_looking_key_in_peer_section(tmp_path, monkeypatch):
    provider = _provider(tmp_path, monkeypatch)
    src = tmp_path / "nl.conf"
    # a DNS-looking key inside [Peer] must not count — only [Interface] does
    src.write_text(
        "[Interface]\nprivatekey = x\n\n[Peer]\nDns = 1.1.1.1\nEndpoint = 1.2.3.4:51820\n"
    )

    result = provider.import_config(str(src))
    assert "no DNS=" in result.message


def test_has_dns_directive_unreadable_file_treated_as_present(tmp_path):
    missing = tmp_path / "nope.conf"
    assert wireguard._has_dns_directive(missing) is True
