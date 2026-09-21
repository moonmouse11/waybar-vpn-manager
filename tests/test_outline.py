import base64
import json

import pytest

import providers.outline as outline


def ss_url(method="aes-256-gcm", password="secret", host="example.com", port=8388, tag=""):
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    frag = f"#{tag}" if tag else ""
    return f"ss://{userinfo}@{host}:{port}{frag}"


# ── parse_ss_key ──────────────────────────────────────────────────────────────


def test_parse_sip002_with_name():
    parsed = outline.parse_ss_key(ss_url(tag="My%20Server"))
    assert parsed == {
        "name": "My Server",
        "host": "example.com",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "secret",
    }


def test_parse_sip002_standard_b64_alphabet_and_padding():
    # standard (non-urlsafe) base64 with padding must decode too
    userinfo = base64.b64encode(b"chacha20-poly1305:pass").decode()  # has +/= maybe
    url = f"ss://{userinfo}@vpn.example.org:443"
    parsed = outline.parse_ss_key(url)
    assert parsed["method"] == "chacha20-poly1305"
    assert parsed["password"] == "pass"
    assert parsed["name"] == "vpn.example.org:443"  # default name: host:port


def test_parse_legacy_json_form():
    payload = base64.b64encode(
        json.dumps(
            {"server": "legacy.example.com", "server_port": 9999,
             "method": "aes-128-gcm", "password": "pw"}
        ).encode()
    ).decode()
    parsed = outline.parse_ss_key(f"ss://{payload}#old")
    assert parsed["host"] == "legacy.example.com"
    assert parsed["port"] == 9999
    assert parsed["method"] == "aes-128-gcm"
    assert parsed["name"] == "old"


def test_parse_ipv6_host():
    parsed = outline.parse_ss_key(ss_url(host="[2001:db8::1]", port=999))
    assert parsed["host"] == "2001:db8::1"
    assert parsed["port"] == 999


def test_parse_rejects_plugin():
    url = ss_url() + "?plugin=v2ray-plugin"
    with pytest.raises(ValueError, match="plugin"):
        outline.parse_ss_key(url)


def test_parse_rejects_outline_prefix():
    url = ss_url() + "?prefix=POST%20"
    with pytest.raises(ValueError, match="prefix"):
        outline.parse_ss_key(url)


def test_parse_rejects_unknown_method():
    with pytest.raises(ValueError, match="method"):
        outline.parse_ss_key(ss_url(method="rc4-md5"))


def test_parse_rejects_garbled():
    with pytest.raises(ValueError):
        outline.parse_ss_key("ss://not-a-key")
    with pytest.raises(ValueError):
        outline.parse_ss_key("ss://YWVzLTI1Ni1nY206c2VjcmV0@host:notaport")
    with pytest.raises(ValueError):
        outline.parse_ss_key("https://example.com")


# ── store ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(outline, "STORE", tmp_path / "outline.json")
    return tmp_path / "outline.json"


def test_add_server_roundtrip_and_mode(store):
    assert outline.add_server(outline.parse_ss_key(ss_url(tag="one"))).success
    servers = outline._load_servers()
    assert len(servers) == 1
    assert servers[0]["name"] == "one"
    import stat

    assert stat.S_IMODE(store.stat().st_mode) == 0o600  # passwords inside


def test_add_server_dedupes_identical_keys(store):
    key = ss_url(tag="a")
    assert outline.add_server(outline.parse_ss_key(key)).success
    dup = outline.add_server(outline.parse_ss_key(key))
    assert not dup.success
    assert "Already" in dup.message
    assert len(outline._load_servers()) == 1


def test_add_server_disambiguates_same_name(store):
    assert outline.add_server(outline.parse_ss_key(ss_url(host="a.com", tag="x"))).success
    second = outline.add_server(outline.parse_ss_key(ss_url(host="b.com", tag="x")))
    assert second.success
    names = [s["name"] for s in outline._load_servers()]
    assert names == ["x", "x (2)"]


def test_find_server_exact_and_unique_substring(store):
    outline.add_server(outline.parse_ss_key(ss_url(host="a.com", tag="alpha")))
    outline.add_server(outline.parse_ss_key(ss_url(host="b.com", tag="beta")))
    assert outline._find_server("beta")["host"] == "b.com"
    assert outline._find_server("alp")["host"] == "a.com"  # unique substring
    assert outline._find_server("a") is None  # ambiguous: alpha / bet[a]


# ── provider ──────────────────────────────────────────────────────────────────


def test_connections_marks_active_from_keeper_state(store, monkeypatch):
    outline.add_server(outline.parse_ss_key(ss_url(tag="s1")))
    outline.add_server(outline.parse_ss_key(ss_url(host="b.com", tag="s2")))
    monkeypatch.setattr(outline, "_daemon_running_processes", lambda: ["xray-outline"])
    monkeypatch.setattr(
        outline, "_read_keeper_state", lambda: {"status": "connected", "server": "s1"}
    )
    conns = outline.OutlineProvider().connections()
    assert [(c.name, c.active, c.interface) for c in conns] == [
        ("s1", True, "outline-tun0"),
        ("s2", False, None),
    ]


def test_connections_empty_without_servers(store):
    assert outline.OutlineProvider().connections() == []


def test_ping_targets(store):
    outline.add_server(outline.parse_ss_key(ss_url(host="a.com", tag="x")))
    assert outline.OutlineProvider().ping_targets() == [("x", "a.com", 8388)]


def test_import_config_reads_key_from_file(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(f"Вот ключ:\n{ss_url(tag='from-file')}\n")
    result = outline.OutlineProvider().import_config(str(key_file))
    assert result.success
    assert outline._load_servers()[0]["name"] == "from-file"


def test_import_config_rejects_keyless_file(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text("no keys here")
    result = outline.OutlineProvider().import_config(str(key_file))
    assert not result.success


def test_import_config_surfaces_parser_reason(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(ss_url() + "?plugin=obfs-local")
    result = outline.OutlineProvider().import_config(str(key_file))
    assert not result.success
    assert "plugin" in result.message
