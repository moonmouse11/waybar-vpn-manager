import base64
import json

import pytest

import providers.keys as keys


def ss_url(method="aes-256-gcm", password="secret", host="example.com", port=8388, tag=""):
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    frag = f"#{tag}" if tag else ""
    return f"ss://{userinfo}@{host}:{port}{frag}"


# ── parse_ss_key ──────────────────────────────────────────────────────────────


def test_parse_sip002_with_name():
    parsed = keys.parse_ss_key(ss_url(tag="My%20Server"))
    assert parsed == {
        "kind": "ss",
        "name": "My Server",
        "host": "example.com",
        "port": 8388,
        "method": "aes-256-gcm",
        "password": "secret",
    }


def test_parse_legacy_cipher_rejected():
    """Legacy ciphers (aes-256-cfb, still handed out by OutlineKeys) were
    removed from xray 26 — the import must say so instead of failing at
    connect time."""
    import pytest

    with pytest.raises(ValueError, match="aes-256-cfb"):
        keys.parse_ss_key(ss_url(method="aes-256-cfb"))


# ── parse_vless_key ───────────────────────────────────────────────────────────


def test_parse_vless_minimal():
    """The user's real key shape: no query params at all (tcp, no tls).
    The key-shop " / OutlineKeys.com" suffix is stripped from the name."""
    parsed = keys.parse_vless_key(
        "vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@94.130.68.139:2222"
        "#Germany%20%2341294%20%2F%20OutlineKeys.com"
    )
    assert parsed["kind"] == "vless"
    assert parsed["id"] == "3874802c-d7fb-43e3-aeed-d4413fe444b2"
    assert parsed["host"] == "94.130.68.139"
    assert parsed["port"] == 2222
    assert parsed["network"] == "tcp"
    assert parsed["security"] == "none"
    assert parsed["name"] == "Germany #41294"


def test_parse_vless_reality_grpc():
    parsed = keys.parse_vless_key(
        "vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@x.example.com:443"
        "?security=reality&pbk=PUBKEY&sid=ab12&sni=cdn.example.com&fp=firefox"
        "&type=grpc&serviceName=SVC&flow=xtls-rprx-vision#r"
    )
    assert parsed["security"] == "reality"
    assert parsed["pbk"] == "PUBKEY"
    assert parsed["sni"] == "cdn.example.com"
    assert parsed["fp"] == "firefox"
    assert parsed["network"] == "grpc"
    assert parsed["serviceName"] == "SVC"
    assert parsed["flow"] == "xtls-rprx-vision"


def test_parse_vless_rejects():
    import pytest

    with pytest.raises(ValueError, match="UUID"):
        keys.parse_vless_key("vless://not-a-uuid@h.com:443")
    with pytest.raises(ValueError, match="pbk"):
        keys.parse_vless_key("vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@h.com:443?security=reality")
    with pytest.raises(ValueError, match="transport"):
        keys.parse_vless_key("vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@h.com:443?type=quic")


def test_vless_outbound_structure():
    server = keys.parse_vless_key(
        "vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@x.example.com:443"
        "?security=reality&pbk=PUBKEY&sid=ab12&type=grpc&serviceName=SVC#r"
    )
    out = keys._vless_outbound(server)
    vnext = out["settings"]["vnext"][0]
    assert vnext["address"] == "x.example.com" and vnext["port"] == 443
    assert vnext["users"][0]["id"] == "3874802c-d7fb-43e3-aeed-d4413fe444b2"
    assert out["streamSettings"]["security"] == "reality"
    assert out["streamSettings"]["realitySettings"]["publicKey"] == "PUBKEY"
    assert out["streamSettings"]["realitySettings"]["shortId"] == "ab12"
    assert out["streamSettings"]["grpcSettings"]["serviceName"] == "SVC"


def test_parse_key_dispatch():
    assert keys.parse_key(ss_url())["kind"] == "ss"
    assert (
        keys.parse_key("vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@h.com:1")["kind"] == "vless"
    )
    import pytest

    with pytest.raises(ValueError, match="scheme"):
        keys.parse_key("trojan://x@h:1")


def test_parse_sip002_standard_b64_alphabet_and_padding():
    # standard (non-urlsafe) base64 with padding must decode too
    userinfo = base64.b64encode(b"chacha20-poly1305:pass").decode()  # has +/= maybe
    url = f"ss://{userinfo}@vpn.example.org:443"
    parsed = keys.parse_ss_key(url)
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
    parsed = keys.parse_ss_key(f"ss://{payload}#old")
    assert parsed["host"] == "legacy.example.com"
    assert parsed["port"] == 9999
    assert parsed["method"] == "aes-128-gcm"
    assert parsed["name"] == "old"


def test_parse_ipv6_host():
    parsed = keys.parse_ss_key(ss_url(host="[2001:db8::1]", port=999))
    assert parsed["host"] == "2001:db8::1"
    assert parsed["port"] == 999


def test_parse_rejects_plugin():
    url = ss_url() + "?plugin=v2ray-plugin"
    with pytest.raises(ValueError, match="plugin"):
        keys.parse_ss_key(url)


def test_parse_rejects_sdk_prefix():
    url = ss_url() + "?prefix=POST%20"
    with pytest.raises(ValueError, match="prefix"):
        keys.parse_ss_key(url)


def test_parse_rejects_unknown_method():
    with pytest.raises(ValueError, match="method"):
        keys.parse_ss_key(ss_url(method="camellia-256-cfb"))


def test_parse_rejects_garbled():
    with pytest.raises(ValueError):
        keys.parse_ss_key("ss://not-a-key")
    with pytest.raises(ValueError):
        keys.parse_ss_key("ss://YWVzLTI1Ni1nY206c2VjcmV0@host:notaport")
    with pytest.raises(ValueError):
        keys.parse_ss_key("https://example.com")


# ── store ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(keys, "STORE", tmp_path / "keys.json")
    return tmp_path / "keys.json"


def test_add_server_roundtrip_and_mode(store):
    assert keys.add_server(keys.parse_ss_key(ss_url(tag="one"))).success
    servers = keys._load_servers()
    assert len(servers) == 1
    assert servers[0]["name"] == "one"
    import stat

    assert stat.S_IMODE(store.stat().st_mode) == 0o600  # passwords inside


def test_add_server_dedupes_identical_keys(store):
    key = ss_url(tag="a")
    assert keys.add_server(keys.parse_ss_key(key)).success
    dup = keys.add_server(keys.parse_ss_key(key))
    assert not dup.success
    assert "Already" in dup.message
    assert len(keys._load_servers()) == 1


def test_add_server_disambiguates_same_name(store):
    assert keys.add_server(keys.parse_ss_key(ss_url(host="a.com", tag="x"))).success
    second = keys.add_server(keys.parse_ss_key(ss_url(host="b.com", tag="x")))
    assert second.success
    names = [s["name"] for s in keys._load_servers()]
    assert names == ["x", "x (2)"]


def test_find_server_exact_and_unique_substring(store):
    keys.add_server(keys.parse_ss_key(ss_url(host="a.com", tag="alpha")))
    keys.add_server(keys.parse_ss_key(ss_url(host="b.com", tag="beta")))
    assert keys._find_server("beta")["host"] == "b.com"
    assert keys._find_server("alp")["host"] == "a.com"  # unique substring
    assert keys._find_server("a") is None  # ambiguous: alpha / bet[a]


# ── provider ──────────────────────────────────────────────────────────────────


def test_connections_marks_active_from_keeper_state(store, monkeypatch):
    keys.add_server(keys.parse_ss_key(ss_url(tag="s1")))
    keys.add_server(keys.parse_ss_key(ss_url(host="b.com", tag="s2")))
    monkeypatch.setattr(keys, "_daemon_running_processes", lambda: ["xray-keys-ss"])
    monkeypatch.setattr(
        keys, "_read_keeper_state", lambda path: {"status": "connected", "server": "s1"}
    )
    conns = keys.KeysProvider("ss").connections()
    assert [(c.name, c.active, c.interface) for c in conns] == [
        ("s1", True, "keys-ss-tun0"),
        ("s2", False, None),
    ]


def test_connections_empty_without_servers(store):
    assert keys.KeysProvider("ss").connections() == []


def test_ping_targets(store):
    keys.add_server(keys.parse_ss_key(ss_url(host="a.com", tag="x")))
    assert keys.KeysProvider("ss").ping_targets() == [("x", "a.com", 8388)]


def test_import_config_reads_key_from_file(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(f"Вот ключ:\n{ss_url(tag='from-file')}\n")
    result = keys.KeysProvider("ss").import_config(str(key_file))
    assert result.success
    assert keys._load_servers()[0]["name"] == "from-file"


def test_import_config_accepts_pasted_key(store):
    """The walker input may be the key itself, not a file path."""
    result = keys.KeysProvider("vless").import_config(
        "vless://3874802c-d7fb-43e3-aeed-d4413fe444b2@example.com:443#pasted"
    )
    assert result.success
    assert keys._load_servers()[0]["kind"] == "vless"
    assert keys._load_servers()[0]["name"] == "pasted"


def test_import_config_rejects_keyless_file(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text("no keys here")
    result = keys.KeysProvider("ss").import_config(str(key_file))
    assert not result.success


def test_import_config_surfaces_parser_reason(store, tmp_path):
    key_file = tmp_path / "key.txt"
    key_file.write_text(ss_url() + "?plugin=obfs-local")
    result = keys.KeysProvider("ss").import_config(str(key_file))
    assert not result.success
    assert "plugin" in result.message
