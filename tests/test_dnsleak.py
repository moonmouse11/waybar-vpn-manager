import dnsleak


def test_run_happy_path(monkeypatch):
    monkeypatch.setattr(dnsleak, "_get_test_id", lambda: "abc123")
    probed = []
    monkeypatch.setattr(dnsleak, "_send_probes", lambda test_id: probed.append(test_id))
    entries = [
        {"type": "ip", "ip": "1.2.3.4", "country": "de"},
        {
            "type": "dns",
            "ip": "9.9.9.9",
            "country": "de",
            "country_name": "Germany",
            "asn": "AS1 Quad9",
            "org": "Quad9",
        },
        {"type": "conclusion", "ip": "No DNS leaks found."},
    ]
    monkeypatch.setattr(dnsleak, "_fetch_results", lambda test_id: entries)

    result = dnsleak.run()

    assert probed == ["abc123"]
    assert result["ip"] == "1.2.3.4"
    assert result["ip_country"] == "DE"
    assert result["dns_servers"] == [entries[1]]
    assert result["conclusion"] == "No DNS leaks found."


def test_run_returns_none_on_empty_test_id(monkeypatch):
    monkeypatch.setattr(dnsleak, "_get_test_id", lambda: "")

    def boom(test_id):
        raise AssertionError("must not probe without a test id")

    monkeypatch.setattr(dnsleak, "_send_probes", boom)
    assert dnsleak.run() is None


def test_run_returns_none_on_network_failure(monkeypatch):
    def boom():
        raise OSError("no route")

    monkeypatch.setattr(dnsleak, "_get_test_id", boom)
    assert dnsleak.run() is None


def test_run_returns_none_on_malformed_results(monkeypatch):
    monkeypatch.setattr(dnsleak, "_get_test_id", lambda: "abc123")
    monkeypatch.setattr(dnsleak, "_send_probes", lambda test_id: None)
    monkeypatch.setattr(dnsleak, "_fetch_results", lambda test_id: {"not": "a list"})
    assert dnsleak.run() is None


def test_run_no_dns_servers_still_returns_ip_and_conclusion(monkeypatch):
    monkeypatch.setattr(dnsleak, "_get_test_id", lambda: "abc123")
    monkeypatch.setattr(dnsleak, "_send_probes", lambda test_id: None)
    entries = [{"type": "ip", "ip": "1.2.3.4"}, {"type": "conclusion", "ip": "No leak."}]
    monkeypatch.setattr(dnsleak, "_fetch_results", lambda test_id: entries)

    result = dnsleak.run()
    assert result == {
        "ip": "1.2.3.4",
        "ip_country": "",
        "ip_asn": None,
        "dns_servers": [],
        "conclusion": "No leak.",
    }


def test_probe_swallows_resolution_failure(monkeypatch):
    monkeypatch.setattr(
        dnsleak.socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("nope"))
    )
    dnsleak._probe("1.deadbeef.bash.ws")  # must not raise


def test_send_probes_covers_every_host(monkeypatch):
    # threads complete in whatever order the scheduler picks — compare as a
    # set, not a list; only full coverage of every host matters here.
    monkeypatch.setattr(dnsleak, "PROBE_COUNT", 5)
    seen = []
    monkeypatch.setattr(dnsleak, "_probe", lambda host: seen.append(host))
    dnsleak._send_probes("tid")
    assert set(seen) == {f"{i}.tid.bash.ws" for i in range(1, 6)}


def test_run_parses_exit_ip_asn(monkeypatch):
    monkeypatch.setattr(dnsleak, "_get_test_id", lambda: "abc123")
    monkeypatch.setattr(dnsleak, "_send_probes", lambda test_id: None)
    entries = [{"type": "ip", "ip": "1.2.3.4", "country": "de", "asn": "AS24940 Hetzner"}]
    monkeypatch.setattr(dnsleak, "_fetch_results", lambda test_id: entries)
    assert dnsleak.run()["ip_asn"] == 24940


def test_asn_number_parsing():
    assert dnsleak.asn_number("AS13335 CloudFlare Inc") == 13335
    assert dnsleak.asn_number("as42") == 42
    assert dnsleak.asn_number("CloudFlare") is None
    assert dnsleak.asn_number(None) is None


def test_server_tags_public_resolver_trusted_even_abroad():
    server = {"ip": "172.69.50.15", "country": "nl", "asn": "AS13335 CloudFlare Inc"}
    assert dnsleak.server_tags(server, ip_country="DE", ip_asn=24940) == []


def test_server_tags_vpn_providers_own_resolver_trusted():
    server = {"ip": "5.6.7.8", "country": "fi", "asn": "AS24940 Hetzner"}
    assert dnsleak.server_tags(server, ip_country="DE", ip_asn=24940) == []


def test_server_tags_foreign_asn_same_country():
    server = {"ip": "5.6.7.8", "country": "de", "asn": "AS3320 Deutsche Telekom"}
    assert dnsleak.server_tags(server, ip_country="DE", ip_asn=24940) == ["ASN"]


def test_server_tags_foreign_asn_other_country():
    server = {"ip": "5.6.7.8", "country": "ru", "asn": "AS12389 Rostelecom"}
    assert dnsleak.server_tags(server, ip_country="DE", ip_asn=24940) == ["ASN", "GEO"]


def test_server_tags_unknown_exit_asn_never_claims_asn_mismatch():
    # without the exit IP's ASN the same-provider rule can't be evaluated —
    # stay quiet on ASN rather than flag every non-public resolver
    server = {"ip": "5.6.7.8", "country": "ru", "asn": "AS12389 Rostelecom"}
    assert dnsleak.server_tags(server, ip_country="DE", ip_asn=None) == ["GEO"]


def test_server_tags_nothing_known_is_quiet():
    assert dnsleak.server_tags({"ip": "5.6.7.8"}, ip_country="", ip_asn=None) == []
