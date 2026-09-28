import crtname


class _Resp:
    def __init__(self, text):
        self._payload = text.encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_search_happy_path(monkeypatch):
    monkeypatch.setattr(
        crtname.urllib.request,
        "urlopen",
        lambda url, timeout=8: _Resp("example.com\nwww.example.com\n"),
    )
    assert crtname.search("example.com") == ["example.com", "www.example.com"]


def test_search_empty_result(monkeypatch):
    monkeypatch.setattr(crtname.urllib.request, "urlopen", lambda url, timeout=8: _Resp(""))
    assert crtname.search("nosuchdomain.example") == []


def test_search_strips_blank_lines(monkeypatch):
    monkeypatch.setattr(
        crtname.urllib.request,
        "urlopen",
        lambda url, timeout=8: _Resp("a.example.com\n\n  \nb.example.com\n"),
    )
    assert crtname.search("example.com") == ["a.example.com", "b.example.com"]


def test_search_returns_none_on_network_failure(monkeypatch):
    def boom(url, timeout=8):
        raise OSError("no route")

    monkeypatch.setattr(crtname.urllib.request, "urlopen", boom)
    assert crtname.search("example.com") is None


def test_search_returns_none_on_bad_encoding(monkeypatch):
    class _Bad:
        def read(self):
            return b"\xff\xfe not valid utf-8"

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(crtname.urllib.request, "urlopen", lambda url, timeout=8: _Bad())
    assert crtname.search("example.com") is None


def test_search_url_encodes_the_domain(monkeypatch):
    captured = {}

    def fake_urlopen(url, timeout=8):
        captured["url"] = url
        return _Resp("")

    monkeypatch.setattr(crtname.urllib.request, "urlopen", fake_urlopen)
    crtname.search("exa mple.com")
    assert "exa+mple.com" in captured["url"] or "exa%20mple.com" in captured["url"]


def test_search_returns_none_on_incomplete_read(monkeypatch):
    class _IncompleteResp:
        def read(self):
            raise crtname.http.client.IncompleteRead(partial=b"", expected=100)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(crtname.urllib.request, "urlopen", lambda url, timeout=8: _IncompleteResp())
    assert crtname.search("example.com") is None
