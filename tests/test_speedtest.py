import pytest

import speedtest


class _Resp:
    """Serves `n_bytes` in CHUNK-sized reads, then b"" (EOF)."""

    def __init__(self, n_bytes):
        self._left = n_bytes

    def read(self, size=-1):
        take = self._left if size < 0 else min(size, self._left)
        self._left -= take
        return b"x" * take

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _clock(monkeypatch, step):
    """perf_counter that advances `step` seconds per call."""
    t = [100.0]

    def tick():
        t[0] += step
        return t[0]

    monkeypatch.setattr(speedtest.time, "perf_counter", tick)


def test_measure_reports_mbit_per_second(monkeypatch):
    monkeypatch.setattr(speedtest.urllib.request, "urlopen", lambda req, timeout: _Resp(10_000_000))
    _clock(monkeypatch, 0.01)
    mbps = speedtest.measure("http://x", duration=100).mbps
    reads = -(-10_000_000 // speedtest.CHUNK)  # chunks with data, + one EOF read
    assert mbps == pytest.approx(10_000_000 * 8 / 1_000_000 / ((reads + 1) * 0.01))


def test_measure_stops_after_duration(monkeypatch):
    resp = _Resp(10**12)  # effectively endless
    monkeypatch.setattr(speedtest.urllib.request, "urlopen", lambda req, timeout: resp)
    _clock(monkeypatch, 1.0)
    assert speedtest.measure("http://x", duration=3).mbps is not None
    assert resp._left == 10**12 - 3 * speedtest.CHUNK


def test_measure_sends_browser_user_agent(monkeypatch):
    seen = []
    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda req, timeout: seen.append(req) or _Resp(1)
    )
    _clock(monkeypatch, 1.0)
    speedtest.measure("http://x")
    assert seen[0].get_header("User-agent") == "Mozilla/5.0"


def test_measure_reports_error_and_logs_on_network_failure(monkeypatch):
    logged = []
    monkeypatch.setattr(speedtest.logutil, "log", logged.append)

    def boom(req, timeout):
        raise OSError("no route")

    monkeypatch.setattr(speedtest.urllib.request, "urlopen", boom)
    m = speedtest.measure("http://x")
    assert m.mbps is None
    assert "no route" in m.error
    assert "no route" in logged[0]


def test_measure_reports_error_on_empty_body(monkeypatch):
    monkeypatch.setattr(speedtest.logutil, "log", lambda m: None)
    monkeypatch.setattr(speedtest.urllib.request, "urlopen", lambda req, timeout: _Resp(0))
    _clock(monkeypatch, 1.0)
    assert speedtest.measure("http://x").error


def test_measure_reports_error_on_incomplete_read(monkeypatch):
    monkeypatch.setattr(speedtest.logutil, "log", lambda m: None)

    class _IncompleteResp(_Resp):
        def read(self, size=-1):
            raise speedtest.http.client.IncompleteRead(partial=b"", expected=10_000_000)

    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda req, timeout: _IncompleteResp(0)
    )
    _clock(monkeypatch, 1.0)
    assert speedtest.measure("http://x").error


def test_is_valid_url():
    assert speedtest.is_valid_url("http://10.0.0.5/f.bin")
    assert speedtest.is_valid_url("https://example.com/x")
    assert not speedtest.is_valid_url("file:///etc/passwd")
    assert not speedtest.is_valid_url("https://")


def test_measure_error_is_truncated_for_the_results_window(monkeypatch):
    monkeypatch.setattr(speedtest.logutil, "log", lambda m: None)

    def boom(req, timeout):
        raise OSError("x" * 500)

    monkeypatch.setattr(speedtest.urllib.request, "urlopen", boom)
    assert len(speedtest.measure("http://x").error) == speedtest.ERROR_MAXLEN
