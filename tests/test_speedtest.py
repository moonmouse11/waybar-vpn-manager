import speedtest


class _Resp:
    def __init__(self, n_bytes):
        self._payload = b"x" * n_bytes

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_measure_happy_path(monkeypatch):
    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda url, timeout=20: _Resp(10_000_000)
    )
    times = iter([100.0, 105.0])  # 5 s elapsed
    monkeypatch.setattr(speedtest.time, "perf_counter", lambda: next(times))
    mbps = speedtest.measure()
    assert mbps == 2.0  # 10 MB / 5 s


def test_measure_returns_none_on_network_failure(monkeypatch):
    def boom(url, timeout=20):
        raise OSError("no route")

    monkeypatch.setattr(speedtest.urllib.request, "urlopen", boom)
    assert speedtest.measure() is None


def test_measure_returns_none_on_zero_elapsed_time(monkeypatch):
    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda url, timeout=20: _Resp(1000)
    )
    monkeypatch.setattr(speedtest.time, "perf_counter", lambda: 100.0)  # same value twice
    assert speedtest.measure() is None


def test_measure_returns_none_on_incomplete_read(monkeypatch):
    class _IncompleteResp:
        def read(self):
            raise speedtest.http.client.IncompleteRead(partial=b"", expected=10_000_000)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        speedtest.urllib.request, "urlopen", lambda url, timeout=20: _IncompleteResp()
    )
    monkeypatch.setattr(speedtest.time, "perf_counter", lambda: 100.0)
    assert speedtest.measure() is None
