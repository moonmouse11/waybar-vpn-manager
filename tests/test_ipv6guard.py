import ipv6guard


class Result:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_is_disabled_reads_unprivileged(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Result(stdout="1\n")

    monkeypatch.setattr(ipv6guard.subprocess, "run", fake_run)
    assert ipv6guard.is_disabled()
    assert calls == [["sysctl", "-n", "net.ipv6.conf.all.disable_ipv6"]]


def test_is_disabled_false_when_zero_or_error(monkeypatch):
    monkeypatch.setattr(ipv6guard.subprocess, "run", lambda *a, **k: Result(stdout="0\n"))
    assert not ipv6guard.is_disabled()
    monkeypatch.setattr(ipv6guard.subprocess, "run", lambda *a, **k: Result(returncode=1))
    assert not ipv6guard.is_disabled()


def test_disable_is_noop_when_already_disabled(monkeypatch):
    monkeypatch.setattr(ipv6guard, "is_disabled", lambda: True)
    ran = []
    monkeypatch.setattr(ipv6guard.subprocess, "run", lambda *a, **k: ran.append(a) or Result())
    result = ipv6guard.disable()
    assert result.success
    assert ran == []


def test_disable_writes_both_keys(monkeypatch):
    monkeypatch.setattr(ipv6guard, "is_disabled", lambda: False)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Result()

    monkeypatch.setattr(ipv6guard.subprocess, "run", fake_run)
    result = ipv6guard.disable()
    assert result.success
    assert calls == [
        ["sudo", "-n", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
        ["sudo", "-n", "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=1"],
    ]


def test_enable_is_noop_when_already_enabled(monkeypatch):
    monkeypatch.setattr(ipv6guard, "is_disabled", lambda: False)
    ran = []
    monkeypatch.setattr(ipv6guard.subprocess, "run", lambda *a, **k: ran.append(a) or Result())
    result = ipv6guard.enable()
    assert result.success
    assert ran == []


def test_enable_writes_both_keys(monkeypatch):
    monkeypatch.setattr(ipv6guard, "is_disabled", lambda: True)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Result()

    monkeypatch.setattr(ipv6guard.subprocess, "run", fake_run)
    result = ipv6guard.enable()
    assert result.success
    assert calls == [
        ["sudo", "-n", "sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0"],
        ["sudo", "-n", "sysctl", "-w", "net.ipv6.conf.default.disable_ipv6=0"],
    ]


def test_set_reports_failure_and_stops_on_first_error(monkeypatch):
    monkeypatch.setattr(ipv6guard, "is_disabled", lambda: False)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return Result(returncode=1, stderr="a password is required")

    monkeypatch.setattr(ipv6guard.subprocess, "run", fake_run)
    result = ipv6guard.disable()
    assert not result.success
    assert "make install" in result.message
    assert len(calls) == 1  # must not try the second key after the first fails
