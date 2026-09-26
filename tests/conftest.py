import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Keep tests hermetic: redirect the log away from the real
# ~/.local/state/vpn-manager/vpn-manager.log before any test module
# (killswitch, happmeta, ...) imports logutil and binds LOG_PATH.
import tempfile

import pytest

import ipv6guard
import logutil


def pytest_runtest_setup(item):
    tmp = Path(tempfile.mkdtemp(prefix="vpn-manager-test-log-"))
    logutil.LOG_PATH = tmp / "vpn-manager.log"


@pytest.fixture(autouse=True)
def _no_real_sysctl(monkeypatch):
    """Safety net for every test, not just ipv6guard's own: once `make
    install` adds the sysctl sudoers rule, a test path that calls
    guarded_connect/guarded_disconnect without mocking ipv6guard could
    otherwise flip real host IPv6 state. test_ipv6guard.py re-patches
    subprocess.run itself per case, which simply layers on top of this."""

    class _Result:
        returncode = 0
        stdout = "0\n"
        stderr = ""

    monkeypatch.setattr(ipv6guard.subprocess, "run", lambda *a, **k: _Result())
