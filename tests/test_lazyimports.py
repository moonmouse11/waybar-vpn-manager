"""--status runs every 3 s: importing vpn_manager must not load the network
stack (urllib.request → http.client → ssl, email) or the Tools-only modules.
A fresh interpreter, since this test session has long since imported them."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import lazyimports

SRC = Path(__file__).resolve().parent.parent / "src"
# captured at import, before conftest's autouse fixtures fake subprocess.run
# and set subprocess.Popen to None (see test_xray_compat.py)
_REAL_RUN = subprocess.run
_REAL_POPEN = subprocess.Popen


@pytest.fixture(autouse=True)
def _real_subprocess(monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", _REAL_POPEN)


HEAVY = ["urllib.request", "http.client", "ssl", "email.parser", "concurrent.futures", "statistics"]

PROBE = f"""
import json, sys
sys.path.insert(0, {str(SRC)!r})
import vpn_manager
print(json.dumps([m for m in {HEAVY!r} if type(sys.modules.get(m)).__name__ == "module"]))
"""


def test_importing_vpn_manager_leaves_the_network_stack_unloaded():
    out = _REAL_RUN([sys.executable, "-c", PROBE], capture_output=True, text=True, check=True)
    assert json.loads(out.stdout) == []


def test_a_lazy_module_loads_on_first_use():
    probe = f"""
import sys
sys.path.insert(0, {str(SRC)!r})
import lazyimports, urllib
assert type(sys.modules["http.client"]).__name__ != "module"
urllib.request.Request("https://example.com")
assert type(sys.modules["urllib.request"]).__name__ == "module"
print("ok")
"""
    out = _REAL_RUN([sys.executable, "-c", probe], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "ok"


def test_lazy_returns_an_already_loaded_module_as_is():
    assert lazyimports.lazy("json") is json
