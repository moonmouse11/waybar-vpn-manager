import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Keep tests hermetic: redirect the log away from the real
# ~/.local/state/vpn-manager/vpn-manager.log before any test module
# (killswitch, happmeta, ...) imports logutil and binds LOG_PATH.
import tempfile

import logutil


def pytest_runtest_setup(item):
    tmp = Path(tempfile.mkdtemp(prefix="vpn-manager-test-log-"))
    logutil.LOG_PATH = tmp / "vpn-manager.log"
