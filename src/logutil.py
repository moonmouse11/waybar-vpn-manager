"""Append-only debug log at ~/.local/state/vpn-manager/vpn-manager.log.

Errors that would otherwise disappear into notify-send bubbles are written
here. Log is truncated from the front when it grows past MAX_BYTES.
"""

import time
from pathlib import Path

LOG_PATH = Path.home() / ".local/state/vpn-manager/vpn-manager.log"
MAX_BYTES = 256 * 1024


def log(message: str) -> None:
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > MAX_BYTES:
            LOG_PATH.write_text(LOG_PATH.read_text(errors="replace")[-MAX_BYTES // 2 :])
        with LOG_PATH.open("a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}\n")
    except OSError:
        pass
