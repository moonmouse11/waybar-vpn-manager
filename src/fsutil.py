"""Atomic, permission-safe JSON writes for state/cache files.

Every file written here is created with its final mode from the start —
the old `write_text()` + `chmod(0o600)` pattern left a window where a file
holding keys, subscription tokens or API keys existed with umask perms
(usually 0644, readable by other local users). Writing to a unique temp
file and `os.replace()`-ing it in also means a concurrent reader (the
3-second `--status` tick) never sees a half-written file, and two writers
racing on the same target can't interleave into one shared `.tmp`.
"""

import contextlib
import json
import os
import tempfile
from pathlib import Path


def write_json_atomic(path: Path, data, *, mode: int = 0o600, **dump_kw) -> None:
    """Serialize `data` as JSON into `path` atomically, created with `mode`.

    Raises OSError (and json's TypeError/ValueError) like a plain write would;
    callers keep their own best-effort `except OSError` handling.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp creates the file O_EXCL with mode 0600 — never wider, even briefly.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            if mode != 0o600:
                os.fchmod(f.fileno(), mode)
            json.dump(data, f, **dump_kw)
        os.replace(tmp_name, path)
    except BaseException:
        with contextlib.suppress(OSError):  # keep the original exception
            os.unlink(tmp_name)
        raise
