import json
import os
import stat
from pathlib import Path

import pytest

import fsutil


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


def test_writes_json_with_0600(tmp_path):
    target = tmp_path / "sub" / "state.json"
    fsutil.write_json_atomic(target, {"a": "б"}, ensure_ascii=False)
    assert json.loads(target.read_text()) == {"a": "б"}
    assert _mode(target) == 0o600


def test_temp_file_is_private_before_rename(tmp_path, monkeypatch):
    # The whole point: secrets never sit on disk with umask perms, not even
    # between the write and a later chmod. Inspect the temp file right at
    # the moment it gets renamed into place.
    seen = {}
    real_replace = os.replace

    def spy_replace(src, dst):
        seen["mode"] = _mode(src)
        seen["content"] = Path(src).read_text()
        real_replace(src, dst)

    monkeypatch.setattr(fsutil.os, "replace", spy_replace)
    old_umask = os.umask(0)  # worst case: umask would grant 0666
    try:
        fsutil.write_json_atomic(tmp_path / "config.json", {"api_key": "secret"})
    finally:
        os.umask(old_umask)
    assert seen["mode"] == 0o600
    assert json.loads(seen["content"]) == {"api_key": "secret"}


def test_replacing_a_world_readable_file_tightens_it(tmp_path):
    target = tmp_path / "keys.json"
    target.write_text("[]")
    target.chmod(0o644)
    fsutil.write_json_atomic(target, [{"host": "x"}])
    assert _mode(target) == 0o600


def test_custom_mode(tmp_path):
    target = tmp_path / "public.json"
    fsutil.write_json_atomic(target, {}, mode=0o644)
    assert _mode(target) == 0o644


def test_failed_serialization_keeps_old_file_and_leaves_no_temp(tmp_path):
    target = tmp_path / "state.json"
    target.write_text('{"old": true}')
    with pytest.raises(TypeError):
        fsutil.write_json_atomic(target, {"bad": object()})
    assert json.loads(target.read_text()) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]
