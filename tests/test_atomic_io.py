"""Atomic replacement retries only the bounded, verified Windows boundary."""

import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from litechecker import state, update_store, windows_security, windows_trial


def _windows_error(code):
    error = PermissionError(13, "controlled Windows replacement failure")
    error.winerror = code
    return error


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(windows_security, "is_windows", lambda: True)
    monkeypatch.setattr(windows_security, "_read_directory_acl", lambda path: (
        "S-1-5-21-123", "S-1-5-21-123", True,
        ((0, 0x1F01FF, "S-1-5-21-123"), (0, 0x1F01FF, "S-1-5-18"),
         (0, 0x1F01FF, "S-1-5-32-544")),
    ))


def _writer(kind, root):
    if kind == "state":
        path = root / "control.json"
        write = lambda value: state._atomic_write_json(path, {"phase": value})
    elif kind == "updater":
        store = update_store.UpdateStore(root)
        path = store.install_path
        write = lambda value: store.write_install({**update_store.default_install_state(), "status": value})
    else:
        path = root / "last-report.txt"
        write = lambda value: windows_trial._save_text(root, value)
    return path, write


@pytest.mark.parametrize("kind", ["state", "updater", "report"])
def test_atomic_writers_recover_transient_windows_access_denied_without_changing_payload(tmp_path, monkeypatch, windows, kind):
    # This caught the real deny-delete reader's WinError 5: only replacement
    # fails once; serialization, tempfile ownership and cleanup remain real.
    path, write = _writer(kind, tmp_path)
    write("current")
    old = path.read_bytes()
    replace = os.replace
    attempts = []

    def blocked_once(source, destination):
        assert Path(destination) == path
        attempts.append(Path(source))
        if len(attempts) == 1:
            assert path.read_bytes() == old
            raise _windows_error(5)
        return replace(source, destination)

    monkeypatch.setattr(os, "replace", blocked_once)
    write("updated")
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert not attempts[0].exists()
    if kind == "report":
        assert path.read_bytes() == b"updated\n"
    elif kind == "state":
        assert json.loads(path.read_bytes()) == {"phase": "updated"}
    else:
        assert json.loads(path.read_bytes()) == {**update_store.default_install_state(), "status": "updated"}


def test_relative_state_destination_recovers_with_absolute_sibling_temp(tmp_path, monkeypatch, windows):
    monkeypatch.chdir(tmp_path)
    path = Path("control.json")
    state._atomic_write_json(path, {"phase": "current"})
    replace = os.replace
    attempts = []
    def blocked_once(source, destination):
        attempts.append((Path(source), Path(destination)))
        if len(attempts) == 1:
            raise _windows_error(5)
        return replace(source, destination)
    monkeypatch.setattr(os, "replace", blocked_once)
    state._atomic_write_json(path, {"phase": "updated"})
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert json.loads(path.read_bytes()) == {"phase": "updated"}
    assert not attempts[0][0].exists()


@pytest.fixture
def replacement(tmp_path, monkeypatch, windows):
    module = importlib.import_module("litechecker.atomic_io")
    source, target = tmp_path / "source.tmp", tmp_path / "target.json"
    source.write_bytes(b"complete-new")
    target.write_bytes(b"complete-old")
    clock = SimpleNamespace(now=0.0, sleeps=[])
    monkeypatch.setattr(module, "_monotonic", lambda: clock.now)
    def sleep(delay):
        clock.sleeps.append(delay)
        clock.now += delay
    monkeypatch.setattr(module, "_sleep", sleep)
    return module, source, target, clock


@pytest.mark.parametrize("code", [5, 32, 33])
def test_replace_retries_only_same_complete_file_on_recognized_windows_codes(replacement, monkeypatch, code):
    module, source, target, clock = replacement
    replace = os.replace
    attempts = []
    def transient(src, dst):
        attempts.append((Path(src), Path(dst)))
        if len(attempts) < 3:
            assert source.read_bytes() == b"complete-new"
            assert target.read_bytes() == b"complete-old"
            raise _windows_error(code)
        return replace(src, dst)
    monkeypatch.setattr(os, "replace", transient)
    module.atomic_replace(source, target)
    assert attempts == [(source, target)] * 3
    assert target.read_bytes() == b"complete-new" and not source.exists()
    assert len(clock.sleeps) == 2 and 0 < clock.now < 0.5


@pytest.mark.parametrize("code", [5, 32, 33])
def test_persistent_windows_error_stops_within_deadline_and_preserves_both_files(replacement, monkeypatch, code):
    module, source, target, clock = replacement
    error = _windows_error(code)
    attempts = []
    def blocked(src, dst):
        attempts.append((Path(src), Path(dst)))
        raise error
    monkeypatch.setattr(os, "replace", blocked)
    with pytest.raises(OSError) as caught:
        module.atomic_replace(source, target)
    assert caught.value is error
    assert 1 < len(attempts) <= 51
    assert 0 < clock.now <= 0.5
    assert all(0 < delay <= 0.01 for delay in clock.sleeps)
    assert source.read_bytes() == b"complete-new"
    assert target.read_bytes() == b"complete-old"


@pytest.mark.parametrize("windows_mode,code", [(True, 2), (True, 112), (True, None), (False, 5)])
def test_unrelated_errors_and_posix_fail_immediately(replacement, monkeypatch, windows_mode, code):
    module, source, target, clock = replacement
    monkeypatch.setattr(windows_security, "is_windows", lambda: windows_mode)
    error = _windows_error(code)
    attempts = []
    def failed(src, dst):
        attempts.append((src, dst))
        raise error
    monkeypatch.setattr(os, "replace", failed)
    with pytest.raises(OSError) as caught:
        module.atomic_replace(source, target)
    assert caught.value is error
    assert len(attempts) == 1 and not clock.sleeps
    assert target.read_bytes() == b"complete-old"


@pytest.mark.parametrize("unsafe", ["parent-acl", "source-acl", "target-acl", "target-reparse"])
def test_retry_rechecks_private_paths_and_never_replaces_after_security_changes(replacement, monkeypatch, unsafe):
    module, source, target, clock = replacement
    descriptor = windows_security._read_directory_acl
    reparse = windows_security._is_reparse_point
    error = _windows_error(5)
    attempts = []
    def failed(src, dst):
        attempts.append((src, dst))
        if unsafe == "target-reparse":
            monkeypatch.setattr(windows_security, "_is_reparse_point", lambda path: path == target or reparse(path))
        else:
            affected = {"parent-acl": target.parent, "source-acl": source, "target-acl": target}[unsafe]
            def changed(path):
                owner, current, present, entries = descriptor(path)
                if path == affected:
                    entries += ((0, 0x1F01FF, "S-1-1-0"),)
                return owner, current, present, entries
            monkeypatch.setattr(windows_security, "_read_directory_acl", changed)
        raise error
    monkeypatch.setattr(os, "replace", failed)
    with pytest.raises(OSError) as caught:
        module.atomic_replace(source, target)
    assert caught.value is error
    assert len(attempts) == 1
    assert target.read_bytes() == b"complete-old"


@pytest.mark.parametrize("kind", ["state", "updater", "report"])
def test_atomic_writer_permanent_failure_preserves_old_data_and_cleans_own_temp(tmp_path, monkeypatch, windows, kind):
    module = importlib.import_module("litechecker.atomic_io")
    clock = SimpleNamespace(now=0.0)
    monkeypatch.setattr(module, "_monotonic", lambda: clock.now)
    monkeypatch.setattr(module, "_sleep", lambda delay: setattr(clock, "now", clock.now + delay))
    path, write = _writer(kind, tmp_path)
    write("current")
    old = path.read_bytes()
    before = set(path.parent.iterdir())
    def blocked(src, dst):
        raise _windows_error(5)
    monkeypatch.setattr(os, "replace", blocked)
    with pytest.raises((OSError, state.StateError)):
        write("updated")
    assert path.read_bytes() == old
    assert set(path.parent.iterdir()) == before
    assert 0 < clock.now <= 0.5
