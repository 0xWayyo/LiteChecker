"""Updater entrypoints remain inert without configuration and reject unsafe selectors."""

import json
from pathlib import Path
import pytest


def test_status_without_channel_does_not_construct_platform_adapter(tmp_path, monkeypatch, capsys):
    from litechecker import update_service
    def forbidden(*args, **kwargs):
        raise AssertionError("OS adapter must remain unused")
    monkeypatch.setattr(update_service, "platform_adapter", forbidden)
    assert update_service.main(["status", "--root", str(tmp_path)]) == 0
    assert "unconfigured" in capsys.readouterr().out


def test_unconfigured_check_does_not_construct_platform_adapter(tmp_path, monkeypatch, capsys):
    from litechecker import update_service
    monkeypatch.setattr(update_service, "platform_adapter", lambda *_: pytest.fail("no configured channel"))
    assert update_service.main(["check", "--root", str(tmp_path)]) == 0
    assert "unconfigured" in capsys.readouterr().out


def test_stable_launcher_rejects_state_path_traversal_before_exec(tmp_path):
    from litechecker.update_launcher import select_release, LauncherError
    updates = tmp_path / ".updates"
    updates.mkdir()
    (updates / "install.json").write_text(json.dumps({"active": "../../outside"}))
    with pytest.raises(LauncherError):
        select_release(tmp_path)


def test_stable_launcher_falls_back_only_to_baseline_when_no_active_state(tmp_path):
    from litechecker.update_launcher import select_release
    assert select_release(tmp_path) == tmp_path


def test_stable_launcher_rejects_managed_directory_symlink(tmp_path):
    from litechecker.update_launcher import select_release, LauncherError
    updates = tmp_path / ".updates"
    (updates / "releases").mkdir(parents=True)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (updates / "releases/1.2.3").symlink_to(target, target_is_directory=True)
    (updates / "install.json").write_text(json.dumps({"active": "1.2.3"}))
    with pytest.raises(LauncherError):
        select_release(tmp_path)


def test_stable_launcher_requires_managed_marker_before_selecting_version(tmp_path):
    from litechecker.update_launcher import select_release
    updates = tmp_path / ".updates"
    release = updates / "releases/1.2.3"
    release.mkdir(parents=True)
    state = updates / "install.json"
    state.write_text(json.dumps({"active": "1.2.3"}))
    state.chmod(0o600)
    assert select_release(tmp_path) == tmp_path
    marker = release / ".litechecker-update-owned"
    marker.write_text("litechecker-updater-v1\n")
    marker.chmod(0o600)
    (release / ".artifact.sha256").write_text("a" * 64 + "\n")
    assert select_release(tmp_path) == release


def test_disabled_check_reaches_core_to_recover_pending_transaction(tmp_path, monkeypatch, capsys):
    from litechecker import update_service, updater
    updates = tmp_path / ".updates"
    updates.mkdir()
    (updates / "channel.json").write_text("{}")
    monkeypatch.setattr(updater, "update_status", lambda _: {"status": "disabled"})
    monkeypatch.setattr(update_service, "platform_adapter", lambda _: object())
    async def recover(root, adapter, *, force=False):
        return {"status": "rolled-back", "error": "interrupted-update-recovered"}
    async def no_images(root):
        return 0
    monkeypatch.setattr(updater, "check_for_update", recover)
    monkeypatch.setattr(update_service, "cleanup_platform_images", no_images)
    assert update_service.main(["check", "--root", str(tmp_path)]) == 1
    assert "rolled-back" in capsys.readouterr().out


def test_stop_launcher_uses_baseline_even_when_active_state_is_corrupt(tmp_path, monkeypatch):
    from litechecker import update_launcher
    runtime = tmp_path / ".native-direct/venv/bin/python"
    runtime.parent.mkdir(parents=True)
    runtime.write_text("python")
    runtime.chmod(0o700)
    module = tmp_path / "src/litechecker/update_service.py"
    module.parent.mkdir(parents=True)
    module.write_text("fixture")
    updates = tmp_path / ".updates"
    updates.mkdir()
    (updates / "install.json").write_text("not JSON")
    monkeypatch.setattr(update_launcher.sys, "platform", "darwin")
    executed = []
    def capture(path, args, env):
        executed.append((path, args, env))
        raise SystemExit(0)
    monkeypatch.setattr(update_launcher.os, "execve", capture)
    with pytest.raises(SystemExit) as raised:
        update_launcher.main(["--root", str(tmp_path), "stop"])
    assert raised.value.code == 0
    assert executed[0][0] == str(runtime)
    assert "stop" in executed[0][1]
