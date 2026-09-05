"""The macOS install handoff removes only a proven pristine public bundle."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess

import pytest


def _write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _bundle(tmp_path: Path, *, source_name: str = "extracted", root_name: str = "installed"):
    source = tmp_path / source_name
    root = tmp_path / root_name
    control = b"#!/bin/bash\nprintf '%s\\n' \"$0\" \"$#:$1\"\n"
    payload = {
        "INSTALL.command": b"#!/bin/bash\nexit 0\n",
        "scripts/control.sh": control,
        "src/litechecker/__init__.py": b'"""fixture"""\n',
        "\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt": "public instructions\n".encode(),
    }
    for name, data in payload.items():
        _write(source / name, data, 0o755 if name.endswith((".sh", ".command")) else 0o644)
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in payload.items()}
    _write(source / "CONTENTS.sha256.json", (json.dumps(manifest, ensure_ascii=False) + "\n").encode())

    for name in ("INSTALL.command", "scripts/control.sh"):
        _write(root / name, payload[name], 0o700)
    _write(root / "native-settings.json", b'{"LC_INTERVAL_SECONDS":"600"}\n', 0o600)
    _write(root / ".native-direct/venv/bin/python", b"#!/bin/bash\nexit 0\n", 0o700)
    _write(root / ".native-direct/xray", b"#!/bin/bash\nexit 0\n", 0o700)
    return source, root, manifest


def _finish(source: Path, root: Path) -> dict:
    from litechecker.install_handoff import finish_handoff

    return finish_handoff(source, root)


def _source_files(source: Path) -> set[str]:
    return {
        path.relative_to(source).as_posix()
        for path in source.rglob("*")
        if path.is_file() or path.is_symlink()
    }


def test_pristine_public_bundle_leaves_only_management_launcher(tmp_path):
    source, root, _ = _bundle(tmp_path)

    result = _finish(source, root)

    assert result["ok"] is True
    assert result["cleaned"] is True
    assert result["launcher_created"] is True
    assert _source_files(source) == {"LiteChecker.command"}
    assert os.access(source / "LiteChecker.command", os.X_OK)


@pytest.mark.parametrize("case", ["modified", "additional", "symlink", "empty-directory"])
def test_uncertain_source_refuses_cleanup_and_preserves_existing_files(tmp_path, case):
    source, root, _ = _bundle(tmp_path)
    if case == "modified":
        (source / "src/litechecker/__init__.py").write_text("changed after packaging\n")
    elif case == "additional":
        _write(source / "notes.txt", b"user file\n")
    elif case == "symlink":
        (source / "linked").symlink_to(tmp_path / "outside")
    else:
        (source / "unknown-empty").mkdir()
    before = _source_files(source)

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert before <= _source_files(source)
    assert (source / "LiteChecker.command").exists()
    assert result["reason"]


@pytest.mark.parametrize(
    "entry",
    ["../outside", "/absolute", "safe/../../outside", "safe\\outside", "a//b"],
)
def test_unsafe_manifest_path_refuses_without_touching_payload(tmp_path, entry):
    source, root, _ = _bundle(tmp_path)
    manifest_path = source / "CONTENTS.sha256.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[entry] = hashlib.sha256(b"x").hexdigest()
    manifest_path.write_text(json.dumps(manifest))
    before = _source_files(source)

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert before <= _source_files(source)
    assert not (tmp_path / "outside").exists()


def test_git_checkout_is_never_cleaned(tmp_path):
    source, root, _ = _bundle(tmp_path)
    _write(source / ".git/config", b"[core]\n")

    result = _finish(source, root)

    assert result["ok"] is False
    assert (source / ".git/config").read_bytes() == b"[core]\n"
    assert "git" in result["reason"].lower()


@pytest.mark.parametrize(
    "private_name",
    ["secrets/subscription_url", "state/native-direct/device.json", "native-settings.json", ".env.standalone"],
)
def test_private_manifest_is_refused_without_reading_or_removing_private_file(tmp_path, private_name):
    source, root, _ = _bundle(tmp_path)
    secret = b"plaintext-private-fixture"
    _write(source / private_name, secret, 0o600)
    manifest_path = source / "CONTENTS.sha256.json"
    manifest = json.loads(manifest_path.read_text())
    manifest[private_name] = hashlib.sha256(secret).hexdigest()
    manifest_path.write_text(json.dumps(manifest))

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert (source / private_name).read_bytes() == secret
    assert "private" in result["reason"].lower()


@pytest.mark.parametrize(
    "missing",
    [
        "scripts/control.sh",
        "INSTALL.command",
        "native-settings.json",
        ".native-direct/venv/bin/python",
        ".native-direct/xray",
    ],
)
def test_missing_installed_root_proof_refuses_even_launcher_creation(tmp_path, missing):
    source, root, _ = _bundle(tmp_path)
    (root / missing).unlink()

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert result["launcher_created"] is False
    assert not (source / "LiteChecker.command").exists()
    assert (source / "CONTENTS.sha256.json").exists()


def test_cleanup_never_changes_canonical_identity_outbox_settings_or_secrets(tmp_path):
    source, root, _ = _bundle(tmp_path)
    preserved = {
        "state/native-direct/device.json": b'{"agent_id":"device-preserved"}\n',
        "state/native-direct/outbox.jsonl": b'{"pending":true}\n',
        "native-settings.json": (root / "native-settings.json").read_bytes(),
        "secrets/subscription_url": b"https://subscription.invalid/private\n",
        ".updates/install.json": b'{"active":null}\n',
    }
    for name, data in preserved.items():
        _write(root / name, data, 0o600)

    result = _finish(source, root)

    assert result["ok"] is True
    for name, data in preserved.items():
        assert (root / name).read_bytes() == data


def test_existing_unrelated_launcher_is_not_overwritten_or_used_for_cleanup(tmp_path):
    source, root, _ = _bundle(tmp_path)
    unrelated = b"#!/bin/bash\necho unrelated\n"
    _write(source / "LiteChecker.command", unrelated, 0o700)

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["launcher_created"] is False
    assert (source / "LiteChecker.command").read_bytes() == unrelated
    assert (source / "CONTENTS.sha256.json").exists()


def test_launcher_preserves_unicode_and_spaces_as_one_exact_shell_argument(tmp_path):
    source, root, _ = _bundle(
        tmp_path,
        source_name="\u041f\u0430\u043a\u0435\u0442 LiteChecker (ready)",
        root_name="\u041a\u0430\u043d\u043e\u043d\u0438\u0447\u0435\u0441\u043a\u0438\u0439 LiteChecker $data",
    )

    result = _finish(source, root)
    launched = subprocess.run(
        [source / "LiteChecker.command"], capture_output=True, text=True, timeout=10, check=False
    )

    assert result["ok"] is True
    assert launched.returncode == 0, launched.stderr
    assert launched.stdout.splitlines() == [str(root / "scripts/control.sh"), "1:menu"]


def test_launcher_pins_custom_root_for_real_control_despite_wrong_environment(tmp_path):
    source, root, _ = _bundle(
        tmp_path, source_name="Архив LiteChecker", root_name="Custom LiteChecker root"
    )
    real_control = (Path(__file__).resolve().parents[1] / "scripts/control.sh").read_bytes()
    for path in (source / "scripts/control.sh", root / "scripts/control.sh"):
        path.write_bytes(real_control)
        path.chmod(0o700)
    manifest_path = source / "CONTENTS.sha256.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["scripts/control.sh"] = hashlib.sha256(real_control).hexdigest()
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False))

    calls = tmp_path / "calls"
    wrong = tmp_path / "wrong inherited root"
    fake_home = tmp_path / "wrong home"
    default = fake_home / "Library/Application Support/LiteChecker"
    for candidate, label in ((root, "canonical"), (wrong, "override"), (default, "home")):
        _write(candidate / "native-settings.json", b"{}\n", 0o600)
        _write(candidate / "secrets/telegram_bot_token", b"synthetic-test-token\n", 0o600)
        _write(candidate / "secrets/subscription_url", b"https://example.invalid/test\n", 0o600)
        _write(
            candidate / "run.sh",
            (
                "#!/bin/bash\n"
                f"printf '{label}:%s:%s\\n' \"$LITECHECKER_NATIVE_ROOT\" \"$*\" >> \"$CALLS\"\n"
                "test \"$1\" != status || printf 'state = running\\n'\n"
            ).encode(),
            0o700,
        )

    result = _finish(source, root)
    environment = {
        **os.environ,
        "HOME": str(fake_home),
        "LITECHECKER_NATIVE_ROOT": str(wrong),
        "CALLS": str(calls),
    }
    launched = subprocess.run(
        [source / "LiteChecker.command"],
        input="0\n",
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )

    assert result["ok"] is True
    assert launched.returncode == 0, launched.stderr
    assert calls.read_text().splitlines() == [f"canonical:{root}:status"]


@pytest.mark.parametrize("relation", ["root-inside-source", "source-inside-root"])
def test_nested_source_and_root_are_refused_without_cleanup(tmp_path, relation):
    source, root, _ = _bundle(tmp_path)
    if relation == "root-inside-source":
        nested = source / "installed"
        root.rename(nested)
        root = nested
    else:
        nested = root / "extracted"
        source.rename(nested)
        source = nested

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert (source / "CONTENTS.sha256.json").exists()


@pytest.mark.parametrize("changed", ["payload", "manifest"])
def test_change_after_validation_is_rechecked_before_that_file_is_unlinked(
    tmp_path, monkeypatch, changed
):
    source, root, _ = _bundle(tmp_path)
    from litechecker import install_handoff as module

    original_cleanup = module._cleanup
    target = source / ("INSTALL.command" if changed == "payload" else "CONTENTS.sha256.json")
    changed_bytes = b"user changed this after validation\n"

    def change_then_cleanup(*args, **kwargs):
        target.write_bytes(changed_bytes)
        return original_cleanup(*args, **kwargs)

    monkeypatch.setattr(module, "_cleanup", change_then_cleanup)

    result = module.finish_handoff(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert target.read_bytes() == changed_bytes
    assert (source / "LiteChecker.command").exists()
    assert result["partial_cleanup"] is (changed == "manifest")


def test_keyboard_interrupt_during_cleanup_returns_honest_partial_result(
    tmp_path, monkeypatch
):
    source, root, _ = _bundle(tmp_path)
    original_unlink = Path.unlink

    def interrupt_control(path, *args, **kwargs):
        if path == source / "scripts/control.sh":
            raise KeyboardInterrupt
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", interrupt_control)

    result = _finish(source, root)

    assert result["ok"] is False
    assert result["cleaned"] is False
    assert result["partial_cleanup"] is True
    assert not (source / "INSTALL.command").exists()
    assert (source / "scripts/control.sh").exists()
    assert (source / "LiteChecker.command").exists()
    assert "interrupt" in result["reason"].lower()


def test_cli_prints_concise_russian_refusal_without_raw_json_or_reason(tmp_path, capsys):
    source, root, _ = _bundle(tmp_path)
    _write(source / "unknown.txt", b"do not delete\n")
    from litechecker.install_handoff import main

    status = main(["--source", str(source), "--root", str(root)])
    captured = capsys.readouterr()
    output = captured.out + captured.err

    assert status != 0
    assert "Файлы установщика сохранены" in output
    assert str(source / "LiteChecker.command") in output
    assert "unknown extra file" not in output
    assert not any(character in output for character in "{}[]")
    assert (source / "unknown.txt").exists()


def test_cli_success_says_payload_is_redownloadable_and_shows_launcher(tmp_path, capsys):
    source, root, _ = _bundle(tmp_path)
    from litechecker.install_handoff import main

    status = main(["--source", str(source), "--root", str(root)])
    output = capsys.readouterr().out

    assert status == 0
    assert "снова скачать" in output
    assert str(source / "LiteChecker.command") in output
    assert not any(character in output for character in "{}[]")
