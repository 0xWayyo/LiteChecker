"""Opt-in native Windows smoke for the real pinned uv/Python/Xray bootstrap."""

import json
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest


ENABLED = os.name == "nt" and os.environ.get("LC_WINDOWS_BOOTSTRAP_SMOKE") == "1"


def captured(command, **kwargs):
    # PowerShell emits UTF-8. Keep unexpected non-UTF8 bytes as visible escapes
    # rather than losing an entire stream in a Windows reader-thread exception.
    return subprocess.run(command, capture_output=True, text=True,
                          encoding="utf-8", errors="backslashreplace", **kwargs)


@pytest.mark.parametrize("returncode", [0, 23])
def test_bootstrap_capture_preserves_utf8_diagnostics_and_exit_code(monkeypatch, returncode):
    # Reproduce the runner's legacy locale regardless of the current host.
    monkeypatch.setattr(subprocess, "_text_encoding", lambda: "cp1252")
    result = captured([
        sys.executable, "-I", "-c",
        "import sys;sys.stdout.buffer.write('Ошибка подготовки\\n'.encode('utf-8'));"
        "sys.stderr.buffer.write('Сбой\\n'.encode('utf-8')+bytes([0x81]));"
        f"sys.exit({returncode})",
    ], timeout=10)
    assert result.returncode == returncode
    assert result.stdout == "Ошибка подготовки\n"
    assert result.stderr == "Сбой\n\\x81"


@pytest.mark.skipif(not ENABLED, reason="set LC_WINDOWS_BOOTSTRAP_SMOKE=1 in native Windows CI")
def test_real_candidate_prepare_and_isolated_validation(tmp_path):
    from litechecker.update_launcher import runtime_python
    from litechecker.windows_process_state import python_launch
    from platform_package_support import extracted_profile
    from litechecker.update_store import UpdateStore, validate_source_zip
    from test_active_menu import candidate_archive
    from windows_test_support import secure_test_directory
    baseline, key = extracted_profile(tmp_path, "windows")
    candidate = UpdateStore(baseline).stage("0.7.0", validate_source_zip(
        candidate_archive(baseline, "0.7.0"), expected_platform="windows", expected_version="0.7.0"))

    state = baseline / "windows-state"
    state.mkdir()
    settings = state / "settings.json"
    settings.write_text(
        json.dumps({"subscription_url": "https://subscription.invalid/test"}),
        encoding="utf-8",
    )
    before = settings.read_bytes()
    powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    prepare_command = [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(candidate / "scripts" / "windows-native.ps1"),
         "-Root", str(baseline), "-Action", "Prepare"]
    prepare_environment = {**os.environ, "PSModulePath": str(tmp_path / "intentionally-empty-modules")}
    # Extraction inherits the parent's private ACL, whereas Prepare deliberately
    # requires App's protected baseline ACL. Prove refusal before any download.
    inherited = captured(prepare_command, cwd=candidate, stdin=subprocess.DEVNULL,
        timeout=30, env=prepare_environment)
    assert inherited.returncode != 0, inherited.stdout + inherited.stderr
    assert "Папка _app наследует посторонние права." in inherited.stdout + inherited.stderr
    assert not (candidate / ".windows-native").exists()
    assert settings.read_bytes() == before
    # Model the exact baseline precondition established by the public App action,
    # without starting that action or weakening the production Prepare checks.
    secure_test_directory(baseline)
    result = captured(
        prepare_command, cwd=candidate, stdin=subprocess.DEVNULL, timeout=900,
        env=prepare_environment,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert settings.read_bytes() == before
    assert not (candidate / "windows-state").exists()

    python = candidate / ".windows-native" / "venv" / "Scripts" / "python.exe"
    xray = candidate / ".windows-native" / "tools" / "xray" / "xray.exe"
    assert runtime_python(candidate, system="Windows") == python
    assert xray.is_file()
    runtime = captured(
        [str(python), "-I", "-B", "-c",
         "import json,sys;print(json.dumps({'version':list(sys.version_info[:3]),'base':sys.base_prefix}))"],
        cwd=tmp_path, timeout=30,
        env={**os.environ, "PYTHONPATH": str(tmp_path / "hostile")},
    )
    assert runtime.returncode == 0, runtime.stderr
    details = json.loads(runtime.stdout)
    assert details["version"] == [3, 12, 11]
    assert Path(details["base"]).resolve().is_relative_to(
        (candidate / ".windows-native" / "python").resolve()
    )

    base_executable, environment = python_launch(candidate)
    assert base_executable.is_relative_to(candidate / ".windows-native")
    validation = captured(
        [str(python), "-I", "-B", str(candidate / "scripts" / "windows-app-entry.py"),
         "worker", "--validate", "--root", str(baseline), "--release", str(candidate)],
        cwd=tmp_path, stdin=subprocess.DEVNULL, timeout=30,
        executable=str(base_executable), env=environment,
    )
    assert validation.returncode == 0, validation.stdout + validation.stderr

    # Exercise real inherited Windows gate handles: even a valid registration
    # cannot import the menu when the registering parent closes without go.
    import msvcrt
    import psutil
    from litechecker.runtime_lease import _command
    read_gate, write_gate = os.pipe()
    handle = msvcrt.get_osfhandle(read_gate)
    os.set_handle_inheritable(handle, True)
    startup = subprocess.STARTUPINFO()
    startup.lpAttributeList = {"handle_list": [handle]}
    nonce = "d" * 32
    gated = subprocess.Popen(_command(baseline, candidate, handle, nonce, "menu"),
        executable=str(base_executable), env=environment, startupinfo=startup,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    UpdateStore(baseline)._atomic_json(baseline / ".updates" / f"menu-{nonce}.json",
        dict(owner="litechecker-menu-v1", pid=gated.pid, created=psutil.Process(gated.pid).create_time(),
             version="0.7.0", gate=handle, nonce=nonce, action="menu"))
    os.close(read_gate)
    os.close(write_gate)
    stdout, stderr = gated.communicate(timeout=10)
    assert gated.returncode == 1 and stdout == b"", stderr

    # Commit an authenticated candidate through the real transaction. Runtime
    # preparation above is real; this adapter only avoids service/network work.
    from litechecker import updater
    from test_platform_updates import channel, run_release, signed
    from test_updater import Adapter
    from test_windows_setup_flow import conversation
    updater.initialize_channel(baseline, channel(key.public_key().public_bytes_raw(), "windows"))
    data = candidate_archive(baseline, "0.7.0")
    result = asyncio.run(run_release(baseline, Adapter(baseline, running=False),
        signed(key, data, platform="windows"), data))
    assert result["status"] == "updated", result
    command = [sys.executable, "-I", "-B", str(baseline / "scripts/windows-app-entry.py"),
               "menu", "--root", str(baseline)]
    with conversation(command) as (process, expect, answer, transcript):
        expect("MENU-0.7.0", timeout=30)
        expect("Выберите цифру")
        answer("0")
        assert process.wait(timeout=10) == 0
    assert settings.read_bytes() == before
    assert not (state / "control/worker.json").exists()

    assert not (candidate / "windows-state").exists()

    # The actual public BAT prepares the bootstrap runtime and dispatches the
    # active candidate, preserving complete prompts through PowerShell 5.1.
    bat = baseline.parent / "LiteChecker.bat"
    public = captured(["cmd.exe", "/d", "/c", str(bat)], input="0\n", timeout=900)
    assert public.returncode == 0, public.stdout + public.stderr
    assert "MENU-0.7.0" in public.stdout
    assert settings.read_bytes() == before

    with conversation(command) as (process, expect, answer, transcript):
        expect("MENU-0.7.0", timeout=30)
        expect("Выберите цифру")
        # Kill the stable launcher only. The actual managed menu remains alive
        # and is retained by its own PID/creation time, not by its parent.
        process.kill()
        process.wait(timeout=10)
        for version, sequence in (("0.8.0", 10), ("0.9.0", 11)):
            data = candidate_archive(baseline, version)
            result = asyncio.run(run_release(baseline, Adapter(baseline, running=False),
                signed(key, data, platform="windows", version=version, sequence=sequence), data))
            assert result["status"] == "updated", result
        assert (candidate / "src/litechecker/windows_app.py").is_file()
        assert xray.is_file() and python.is_file()
        answer("0")
        deadline = time.monotonic() + 10
        while candidate.exists() and time.monotonic() < deadline:
            updater.cleanup_updates(baseline)
            time.sleep(.05)
        assert not candidate.exists()
    assert settings.read_bytes() == before
    assert not (state / "control/worker.json").exists()

    marker = baseline / "distribution.json"
    marker.write_text('{"platform":"macos","schema":1}\n')
    refused = captured(command, input="0\n", timeout=30)
    assert refused.returncode != 0
    assert "Выберите цифру" not in refused.stdout
