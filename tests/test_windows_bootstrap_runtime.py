"""Opt-in native Windows smoke for the real pinned uv/Python/Xray bootstrap."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
ENABLED = os.name == "nt" and os.environ.get("LC_WINDOWS_BOOTSTRAP_SMOKE") == "1"


@pytest.mark.skipif(not ENABLED, reason="set LC_WINDOWS_BOOTSTRAP_SMOKE=1 in native Windows CI")
def test_real_candidate_prepare_and_isolated_validation(tmp_path):
    from litechecker.update_launcher import runtime_python
    from windows_test_support import secure_test_directory

    baseline = tmp_path / "LiteChecker" / "_app"
    baseline.mkdir(parents=True)
    secure_test_directory(baseline)
    candidate = baseline / ".updates" / "releases" / "0.5.1"
    candidate.mkdir(parents=True)

    for source in sorted((REPOSITORY / "src" / "litechecker").rglob("*.py")):
        destination = candidate / source.relative_to(REPOSITORY)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    for relative in (
        "pyproject.toml",
        "uv.lock",
        "scripts/windows-native.ps1",
        "scripts/windows-app-entry.py",
    ):
        destination = candidate / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY / relative, destination)

    state = baseline / "windows-state"
    state.mkdir()
    settings = state / "settings.json"
    settings.write_text(
        json.dumps({"subscription_url": "https://subscription.invalid/test"}),
        encoding="utf-8",
    )
    before = settings.read_bytes()
    powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    result = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(candidate / "scripts" / "windows-native.ps1"),
         "-Root", str(baseline), "-Action", "Prepare"],
        cwd=candidate, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=900,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert settings.read_bytes() == before
    assert not (candidate / "windows-state").exists()

    python = candidate / ".windows-native" / "venv" / "Scripts" / "python.exe"
    xray = candidate / ".windows-native" / "tools" / "xray" / "xray.exe"
    assert runtime_python(candidate, system="Windows") == python
    assert xray.is_file()
    runtime = subprocess.run(
        [str(python), "-I", "-B", "-c",
         "import json,sys;print(json.dumps({'version':list(sys.version_info[:3]),'base':sys.base_prefix}))"],
        cwd=tmp_path, text=True, capture_output=True, timeout=30,
        env={**os.environ, "PYTHONPATH": str(tmp_path / "hostile")},
    )
    assert runtime.returncode == 0, runtime.stderr
    details = json.loads(runtime.stdout)
    assert details["version"] == [3, 12, 11]
    assert Path(details["base"]).resolve().is_relative_to(
        (candidate / ".windows-native" / "python").resolve()
    )

    validation = subprocess.run(
        [str(python), "-I", "-B", str(candidate / "scripts" / "windows-app-entry.py"),
         "worker", "--validate", "--root", str(baseline), "--release", str(candidate)],
        cwd=tmp_path, stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=30,
        env={**os.environ, "PYTHONPATH": str(tmp_path / "hostile")},
    )
    assert validation.returncode == 0, validation.stdout + validation.stderr
