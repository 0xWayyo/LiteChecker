"""Exercise the optional launcher without fetching binaries or using a VPN."""
import os
from pathlib import Path
import shutil
import subprocess


SOURCE = Path(__file__).resolve().parents[1]


def setup(tmp_path, *, uv_status=0):
    root = tmp_path / "Lite Checker"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SOURCE / "scripts/try-direct.sh", root / "scripts/try-direct.sh")
    shutil.copy(SOURCE / "scripts/native-direct.sh", root / "scripts/native-direct.sh")
    runtime = root / ".native-direct"
    (runtime / "venv/bin").mkdir(parents=True)
    managed_python = runtime / "python/cpython/bin/python3.12"
    managed_python.parent.mkdir(parents=True)
    mockbin = tmp_path / "bin"
    mockbin.mkdir()
    for path, body in {
        mockbin / "uname": '#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n',
        runtime / "uv": f'#!/bin/sh\nprintf "%s|%s\\n" "${{UV_PYTHON_PREFERENCE:-}}" "$*" >> "{root}/uv-args"\nexit {uv_status}\n',
        runtime / "xray": '#!/bin/sh\necho "Xray 26.3.27"\n',
        managed_python: f'#!/bin/sh\nprintf "%s\\n" "$@" > "{root}/python-args"\n',
    }.items():
        path.write_text(body)
        path.chmod(0o700)
    (runtime / "venv/bin/python").symlink_to(managed_python)
    env = {**os.environ, "PATH": str(mockbin) + ":" + os.environ["PATH"]}
    return root, env


def test_launcher_runs_native_trial_without_docker_or_changing_working_config(tmp_path):
    root, env = setup(tmp_path)
    result = subprocess.run(["bash", "scripts/try-direct.sh"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    args = (root / "python-args").read_text().splitlines()
    assert args[:2] == ["-m", "litechecker.direct_check"]
    assert "--send" in args
    assert str(root) in args
    assert not (root / ".env.standalone").exists()
    assert "--frozen" in (root / "uv-args").read_text()
    assert (root / "uv-args").read_text().startswith("only-managed|")


def test_dependency_failure_does_not_start_checker(tmp_path):
    root, env = setup(tmp_path, uv_status=17)
    result = subprocess.run(["bash", "scripts/try-direct.sh"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert not (root / "python-args").exists()


def test_runtime_symlink_is_rejected(tmp_path):
    root, env = setup(tmp_path)
    target = root / ".native-direct"
    target.rename(root / "elsewhere")
    target.symlink_to(root / "elsewhere", target_is_directory=True)
    result = subprocess.run(["bash", "scripts/try-direct.sh"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
    assert not (root / "python-args").exists()


def test_runtime_python_symlink_escaping_private_runtime_is_rejected_before_sync(tmp_path):
    root, env = setup(tmp_path)
    python = root / ".native-direct/venv/bin/python"
    python.unlink()
    outside = tmp_path / "outside-python"
    outside.write_text('#!/bin/sh\nexit 0\n')
    outside.chmod(0o700)
    python.symlink_to(outside)

    result = subprocess.run(["bash", "scripts/try-direct.sh"], cwd=root, env=env,
                            capture_output=True, text=True, timeout=10)

    assert result.returncode != 0
    assert not (root / "uv-args").exists()
    assert not (root / "python-args").exists()
