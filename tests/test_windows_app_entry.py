import os
import shutil
import subprocess
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


def test_isolated_entry_dispatches_known_commands_and_preserves_argv(tmp_path):
    release = tmp_path / "release"
    scripts = release / "scripts"
    package = release / "src" / "litechecker"
    hostile = tmp_path / "hostile" / "litechecker"
    scripts.mkdir(parents=True)
    package.mkdir(parents=True)
    hostile.mkdir(parents=True)
    shutil.copy2(REPOSITORY / "scripts" / "windows-app-entry.py", scripts / "windows-app-entry.py")
    (package / "__init__.py").write_text("")
    (hostile / "__init__.py").write_text("")
    (hostile / "windows_control.py").write_text("raise RuntimeError('hostile import')\n")
    (package / "windows_control.py").write_text(
        "def main(argv=None):\n"
        "    print('trusted-supervisor:' + '|'.join(argv or []))\n"
        "    return 17\n"
    )

    result = subprocess.run(
        [sys.executable, "-I", "-B", str(scripts / "windows-app-entry.py"),
         "supervisor", "--root", "C:/Root With Spaces", "--release", "C:/Release", "--instance", "abc"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(hostile), "PYTHONSTARTUP": str(tmp_path / "bad.py")},
        text=True,
        capture_output=True,
    )
    assert result.returncode == 17
    assert result.stdout.strip() == "trusted-supervisor:--root|C:/Root With Spaces|--release|C:/Release|--instance|abc"
    assert "hostile" not in result.stderr


def test_entry_rejects_unknown_action_without_importing(tmp_path):
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(REPOSITORY / "scripts" / "windows-app-entry.py"), "other"],
        cwd=tmp_path, text=True, capture_output=True,
    )
    assert result.returncode == 2


def test_entry_rejects_symlinked_scripts_ancestor(tmp_path):
    release = tmp_path / "release"
    real_scripts = tmp_path / "real-scripts"
    real_scripts.mkdir()
    release.mkdir()
    shutil.copy2(REPOSITORY / "scripts" / "windows-app-entry.py", real_scripts / "windows-app-entry.py")
    (release / "scripts").symlink_to(real_scripts, target_is_directory=True)

    result = subprocess.run(
        [sys.executable, "-I", "-B", str(release / "scripts" / "windows-app-entry.py"), "menu"],
        cwd=tmp_path, text=True, capture_output=True,
    )
    assert result.returncode != 0
    assert "unsafe Windows entry" in result.stderr
