"""The public macOS entry survives installer cleanup and preserves update bytes."""
import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
import zipfile

import pytest

from test_platform_distribution import contents, script, sources  # noqa: F401


def unpack(source, destination):
    archive = destination / "macOS.zip"
    destination.mkdir(parents=True)
    script("package_desktop").build_package(source, archive, platform="macos")
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(destination)
        for item in bundle.infolist():
            (destination / item.filename).chmod((item.external_attr >> 16) & 0o777)
    return destination / "LiteChecker", archive


def test_macos_wrapper_has_one_entry_folder_and_guide_with_exact_update_payload(sources, tmp_path):
    _, paths = sources
    root, first = unpack(paths["macos"], tmp_path / "first")
    _, second = unpack(paths["macos"], tmp_path / "second")
    assert {p.name for p in root.iterdir()} == {"INSTALL.command", "_app", "НАЧНИТЕ-ЗДЕСЬ.txt"}
    expected = contents(paths["macos"])
    with zipfile.ZipFile(first) as bundle:
        actual = {name.removeprefix("LiteChecker/_app/"): bundle.read(name)
                  for name in bundle.namelist() if name.startswith("LiteChecker/_app/")}
        assert actual == expected
        assert stat.S_IMODE(bundle.getinfo("LiteChecker/INSTALL.command").external_attr >> 16) == 0o755
    assert (root / "НАЧНИТЕ-ЗДЕСЬ.txt").read_bytes() == expected["MACOS.md"]
    assert first.read_bytes() == second.read_bytes()
    assert first.with_suffix(".zip.sha256").read_text() == f"{hashlib.sha256(first.read_bytes()).hexdigest()}  macOS.zip\n"


@pytest.mark.parametrize("wrong_platform", ["windows", "linux"])
def test_macos_wrapper_rejects_other_platforms_before_writing(sources, tmp_path, wrong_platform):
    _, paths = sources
    output = tmp_path / "invalid.zip"
    with pytest.raises(ValueError):
        script("package_desktop").build_package(paths[wrong_platform], output, platform="macos")
    assert not output.exists()
    assert not output.with_suffix(".zip.sha256").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX launcher behavior")
def test_macos_entry_runs_installer_from_a_different_working_directory(sources, tmp_path):
    _, paths = sources
    root, _ = unpack(paths["macos"], tmp_path / "папка с пробелами")
    # The child is the installation boundary: never download or start services.
    (root / "_app/INSTALL.command").write_text("#!/bin/bash\nprintf 'installer reached\\n'\nexit 37\n")
    result = subprocess.run([str(root / "INSTALL.command")], cwd=tmp_path,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert result.returncode == 37
    assert result.stdout == "installer reached\n"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX launcher and handoff behavior")
def test_same_outer_entry_opens_management_after_real_safe_handoff(sources, tmp_path, monkeypatch):
    from litechecker import install_handoff

    monkeypatch.setattr(install_handoff, "sys", SimpleNamespace(platform="darwin"))
    _, paths = sources
    root, _ = unpack(paths["macos"], tmp_path / "распаковка")
    source = root / "_app"
    installed = tmp_path / "installed data"
    for relative in ("INSTALL.command", "scripts/control.sh"):
        target = installed / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative, target)
        target.chmod(0o700)
    (installed / "native-settings.json").write_text('{"LC_INTERVAL_SECONDS":"600"}\n')
    (installed / "native-settings.json").chmod(0o600)
    for relative in (".native-direct/venv/bin/python", ".native-direct/xray"):
        target = installed / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/bash\nexit 0\n")
        target.chmod(0o700)

    result = install_handoff.finish_handoff(source, installed)
    assert result["ok"] is True, result
    assert {p.name for p in source.iterdir()} == {"LiteChecker.command"}
    assert {p.name for p in root.iterdir()} == {"INSTALL.command", "_app", "НАЧНИТЕ-ЗДЕСЬ.txt"}
    # Replace only the service-owning boundary after the real validated handoff.
    (installed / "scripts/control.sh").write_text('#!/bin/bash\nprintf "%s\\n" "$1" "$LITECHECKER_NATIVE_ROOT"\n')
    launched = subprocess.run([str(root / "INSTALL.command")], cwd=tmp_path,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert launched.returncode == 0, launched.stderr
    assert launched.stdout.splitlines() == ["menu", str(installed)]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX launcher boundary")
@pytest.mark.parametrize("broken", ["missing", "folder-link", "entry-link"])
def test_macos_entry_refuses_missing_or_linked_payload(sources, tmp_path, broken):
    _, paths = sources
    root, _ = unpack(paths["macos"], tmp_path / "public")
    child = root / "_app/INSTALL.command"
    if broken == "missing":
        child.unlink()
    elif broken == "folder-link":
        outside = tmp_path / "moved-payload"
        (root / "_app").rename(outside)
        (root / "_app").symlink_to(outside, target_is_directory=True)
    else:
        outside = tmp_path / "outside.command"
        outside.write_text("#!/bin/bash\nprintf 'unsafe entry ran\\n'\n")
        child.unlink()
        child.symlink_to(outside)
    result = subprocess.run([str(root / "INSTALL.command")], cwd=tmp_path,
                            stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert result.returncode == 2
    assert "_app" in result.stderr
    assert "unsafe entry ran" not in result.stdout
