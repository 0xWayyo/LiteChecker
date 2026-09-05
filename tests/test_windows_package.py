"""The Windows trial archive is an exact, deterministic public allowlist."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest


REPOSITORY = Path(__file__).resolve().parents[1]
PREFIX = "LiteChecker-Windows-test/"


def load_builder():
    path = REPOSITORY / "scripts/package_windows_trial.py"
    spec = importlib.util.spec_from_file_location("windows_trial_packager", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def fixture_project(root: Path) -> None:
    files = {
        "TRY-WINDOWS.bat": b"@echo off\r\nfixture launcher\r\n",
        "DIAGNOSE-WINDOWS.bat": b"@echo off\r\nfixture diagnostics\r\n",
        "WINDOWS-TRIAL.md": (
            "# Test\n\n## \u0411\u044b\u0441\u0442\u0440\u044b\u0439 \u0441\u0442\u0430\u0440\u0442\n\n"
            "\u0420\u0430\u0441\u043f\u0430\u043a\u0443\u0439\u0442\u0435 ZIP \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e.\n\n"
            "## \u0412\u0430\u0436\u043d\u043e\n\n\u0422\u043e\u043b\u044c\u043a\u043e \u0442\u0435\u0441\u0442.\n"
        ).encode("utf-8"),
        "pyproject.toml": b"[project]\nname='fixture'\n",
        "uv.lock": b"version = 1\n",
        "README.md": b"THIS LARGE REPOSITORY README MUST NOT SHIP\n",
        "scripts/windows-native.ps1": b"\xef\xbb\xbfparam([string]$Root)\r\n",
        "scripts/windows-entry.py": b"raise SystemExit('fixture entry')\n",
        "src/litechecker/__init__.py": b"PACKAGE = True\n",
        "src/litechecker/nested/runtime.py": b"RUNTIME = True\n",
    }
    for name, payload in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)


def test_noisy_project_build_is_exact_deterministic_and_checksummed(tmp_path):
    builder = load_builder()
    source = tmp_path / "source with unicode \u0442\u0435\u0441\u0442"
    source.mkdir()
    fixture_project(source)
    noise = {
        ".git/config": b"private remote",
        ".superpowers/plan.md": b"private plan",
        "tests/test_private.py": b"private test",
        "windows-state/settings.json": b"PRIVATE-SUBSCRIPTION-AND-TOKEN",
        ".windows-native/cache/download": b"PRIVATE-RUNTIME",
        "scripts/update.ps1": b"production updater",
        "src/litechecker/__pycache__/runtime.pyc": b"compiled cache",
        "src/litechecker/nested/settings.json": b"PRIVATE-SETTINGS",
        "src/litechecker/nested/debug.log": b"PRIVATE-LOG",
    }
    for name, payload in noise.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    first_result = builder.build_package(source, first)
    second_result = builder.build_package(source, second)

    assert first.read_bytes() == second.read_bytes()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert first_result.sha256 == digest
    assert second_result.sha256 == digest
    assert first.with_suffix(".zip.sha256").read_text("ascii") == f"{digest}  first.zip\n"

    expected = [
        PREFIX + "DIAGNOSE-WINDOWS.bat",
        PREFIX + "TRY-WINDOWS.bat",
        PREFIX + "_app/README.md",
        PREFIX + "_app/pyproject.toml",
        PREFIX + "_app/scripts/windows-native.ps1",
        PREFIX + "_app/scripts/windows-entry.py",
        PREFIX + "_app/src/litechecker/__init__.py",
        PREFIX + "_app/src/litechecker/nested/runtime.py",
        PREFIX + "_app/uv.lock",
        PREFIX + "\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt",
    ]
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == sorted(expected)
        assert archive.testzip() is None
        assert b"PRIVATE-" not in b"".join(archive.read(name) for name in expected)
        assert b"THIS LARGE REPOSITORY README" not in archive.read(PREFIX + "_app/README.md")
        starter = archive.read(PREFIX + "\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt").decode("utf-8-sig")
        assert "\u0420\u0430\u0441\u043f\u0430\u043a\u0443\u0439\u0442\u0435 ZIP \u043f\u043e\u043b\u043d\u043e\u0441\u0442\u044c\u044e." in starter
        assert "\u0422\u043e\u043b\u044c\u043a\u043e \u0442\u0435\u0441\u0442." in starter


@pytest.mark.parametrize(
    "link_name,target_name",
    [
        ("TRY-WINDOWS.bat", "outside.bat"),
        ("src/litechecker/linked.py", "outside.py"),
        ("src/litechecker/linked", "outside-runtime"),
    ],
)
def test_builder_rejects_symlink_inputs_without_creating_archive(tmp_path, link_name, target_name):
    builder = load_builder()
    source = tmp_path / "source"
    source.mkdir()
    fixture_project(source)
    link = source / link_name
    if link.exists():
        link.unlink()
    target = tmp_path / target_name
    if "." in Path(target_name).name:
        target.write_text("outside")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target)
    else:
        target.mkdir()
        (target / "escape.py").write_text("ESCAPED = True\n")
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(target, target_is_directory=True)
    output = tmp_path / "trial.zip"

    with pytest.raises(ValueError, match="symbolic link"):
        builder.build_package(source, output)

    assert not output.exists()
    assert not output.with_suffix(".zip.sha256").exists()


def test_builder_rejects_symlinked_parent_of_exact_input(tmp_path):
    builder = load_builder()
    source = tmp_path / "source"
    source.mkdir()
    fixture_project(source)
    outside = tmp_path / "outside-scripts"
    outside.mkdir()
    (outside / "windows-native.ps1").write_text("must not ship")
    shutil.rmtree(source / "scripts")
    (source / "scripts").symlink_to(outside, target_is_directory=True)
    output = tmp_path / "trial.zip"

    with pytest.raises(ValueError, match="symbolic link"):
        builder.build_package(source, output)

    assert not output.exists()


def test_builder_rejects_symlink_output(tmp_path):
    builder = load_builder()
    source = tmp_path / "source"
    source.mkdir()
    fixture_project(source)
    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"must remain unchanged")
    output = tmp_path / "trial.zip"
    output.symlink_to(outside)

    with pytest.raises(ValueError, match="output"):
        builder.build_package(source, output)

    assert outside.read_bytes() == b"must remain unchanged"


@pytest.mark.parametrize("occupied", ["archive", "checksum"])
def test_builder_rejects_non_file_output_targets_before_promotion(tmp_path, occupied):
    builder = load_builder()
    source = tmp_path / "source"
    source.mkdir()
    fixture_project(source)
    output = tmp_path / "trial.zip"
    target = output if occupied == "archive" else output.with_suffix(".zip.sha256")
    target.mkdir()

    with pytest.raises(ValueError, match="output"):
        builder.build_package(source, output)

    assert target.is_dir()
    assert not any(path.name.startswith(".windows-trial-") for path in tmp_path.iterdir())


def test_repository_archive_contains_safe_native_launch_contract(tmp_path):
    builder = load_builder()
    output = tmp_path / "LiteChecker-Windows-test.zip"
    builder.build_package(REPOSITORY, output)

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert all(name.startswith(PREFIX) and not name.endswith("/") for name in names)
        assert not any(
            marker in name.lower()
            for name in names
            for marker in ("/.git", "/tests/", "/.superpowers/", "windows-state", ".windows-native")
        )
        assert set(names) == {
            PREFIX + "DIAGNOSE-WINDOWS.bat",
            PREFIX + "TRY-WINDOWS.bat",
            PREFIX + "\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt",
            PREFIX + "_app/README.md",
            PREFIX + "_app/pyproject.toml",
            PREFIX + "_app/uv.lock",
            PREFIX + "_app/scripts/windows-native.ps1",
            PREFIX + "_app/scripts/windows-entry.py",
            *(PREFIX + "_app/" + path.relative_to(REPOSITORY).as_posix()
              for path in sorted((REPOSITORY / "src/litechecker").rglob("*.py"))),
        }

        batch = archive.read(PREFIX + "TRY-WINDOWS.bat").decode("ascii").lower()
        assert "%~dp0" in batch
        assert "_app\\scripts\\windows-native.ps1" in batch
        assert "scripts\\windows-native.ps1" in batch
        assert "-executionpolicy bypass" in batch
        assert '-root "%litechecker_root%."' in batch
        assert "set-executionpolicy" not in batch

        diagnostics_batch = archive.read(PREFIX + "DIAGNOSE-WINDOWS.bat").decode("ascii").lower()
        assert "%~dp0" in diagnostics_batch
        assert "_app\\scripts\\windows-native.ps1" in diagnostics_batch
        assert "scripts\\windows-native.ps1" in diagnostics_batch
        assert "-executionpolicy bypass" in diagnostics_batch
        assert '-root "%litechecker_root%."' in diagnostics_batch
        assert "-action diagnose" in diagnostics_batch
        assert "set-executionpolicy" not in diagnostics_batch

        powershell_raw = archive.read(PREFIX + "_app/scripts/windows-native.ps1")
        assert powershell_raw.startswith(b"\xef\xbb\xbf")
        powershell = powershell_raw.decode("utf-8-sig").lower()
        for required in (
            "5049375aa2a5162f132b2c1cb992e25d42d47d934cab8c174dbe6f60973dcc12",
            "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
            "https://github.com/astral-sh/uv/releases/download/0.8.22/uv-x86_64-pc-windows-msvc.zip",
            "https://github.com/xtls/xray-core/releases/download/v26.3.27/xray-windows-64.zip",
            "uv_project_environment",
            "$uvcachedirectory",
            "$pythondirectory",
            "$venvdirectory",
            "uv_python_install_registry",
            "& $uvexe sync --no-install-project --no-build --frozen --no-dev --python $pythonversion --no-config",
            "& $script:pythonexe -i -b $script:entryscript --root $script:rootpath --xray $script:xrayexe @arguments",
            "$script:entryscript",
            "assert-saferegularfile $script:entryscript",
            "-i", "-b", "--root", "--xray",
            "6. \u0434\u0438\u0430\u0433\u043d\u043e\u0441\u0442\u0438\u043a\u0430 \u0441\u0435\u0442\u0438 (\u043f\u0440\u0438 \u043f\u0440\u043e\u0431\u043b\u0435\u043c\u0430\u0445 \u0441 tun)",
            "initialize-nativeruntime -includexray $false",
            "& $script:pythonexe -i -b $script:entryscript --root $script:rootpath --diagnose",
        ):
            assert required in powershell
        assert "-m litechecker.windows_trial" not in powershell
        for forbidden in (
            "invoke-expression", "set-executionpolicy", "start-service", "new-service",
            "set-netroute", "set-dnsclientserveraddress", "netsh", "reg.exe",
        ):
            assert forbidden not in powershell

        guide = archive.read(PREFIX + "\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt").decode("utf-8-sig")
        for phrase in (
            "Windows 10/11 x64", "Ctrl+C", "windows-state",
            "last-report.txt", "last-observation.json", "\u0422\u0415\u0421\u0422\u041e\u0412\u0410\u042f",
            "DIAGNOSE-WINDOWS.bat", "last-diagnostics.txt", "GUID",
        ):
            assert phrase in guide


def test_isolated_entry_uses_bundled_source_and_preserves_arguments(tmp_path):
    application = tmp_path / "application with unicode \u0442\u0435\u0441\u0442"
    scripts = application / "scripts"
    bundled = application / "src/litechecker"
    hostile = tmp_path / "hostile/litechecker"
    unrelated = tmp_path / "unrelated working directory"
    scripts.mkdir(parents=True)
    bundled.mkdir(parents=True)
    hostile.mkdir(parents=True)
    unrelated.mkdir()
    shutil.copyfile(REPOSITORY / "scripts/windows-entry.py", scripts / "windows-entry.py")
    (bundled / "__init__.py").write_text("")
    (bundled / "windows_trial.py").write_text(
        "import json, sys\n"
        "def main():\n"
        "    print(json.dumps({'origin': __file__, 'argv': sys.argv[1:]}))\n"
        "    return 23\n"
    )
    (hostile / "__init__.py").write_text("")
    (hostile / "windows_trial.py").write_text("raise RuntimeError('hostile module imported')\n")
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(hostile.parent)
    arguments = ["--root", "C:\\trial root", "--xray", "C:\\xray.exe", "--setup"]

    completed = subprocess.run(
        [sys.executable, "-I", "-B", str(scripts / "windows-entry.py"), *arguments],
        cwd=unrelated,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 23, completed.stderr
    result = json.loads(completed.stdout)
    assert Path(result["origin"]) == bundled / "windows_trial.py"
    assert result["argv"] == arguments
