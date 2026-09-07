"""End-user Windows ZIP is a clean wrapper around the validated source payload."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]


def load_script(name):
    # Mirror direct script execution so the shared sibling builder is importable.
    if str(ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(ROOT / "scripts"))
    path = ROOT / "scripts" / name
    assert path.is_file(), "Windows distribution builder is missing"
    spec = importlib.util.spec_from_file_location("distribution_" + path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_package(tmp_path):
    return load_script("package_platforms.py").build_sources(
        tmp_path / "source", version="0.6.3", repository="example/LiteChecker",
        public_key=Ed25519PrivateKey.generate().public_key().public_bytes_raw(),
    )["windows"]


def test_windows_profile_contains_native_windows_bootstrap(tmp_path):
    source = source_package(tmp_path)
    with zipfile.ZipFile(source) as archive:
        for name in ("LiteChecker.bat", "scripts/windows-native.ps1", "scripts/windows-app-entry.py", "WINDOWS.md"):
            assert "LiteChecker/" + name in archive.namelist()


def test_clean_windows_wrapper_preserves_all_validated_payload_bytes(tmp_path):
    builder = load_script("package_desktop.py")
    source = source_package(tmp_path)
    destination = tmp_path / "windows.zip"
    builder.build_package(source, destination)
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(destination) as packaged:
        names = packaged.namelist()
        assert packaged.testzip() is None
        assert len(names) == len(set(names))
        assert sorted(name for name in names if name.count("/") == 1) == ["LiteChecker/LiteChecker.bat", "LiteChecker/НАЧНИТЕ-ЗДЕСЬ.txt"]
        for name in original.namelist():
            relative = name.removeprefix("LiteChecker/")
            assert packaged.read("LiteChecker/_app/" + relative) == original.read(name)
        assert not any(part in {"tests", ".git", "secrets", "windows-state", ".windows-native", ".superpowers"} for name in names for part in name.split("/"))
        assert packaged.read("LiteChecker/LiteChecker.bat") == original.read("LiteChecker/LiteChecker.bat")
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    assert destination.with_suffix(".zip.sha256").read_text("ascii") == f"{digest}  windows.zip\n"


def test_wrapper_refuses_tampered_source_and_keeps_existing_output(tmp_path):
    builder = load_script("package_desktop.py")
    source = source_package(tmp_path)
    with zipfile.ZipFile(source, "a") as archive:
        archive.writestr("LiteChecker/src/foreign.py", "not in manifest")
    output = tmp_path / "windows.zip"
    output.write_bytes(b"existing delivery")
    with pytest.raises(ValueError):
        builder.build_package(source, output)
    assert output.read_bytes() == b"existing delivery"


def test_wrapper_refuses_symlink_output_and_does_not_touch_target(tmp_path):
    builder = load_script("package_desktop.py")
    source = source_package(tmp_path)
    outside = tmp_path / "outside.zip"
    outside.write_bytes(b"preserve")
    output = tmp_path / "windows.zip"
    output.symlink_to(outside)
    with pytest.raises(ValueError):
        builder.build_package(source, output)
    assert outside.read_bytes() == b"preserve"


def test_failed_checksum_write_removes_only_new_partial_delivery(tmp_path, monkeypatch):
    builder = load_script("package_desktop.py")
    source = source_package(tmp_path)
    output = tmp_path / "windows.zip"
    checksum = output.with_suffix(".zip.sha256")
    original_open = Path.open

    class FailedWrite:
        def __enter__(self):
            self.stream = original_open(checksum, "x", encoding="ascii")
            return self
        def write(self, data):
            self.stream.write(data[:5])
            raise OSError("fixture disk full")
        def __exit__(self, *args):
            self.stream.close()

    def fail_checksum(path, mode="r", *args, **kwargs):
        if path == checksum and mode == "x":
            return FailedWrite()
        return original_open(path, mode, *args, **kwargs)
    monkeypatch.setattr(Path, "open", fail_checksum)
    with pytest.raises(OSError, match="fixture disk full"):
        builder.build_package(source, output)
    assert source.is_file()
    assert not output.exists()
    assert not checksum.exists()
