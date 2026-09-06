"""Real public profile fixtures; private test roots and synthetic keys only."""
from pathlib import Path
import shutil
import sys
import zipfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_platform_distribution import script
from windows_test_support import secure_test_directory


def extracted_profile(directory: Path, platform: str):
    directory.mkdir(parents=True, exist_ok=True)
    secure_test_directory(directory)
    key = Ed25519PrivateKey.generate()
    paths = script("package_platforms").build_sources(
        directory / "archives", version="0.6.1", public_key=key.public_key().public_bytes_raw(),
        repository="example/LiteChecker")
    archive = paths[platform]
    if platform in {"windows", "macos"}:
        label = "Windows" if platform == "windows" else "macOS"
        archive = directory / f"archives/LiteChecker-0.6.1-{label}.zip"
        script("package_desktop").build_package(paths[platform], archive, platform=platform)
    with zipfile.ZipFile(archive) as bundle:
        bundle.extractall(directory / "public")
    root = directory / "public/LiteChecker"
    return (root / "_app" if platform in {"windows", "macos"} else root), key


def local_runtime(release: Path):
    """A real copied executable, no download; real pinned preparation is a CI gate."""
    runtime = release / (".windows-native" if sys.platform == "win32" else
                         ".native-direct" if sys.platform == "darwin" else ".updater-runtime")
    executable = runtime / ("venv/Scripts/python.exe" if sys.platform == "win32" else "venv/bin/python")
    executable.parent.mkdir(parents=True)
    shutil.copy2(sys.executable, executable)
    executable.chmod(0o700)
    (runtime / "venv/pyvenv.cfg").write_text(
        f"home = {Path(sys._base_executable).parent}\ninclude-system-site-packages = true\n")
    if sys.platform != "win32":
        lib = runtime / f"venv/lib/python{sys.version_info.major}.{sys.version_info.minor}"
        lib.mkdir(parents=True)
        (lib / "site-packages").symlink_to(Path(sys.prefix) / f"lib/python{sys.version_info.major}.{sys.version_info.minor}/site-packages", target_is_directory=True)
    return executable
