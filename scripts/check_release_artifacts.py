#!/usr/bin/env python3
"""Reject release archives containing anything outside the package allowlist."""

from __future__ import annotations

import sys
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


_FORBIDDEN = frozenset(
    {".superpowers", ".worktrees", "secrets", "tests", "deploy", "scripts"}
)


def _safe_member(name: str, *, wheel: bool) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or _FORBIDDEN.intersection(path.parts):
        return False
    lowered = name.lower()
    if lowered.endswith((".diff", ".report")) or ".env" in path.parts:
        return False
    if wheel:
        return path.parts[0] == "litechecker" or (
            len(path.parts) > 1 and path.parts[0].endswith(".dist-info")
        )
    if len(path.parts) < 2:
        return path.parts[0].startswith("litechecker-")
    relative = PurePosixPath(*path.parts[1:])
    return relative in {
        PurePosixPath("PKG-INFO"),
        PurePosixPath("README.md"),
        PurePosixPath("pyproject.toml"),
        PurePosixPath(".gitignore"),
    } or relative.parts[:2] == ("src", "litechecker")


def check_directory(directory: Path) -> bool:
    archives = sorted(directory.glob("litechecker-*"))
    if not archives or not any(path.suffix == ".whl" for path in archives):
        return False
    if not any(path.name.endswith(".tar.gz") for path in archives):
        return False
    for archive in archives:
        wheel = archive.suffix == ".whl"
        if wheel:
            with zipfile.ZipFile(archive) as bundle:
                names = bundle.namelist()
        elif archive.name.endswith(".tar.gz"):
            with tarfile.open(archive) as bundle:
                members = bundle.getmembers()
                if any(not (member.isfile() or member.isdir()) for member in members):
                    return False
                names = [member.name for member in members]
        else:
            return False
        if not names or any(not _safe_member(name, wheel=wheel) for name in names):
            return False
    return True


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--platform-smoke":
        return platform_smoke(Path(argv[1]).absolute())
    if len(argv) > 1:
        return 64
    directory = Path(argv[0] if argv else "dist")
    return 0 if directory.is_dir() and check_directory(directory) else 1


def platform_smoke(output: Path) -> int:
    """Author CI: build every source from one snapshot, exercise the host archive."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from litechecker.distribution import host_platform
    from litechecker.update_store import validate_source_zip
    import package_platforms
    import package_windows
    key = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    paths = package_platforms.build_sources(output / "archives", version="0.6.0",
        public_key=key, repository="example/LiteChecker")
    snapshots = {}
    for platform, path in paths.items():
        validated = validate_source_zip(path.read_bytes(), expected_platform=platform, expected_version="0.6.0")
        snapshots[platform] = {str(item.path): item.data for item in validated.files}
    for module in package_platforms.COMMON_MODULES:
        name = "src/litechecker/" + module
        if len({files[name] for files in snapshots.values()}) != 1:
            raise ValueError("shared profile source mismatch")
    platform = host_platform()
    source = paths[platform]
    if platform == "windows":
        source = output / "archives/LiteChecker-0.6.0-Windows.zip"
        package_windows.build_package(paths[platform], source)
    with zipfile.ZipFile(source) as archive:
        archive.extractall(output / "public")
    root = output / "public/LiteChecker"
    if platform == "windows":
        root /= "_app"
    modules = ["litechecker." + name.removesuffix(".py").replace("/", ".")
               for name in package_platforms.COMMON_MODULES + package_platforms.PLATFORM_MODULES[platform]]
    code = ("import sys,importlib;sys.path.insert(0,sys.argv[1]);"
            "[importlib.import_module(name) for name in sys.argv[2:]]")
    subprocess.run([sys.executable, "-I", "-B", "-c", code, str(root / "src"), *modules],
                   cwd=output, stdin=subprocess.DEVNULL, check=True, timeout=45,
                   env={key: value for key, value in os.environ.items() if not key.upper().startswith("PYTHON")})
    print(f"profile={platform} offline-import=ok root={root}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
