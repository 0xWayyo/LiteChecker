#!/usr/bin/env python3
"""Build the explicit, public-only LiteChecker native Windows trial archive."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import NamedTuple
import zipfile


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "LiteChecker-Windows-test/"
FIXED_ZIP_TIME = (2026, 9, 5, 0, 0, 0)
MAX_INPUT_BYTES = 16 * 1024 * 1024
EXACT_INPUTS = {
    "DIAGNOSE-WINDOWS.bat": "DIAGNOSE-WINDOWS.bat",
    "TRY-WINDOWS.bat": "TRY-WINDOWS.bat",
    "pyproject.toml": "_app/pyproject.toml",
    "uv.lock": "_app/uv.lock",
    "scripts/windows-native.ps1": "_app/scripts/windows-native.ps1",
    "scripts/windows-entry.py": "_app/scripts/windows-entry.py",
}
BUILD_README = b"""# LiteChecker Windows D2 test application\n\nThis directory is application payload for DIAGNOSE-WINDOWS.bat and TRY-WINDOWS.bat in the parent directory.\nRun diagnostics first, then choose item 1 in TRY-WINDOWS.bat. D2 uses bound Cloudflare DoH for the normal trial; diagnostics separately reports adapter DNS errors and the observed public IP.\nKeep the extracted directory together. This is an experimental one-shot test, not an installer or updater. It does not change routes, DNS, VPN or firewall settings and cannot guarantee bypass of every TUN implementation.\n"""


class PackageResult(NamedTuple):
    archive: Path
    checksum: Path
    sha256: str
    files: int


def _require_real_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a real directory")


def _read_regular(path: Path) -> bytes:
    if path.is_symlink():
        raise ValueError("package input must not be a symbolic link")
    try:
        metadata = path.stat()
    except OSError as error:
        raise ValueError("required package input is missing") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("package input must be a regular file")
    if not 0 <= metadata.st_size <= MAX_INPUT_BYTES:
        raise ValueError("package input has an unsafe size")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        raise ValueError("package input changed while it was read")
    return data


def _reject_symlinked_parents(source: Path, path: Path) -> None:
    current = source
    for part in path.relative_to(source).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise ValueError("package input must not be beneath a symbolic link")


def _python_sources(source: Path) -> list[Path]:
    root = source / "src/litechecker"
    _require_real_directory(root, "Python source directory")
    selected: list[Path] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in directory_names:
            if (current / name).is_symlink():
                raise ValueError("package input must not be a symbolic link")
        for name in file_names:
            candidate = current / name
            if candidate.is_symlink():
                raise ValueError("package input must not be a symbolic link")
            if candidate.suffix == ".py":
                selected.append(candidate)
    return sorted(selected, key=lambda path: path.relative_to(source).as_posix())


def _strip_markdown(markdown: str) -> str:
    lines: list[str] = []
    for source_line in markdown.splitlines():
        line = source_line.strip()
        if not line:
            if lines and lines[-1]:
                lines.append("")
            continue
        line = re.sub(r"^#{1,6}\s+", "", line)
        line = re.sub(r"^[-*]\s+", "- ", line)
        line = re.sub(r"\[([^]]+)]\([^)]+\)", r"\1", line)
        line = line.replace("**", "").replace("`", "")
        lines.append(line)
    while lines and not lines[-1]:
        lines.pop()
    return "\r\n".join(lines) + "\r\n"


def _starter_from_document(payload: bytes) -> bytes:
    try:
        document = payload.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("WINDOWS-TRIAL.md must be UTF-8") from error
    marker = "## \u041a\u0440\u0430\u0442\u043a\u0430\u044f \u043f\u0430\u043c\u044f\u0442\u043a\u0430 \u0434\u043b\u044f \u0444\u0430\u0439\u043b\u0430 \u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c"
    if marker in document:
        section = document.split(marker, 1)[1]
        section = re.split(r"(?m)^##\s+", section, maxsplit=1)[0]
    else:
        section = document
    text = _strip_markdown(section)
    if not text.strip():
        raise ValueError("WINDOWS-TRIAL.md does not contain starter guidance")
    return b"\xef\xbb\xbf" + text.encode("utf-8")


def _contents(source: Path) -> dict[str, bytes]:
    _require_real_directory(source, "source root")
    contents: dict[str, bytes] = {}
    for input_name, destination in EXACT_INPUTS.items():
        path = source / input_name
        _reject_symlinked_parents(source, path)
        contents[destination] = _read_regular(path)
    document_path = source / "WINDOWS-TRIAL.md"
    _reject_symlinked_parents(source, document_path)
    document = _read_regular(document_path)
    contents["\u041d\u0410\u0427\u041d\u0418\u0422\u0415-\u0417\u0414\u0415\u0421\u042c.txt"] = _starter_from_document(document)
    contents["_app/README.md"] = BUILD_README
    for path in _python_sources(source):
        relative = path.relative_to(source).as_posix()
        contents["_app/" + relative] = _read_regular(path)
    return contents


def _validate_output(output: Path) -> None:
    if output.suffix.lower() != ".zip":
        raise ValueError("output must have a .zip suffix")
    if output.is_symlink():
        raise ValueError("output must not be a symbolic link")
    if output.exists() and not output.is_file():
        raise ValueError("output must be a regular file")
    checksum = output.with_suffix(".zip.sha256")
    if checksum.is_symlink():
        raise ValueError("output checksum must not be a symbolic link")
    if checksum.exists() and not checksum.is_file():
        raise ValueError("output checksum must be a regular file")
    existing = output.parent
    while not existing.exists() and existing != existing.parent:
        existing = existing.parent
    if existing.is_symlink() or not existing.is_dir():
        raise ValueError("output directory must be a real directory")


def _write_archive(path: Path, contents: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative_name in sorted(contents):
            info = zipfile.ZipInfo(PREFIX + relative_name, date_time=FIXED_ZIP_TIME)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, contents[relative_name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _verify_archive(path: Path, contents: dict[str, bytes]) -> None:
    expected = [PREFIX + name for name in sorted(contents)]
    with zipfile.ZipFile(path) as archive:
        if archive.namelist() != expected or archive.testzip() is not None:
            raise ValueError("archive verification failed")
        for name in sorted(contents):
            if archive.read(PREFIX + name) != contents[name]:
                raise ValueError("archive content verification failed")


def _temporary_file(parent: Path, prefix: str) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=prefix, dir=parent)
    os.close(descriptor)
    return Path(name)


def build_package(source_root: Path, output_path: Path) -> PackageResult:
    source = Path(source_root).absolute()
    output = Path(output_path).absolute()
    _validate_output(output)
    contents = _contents(source)
    output.parent.mkdir(parents=True, exist_ok=True)
    archive_stage = _temporary_file(output.parent, ".windows-trial-archive-")
    checksum = output.with_suffix(".zip.sha256")
    checksum_stage: Path | None = None
    try:
        _write_archive(archive_stage, contents)
        _verify_archive(archive_stage, contents)
        digest = hashlib.sha256(archive_stage.read_bytes()).hexdigest()
        checksum_stage = _temporary_file(output.parent, ".windows-trial-checksum-")
        checksum_stage.write_text(f"{digest}  {output.name}\n", encoding="ascii", newline="\n")
        os.replace(archive_stage, output)
        os.replace(checksum_stage, checksum)
    finally:
        archive_stage.unlink(missing_ok=True)
        if checksum_stage is not None:
            checksum_stage.unlink(missing_ok=True)
    return PackageResult(output, checksum, digest, len(contents))


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="explicit destination .zip path")
    parser.add_argument("--source-root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    result = build_package(arguments.source_root, arguments.output)
    print(f"archive={result.archive} files={result.files} bytes={result.archive.stat().st_size}")
    print(f"sha256={result.sha256}")


if __name__ == "__main__":
    main()
