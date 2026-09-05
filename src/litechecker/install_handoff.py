"""Leave one macOS management launcher after a proven native installation."""

from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import unicodedata

from litechecker.native_runtime import read_bounded_regular, validate_native_runtime
from litechecker.update_launcher import checked_path


MANIFEST = "CONTENTS.sha256.json"
LAUNCHER = "LiteChecker.command"
MAX_FILES = 2048
MAX_FILE_BYTES = 32 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PRIVATE_COMPONENTS = frozenset(
    {
        ".git",
        ".native-direct",
        ".updates",
        ".updater-runtime",
        ".venv",
        "__pycache__",
        "runtime",
        "secrets",
        "state",
        "venv",
    }
)
PRIVATE_FILES = frozenset(
    {
        "agent_token",
        "native-settings.json",
        "state_key",
        "subscription_url",
        "telegram_bot_token",
        "telegram_proxy_url",
        "update_signing_key",
    }
)


class HandoffRefusal(ValueError):
    """The source cannot be proven safe to clean."""


def _result(
    *, ok: bool, cleaned: bool, launcher: Path | None, created: bool,
    reason: str, removed_files: int = 0, removed_directories: int = 0,
    partial_cleanup: bool = False,
) -> dict:
    return {
        "ok": ok,
        "cleaned": cleaned,
        "launcher": str(launcher) if launcher is not None else None,
        "launcher_created": created,
        "reason": reason,
        "removed_files": removed_files,
        "removed_directories": removed_directories,
        "partial_cleanup": partial_cleanup,
    }


def _canonical_directory(path: Path, label: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute() or any(part in {".", ".."} for part in candidate.parts):
        raise HandoffRefusal(f"{label} path must be absolute and canonical")
    current = Path(candidate.anchor)
    try:
        for component in candidate.parts[1:]:
            current /= component
            if current.is_symlink():
                raise HandoffRefusal(f"{label} path must not contain symbolic links")
        resolved = candidate.resolve(strict=True)
        metadata = candidate.stat()
    except HandoffRefusal:
        raise
    except OSError as exc:
        raise HandoffRefusal(f"{label} directory is missing or unsafe") from exc
    if resolved != candidate or not stat.S_ISDIR(metadata.st_mode):
        raise HandoffRefusal(f"{label} path must be a real canonical directory")
    if os.name == "posix" and metadata.st_uid != os.geteuid():
        raise HandoffRefusal(f"{label} directory owner is unsafe")
    return resolved


def _owned_regular(root: Path, relative: str, *, private: bool = False) -> bytes:
    path = checked_path(root, root / relative, regular=True)
    data = read_bounded_regular(path, private=private)
    metadata = path.stat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise HandoffRefusal("installed root proof is not owner-controlled")
    return data


def _validate_installed_root(root: Path) -> None:
    _owned_regular(root, "scripts/control.sh")
    _owned_regular(root, "INSTALL.command")
    settings = _owned_regular(root, "native-settings.json", private=True)
    try:
        parsed = json.loads(settings)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise HandoffRefusal("installed native settings are invalid") from exc
    if not isinstance(parsed, dict):
        raise HandoffRefusal("installed native settings are invalid")
    validate_native_runtime(root)


def _create_launcher(source: Path, root: Path) -> Path:
    launcher = source / LAUNCHER
    control = root / "scripts/control.sh"
    body = (
        "#!/bin/bash\n"
        f"export LITECHECKER_NATIVE_ROOT={shlex.quote(str(root))}\n"
        f"exec /bin/bash {shlex.quote(str(control))} menu\n"
    ).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(launcher, flags, 0o700)
    except FileExistsError as exc:
        raise HandoffRefusal("management launcher already exists and was not overwritten") from exc
    except OSError as exc:
        raise HandoffRefusal("management launcher could not be created safely") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o700)
            stream.write(body)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            launcher.unlink()
        except OSError:
            pass
        raise HandoffRefusal("management launcher could not be written safely") from None
    return launcher


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise HandoffRefusal("content manifest contains duplicate entries")
        value[key] = item
    return value


def _manifest_path(name: str) -> PurePosixPath:
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or "\x00" in name
        or "//" in name
        or len(name.encode("utf-8")) > 1024
    ):
        raise HandoffRefusal("content manifest contains an unsafe path")
    path = PurePosixPath(name)
    if not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise HandoffRefusal("content manifest contains an unsafe path")
    folded = [unicodedata.normalize("NFC", part).casefold() for part in path.parts]
    if ".git" in folded:
        raise HandoffRefusal("git checkout cleanup is forbidden")
    basename = folded[-1]
    private_environment = basename == ".env" or basename.startswith(".env.")
    if any(part in PRIVATE_COMPONENTS for part in folded) or basename in PRIVATE_FILES or private_environment:
        raise HandoffRefusal("private data manifest is not a public bundle")
    for part in path.parts:
        if (
            len(part.encode("utf-8")) > 255
            or part.endswith((" ", "."))
            or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
        ):
            raise HandoffRefusal("content manifest contains an unsafe path")
    if name in {MANIFEST, LAUNCHER}:
        raise HandoffRefusal("content manifest contains a managed path")
    return path


def _read_manifest(source: Path) -> tuple[dict[str, str], str]:
    path = source / MANIFEST
    try:
        raw = read_bounded_regular(path)
        metadata = path.stat()
    except (OSError, ValueError) as exc:
        raise HandoffRefusal("public content manifest is missing or unsafe") from exc
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
        raise HandoffRefusal("public content manifest owner or permissions are unsafe")
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except HandoffRefusal:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HandoffRefusal("public content manifest is invalid") from exc
    if not isinstance(manifest, dict) or not 1 <= len(manifest) <= MAX_FILES:
        raise HandoffRefusal("public content manifest is invalid")
    normalized: set[str] = set()
    for name, digest in manifest.items():
        if not isinstance(name, str) or not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise HandoffRefusal("public content manifest entry is invalid")
        relative = _manifest_path(name)
        folded = unicodedata.normalize("NFC", relative.as_posix()).casefold()
        if folded in normalized:
            raise HandoffRefusal("content manifest contains colliding paths")
        normalized.add(folded)
    for required in ("INSTALL.command", "scripts/control.sh"):
        if required not in manifest:
            raise HandoffRefusal("content manifest does not prove the installed controls")
    return manifest, hashlib.sha256(raw).hexdigest()


def _digest_regular(root: Path, relative: str) -> str:
    path = checked_path(root, root / relative, regular=True)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not 0 <= metadata.st_size <= MAX_FILE_BYTES
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise HandoffRefusal("payload file is not immutable owner-controlled content")
        digest = hashlib.sha256()
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise HandoffRefusal("payload file changed while being verified")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise HandoffRefusal("payload file changed while being verified")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def _scan_source(source: Path, manifest: dict[str, str], launcher: Path) -> tuple[set[str], set[str]]:
    expected_files = set(manifest) | {MANIFEST, launcher.name}
    expected_directories = {
        PurePosixPath(name).parent.as_posix()
        for name in manifest
        if PurePosixPath(name).parent != PurePosixPath(".")
    }
    expected_directories |= {
        parent.as_posix()
        for name in manifest
        for parent in PurePosixPath(name).parents
        if parent != PurePosixPath(".")
    }
    observed_files: set[str] = set()
    observed_directories: set[str] = set()
    for directory, dirnames, filenames in os.walk(source, topdown=True, followlinks=False):
        base = Path(directory)
        for name in dirnames:
            path = base / name
            relative = path.relative_to(source).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise HandoffRefusal("source contains a symbolic link")
            if not stat.S_ISDIR(metadata.st_mode):
                raise HandoffRefusal("source contains a non-directory entry")
            if ".git" in (part.casefold() for part in Path(relative).parts):
                raise HandoffRefusal("git checkout cleanup is forbidden")
            observed_directories.add(relative)
        for name in filenames:
            path = base / name
            relative = path.relative_to(source).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise HandoffRefusal("source contains a symbolic link")
            if not stat.S_ISREG(metadata.st_mode):
                raise HandoffRefusal("source contains a non-regular file")
            if ".git" in (part.casefold() for part in Path(relative).parts):
                raise HandoffRefusal("git checkout cleanup is forbidden")
            observed_files.add(relative)
    unknown_files = observed_files - expected_files
    unknown_files = {name for name in unknown_files if PurePosixPath(name).name != ".DS_Store"}
    if unknown_files:
        raise HandoffRefusal("source contains an unknown extra file")
    if expected_files - observed_files:
        raise HandoffRefusal("source payload inventory is incomplete")
    if observed_directories - expected_directories:
        raise HandoffRefusal("source contains an unknown extra directory")
    return observed_files, observed_directories


def _validate_bundle(
    source: Path, root: Path, launcher: Path
) -> tuple[dict[str, str], set[str], str]:
    manifest, manifest_digest = _read_manifest(source)
    _, directories = _scan_source(source, manifest, launcher)
    for name, expected in manifest.items():
        try:
            actual = _digest_regular(source, name)
        except (OSError, ValueError) as exc:
            raise HandoffRefusal("source payload file is missing or unsafe") from exc
        if not hmac.compare_digest(actual, expected):
            raise HandoffRefusal("source payload hash changed after packaging")
    for name in manifest:
        installed = root / name
        if installed.exists() or installed.is_symlink():
            try:
                actual = _digest_regular(root, name)
            except (OSError, ValueError) as exc:
                raise HandoffRefusal("corresponding installed payload is unsafe") from exc
            if not hmac.compare_digest(actual, manifest[name]):
                raise HandoffRefusal("source payload does not match its installed copy")
    return manifest, directories, manifest_digest


def _cleanup_failure(
    launcher: Path, removed_files: int, removed_directories: int, reason: str
) -> dict:
    return _result(
        ok=False,
        cleaned=False,
        launcher=launcher,
        created=True,
        reason=reason,
        removed_files=removed_files,
        removed_directories=removed_directories,
        partial_cleanup=removed_files > 0 or removed_directories > 0,
    )


def _cleanup(
    source: Path,
    manifest: dict[str, str],
    directories: set[str],
    launcher: Path,
    manifest_digest: str,
) -> dict:
    removed_files = 0
    removed_directories = 0
    targets = [(name, manifest[name]) for name in sorted(manifest)]
    targets.append((MANIFEST, manifest_digest))
    for name, expected in targets:
        try:
            actual = _digest_regular(source, name)
        except KeyboardInterrupt:
            return _cleanup_failure(
                launcher,
                removed_files,
                removed_directories,
                "cleanup interrupted; the current target and launcher were preserved",
            )
        except (OSError, ValueError):
            return _cleanup_failure(
                launcher,
                removed_files,
                removed_directories,
                "partial cleanup stopped because a target became unsafe; the target was preserved",
            )
        if not hmac.compare_digest(actual, expected):
            return _cleanup_failure(
                launcher,
                removed_files,
                removed_directories,
                "partial cleanup stopped because a target changed; the changed file was preserved",
            )
        try:
            target = source / name
            target.unlink()
            removed_files += 1
        except KeyboardInterrupt:
            return _cleanup_failure(
                launcher,
                removed_files,
                removed_directories,
                "cleanup interrupted; the current target and launcher were preserved",
            )
        except OSError:
            return _cleanup_failure(
                launcher,
                removed_files,
                removed_directories,
                "partial cleanup stopped after a filesystem error; the target and launcher were preserved",
            )
    try:
        for name in sorted(directories, key=lambda item: (item.count("/"), item), reverse=True):
            try:
                (source / name).rmdir()
                removed_directories += 1
            except OSError as exc:
                if exc.errno == errno.ENOTEMPTY:
                    continue
                raise
    except KeyboardInterrupt:
        return _cleanup_failure(
            launcher,
            removed_files,
            removed_directories,
            "cleanup interrupted while removing empty directories; the launcher was preserved",
        )
    except OSError:
        return _cleanup_failure(
            launcher,
            removed_files,
            removed_directories,
            "partial cleanup stopped after a filesystem error; the valid management launcher was preserved",
        )
    return _result(
        ok=True,
        cleaned=True,
        launcher=launcher,
        created=True,
        reason="pristine public install payload removed; management launcher preserved",
        removed_files=removed_files,
        removed_directories=removed_directories,
    )


def finish_handoff(source: Path, root: Path) -> dict:
    """Create the stable launcher and clean only an exact pristine public bundle."""

    launcher: Path | None = None
    created = False
    try:
        if sys.platform != "darwin":
            raise HandoffRefusal("install handoff cleanup is supported only on macOS")
        source_path = _canonical_directory(Path(source), "source")
        root_path = _canonical_directory(Path(root), "installed root")
        if source_path == root_path or source_path in root_path.parents or root_path in source_path.parents:
            raise HandoffRefusal("source and installed root must be distinct non-nested paths")
        try:
            _validate_installed_root(root_path)
        except HandoffRefusal:
            raise
        except Exception as exc:
            raise HandoffRefusal("installed root proof is incomplete or unsafe") from exc
        launcher = _create_launcher(source_path, root_path)
        created = True
        manifest, directories, manifest_digest = _validate_bundle(
            source_path, root_path, launcher
        )
        # Inventory validation is deliberately single-pass. Each exact target is
        # checked again in _cleanup immediately before unlink, which closes the
        # user-edit window without pretending a duplicate preflight is atomic.
        return _cleanup(
            source_path, manifest, directories, launcher, manifest_digest
        )
    except HandoffRefusal as exc:
        return _result(
            ok=False,
            cleaned=False,
            launcher=launcher,
            created=created,
            reason=str(exc),
        )
    except Exception:
        return _result(
            ok=False,
            cleaned=False,
            launcher=launcher,
            created=created,
            reason="handoff refused because safety validation could not complete",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    arguments = parser.parse_args(argv)
    result = finish_handoff(arguments.source, arguments.root)
    if result["ok"]:
        print(
            "Установка завершена. Проверенные файлы установщика удалены; "
            "при необходимости их можно снова скачать с GitHub."
        )
        print(f"Управление LiteChecker: {result['launcher']}")
    else:
        if result["partial_cleanup"]:
            message = (
                "Очистка остановлена: часть проверенных файлов уже удалена, "
                "остальные сохранены. Установленный LiteChecker не изменён."
            )
        else:
            message = (
                "Файлы установщика сохранены: безопасная очистка не подтверждена "
                "(файлы могли быть изменены, содержать приватные данные или неизвестные элементы)."
            )
        print(message, file=sys.stderr)
        if result["launcher"] is not None:
            print(f"Управление LiteChecker: {result['launcher']}", file=sys.stderr)
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
