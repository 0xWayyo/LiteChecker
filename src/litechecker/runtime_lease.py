"""Short dispatch serialization and exact live menu identities, never executable paths from state."""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parents[1]))

import psutil
from filelock import FileLock

from litechecker.update_launcher import checked_path, read_json, runtime_python, select_release, validate_baseline, LauncherError, VERSION

LIFETIME_MARKER = b"litechecker-menu-lifetime-v1\n"


def _lifetime_live(root: Path, path: Path) -> bool:
    """An inherited POSIX kernel lock covers a wizard surviving its Bash parent."""
    if os.name == "nt":
        return False
    if not path.exists():
        if path.is_symlink():
            raise ValueError("invalid-menu-lifetime")
        return False
    import fcntl
    checked_path(root, path, regular=True)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        details = os.fstat(fd)
        if (not stat.S_ISREG(details.st_mode) or details.st_uid != os.geteuid()
                or details.st_mode & 0o077 or details.st_nlink != 1
                or details.st_size != len(LIFETIME_MARKER)
                or os.read(fd, len(LIFETIME_MARKER) + 1) != LIFETIME_MARKER):
            raise ValueError("invalid-menu-lifetime")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False
    finally:
        os.close(fd)


def _create_lifetime(root: Path, nonce: str) -> int:
    import fcntl
    path = checked_path(root, root / ".updates" / f"menu-{nonce}.lock")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, LIFETIME_MARKER)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def dispatch_lock(root: Path):
    from litechecker.update_store import UpdateStore
    UpdateStore(root).ensure_layout()
    path = checked_path(root, root / ".updates/dispatch.lock")
    if path.exists():
        from litechecker.update_launcher import read_bytes
        read_bytes(root, path, 64)
    with FileLock(path, timeout=3, mode=0o600, preserve_lock_file=True):
        yield


def _release(root: Path, version: str | None) -> Path:
    if version is None:
        return checked_path(root, root)
    if type(version) is not str or VERSION.fullmatch(version) is None:
        raise ValueError("invalid-menu-release")
    release = checked_path(root, root / ".updates/releases" / version)
    from litechecker.update_store import OWNED_MARKER, OWNED_MARKER_BYTES
    from litechecker.update_launcher import read_bytes
    if read_bytes(root, release / OWNED_MARKER, 64) != OWNED_MARKER_BYTES:
        raise ValueError("invalid-menu-release")
    return release


def _command(root: Path, release: Path, gate: int, nonce: str, action: str) -> list[str]:
    helper = checked_path(release, release / "src/litechecker/runtime_lease.py", regular=True)
    return [str(runtime_python(release)), "-I", "-B", str(helper),
            str(root), release.name if release != root else "baseline", str(gate), nonce, action]


def _shell_command(root: Path, release: Path, action: str) -> list[str]:
    script = checked_path(release, release / "scripts/control.sh", regular=True)
    return ["/bin/bash", str(script), "--active-menu", str(root), action]


def live_versions(root: Path) -> set[str]:
    """Caller holds dispatch lock. Stale files never confer retention."""
    live = set()
    for path in (root / ".updates").glob("menu-*.json"):
        if re.fullmatch(r"menu-[a-f0-9]{32}\.json", path.name) is None:
            continue
        valid = False
        owned = False
        release = None
        try:
            record = read_json(root, path)
            if (set(record) != {"owner", "pid", "created", "version", "gate", "nonce", "action"}
                    or record["owner"] != "litechecker-menu-v1"):
                raise ValueError("invalid-menu-lease")
            owned = True
            pid, created, gate = record["pid"], record["created"], record["gate"]
            if (type(pid) is not int or pid <= 0 or type(gate) is not int or gate < 0
                    or type(created) not in (int, float) or not math.isfinite(created)
                    or record["nonce"] != path.stem.removeprefix("menu-")
                    or record["action"] not in {"menu", "folder", "settings"}):
                raise ValueError("invalid-menu-lease")
            release = _release(root, record["version"])
            process = psutil.Process(pid)
            if abs(process.create_time() - created) > .001 or process.status() == psutil.STATUS_ZOMBIE:
                raise ValueError("stale-menu-lease")
            expected = _command(root, release, gate, record["nonce"], record["action"])
            if os.name == "nt":
                from litechecker.windows_process_state import python_launch
                executable, _ = python_launch(release)
            else:
                executable = runtime_python(release).resolve(strict=True)
            # POSIX child performs exactly one exec (Python -> bash). Sample
            # around argv to avoid rejecting an identity across that transition.
            for _ in range(3):
                observed = process.exe()
                actual = process.cmdline()
                if observed == process.exe():
                    break
            else:
                raise ValueError("unstable-menu-process")
            valid = (os.path.normcase(observed) == os.path.normcase(str(executable))
                     and actual == expected)
            if os.name != "nt" and not valid:
                valid = (Path(observed).resolve() == Path("/bin/bash").resolve()
                         and actual == _shell_command(root, release, record["action"]))
            if valid and record["version"] is not None:
                live.add(record["version"])
        except (OSError, ValueError, TypeError, KeyError, psutil.Error):
            pass
        lock_path = path.with_suffix(".lock")
        if release is not None:
            try:
                if _lifetime_live(root, lock_path):
                    valid = True
                    if record["version"] is not None:
                        live.add(record["version"])
            except (OSError, ValueError):
                pass
        if owned and not valid and not path.is_symlink():
            path.unlink(missing_ok=True)
    # A launcher that died before JSON registration may leave an unlocked,
    # marked lock file. Such a file alone never retains any release.
    if os.name != "nt":
        for path in (root / ".updates").glob("menu-*.lock"):
            if re.fullmatch(r"menu-[a-f0-9]{32}\.lock", path.name) is None or path.with_suffix(".json").exists():
                continue
            try:
                if not _lifetime_live(root, path):
                    path.unlink(missing_ok=True)
            except (OSError, ValueError):
                pass
    return live


def launch_menu(root: Path, action: str = "menu", *, windows: bool = False) -> int | None:
    """Gate the actual menu until its exact identity is registered for cleanup."""
    if action not in {"menu", "folder", "settings"}:
        raise ValueError("invalid-menu-action")
    root = validate_baseline(root)
    process = None
    lease = None
    with dispatch_lock(root):
        validate_baseline(root)
        try:
            release = select_release(root)
        except LauncherError:
            print("Активная версия недоступна. Открыто базовое меню восстановления.", file=sys.stderr)
            release = root
        # Recovery anchors have no cleanup lifetime and may use a test/host interpreter.
        if release == root and windows:
            return None  # Stable entry executes the retained baseline after unlocking.
        read_gate, write_gate = os.pipe()
        nonce = uuid.uuid4().hex
        gate = read_gate
        lifetime = None
        kwargs = {}
        env = {key: value for key, value in os.environ.items()
               if not key.upper().startswith(("PYTHON", "PYLAUNCHER"))
               and key.upper() != "__PYVENV_LAUNCHER__"}
        try:
            if os.name == "nt":
                import msvcrt
                from litechecker.windows_process_state import python_launch
                gate = msvcrt.get_osfhandle(read_gate)
                os.set_handle_inheritable(gate, True)
                startup = subprocess.STARTUPINFO()
                startup.lpAttributeList = {"handle_list": [gate]}
                executable, env = python_launch(release)
                kwargs.update(startupinfo=startup, executable=str(executable))
            else:
                lifetime = _create_lifetime(root, nonce)
                # Bash's ordinary settings Python inherits this descriptor.
                # launchd/systemd/Docker services are created by their daemons,
                # so independent monitoring does not inherit this lifetime.
                kwargs["pass_fds"] = (read_gate, lifetime)
            command = _command(root, release, gate, nonce, action)
            process = subprocess.Popen(command, env=env, **kwargs)
            lease = root / ".updates" / f"menu-{nonce}.json"
            record = dict(owner="litechecker-menu-v1", pid=process.pid, created=psutil.Process(process.pid).create_time(),
                          version=release.name if release != root else None,
                          gate=gate, nonce=nonce, action=action)
            from litechecker.update_store import UpdateStore
            UpdateStore(root)._atomic_json(lease, record)
            os.write(write_gate, b"1")
        except BaseException:
            if process is not None:
                process.terminate()
                process.wait(timeout=5)
            raise
        finally:
            os.close(read_gate)
            os.close(write_gate)
            if lifetime is not None:
                os.close(lifetime)
    try:
        return process.wait()
    except KeyboardInterrupt:
        process.terminate()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=5)
    finally:
        if process.poll() is not None:
            with dispatch_lock(root):
                live_versions(root)


def _child(arguments: list[str]) -> int:
    root_text, version, gate_text, nonce, action = arguments
    gate = int(gate_text)
    if os.name == "nt":
        import msvcrt
        gate = msvcrt.open_osfhandle(gate, os.O_RDONLY)
    try:
        if os.read(gate, 1) != b"1":
            return 1  # Parent died before registration: never import the UI.
    finally:
        os.close(gate)
    root = Path(root_text)
    release = _release(root, None if version == "baseline" else version)
    if Path(__file__).resolve() != release / "src/litechecker/runtime_lease.py":
        raise ValueError("invalid-menu-child")
    record = read_json(root, root / ".updates" / f"menu-{nonce}.json")
    if record["pid"] != os.getpid() or record["nonce"] != nonce:
        raise ValueError("invalid-menu-child")
    if os.name == "nt":
        from litechecker.windows_app import main
        return main(["--root", str(root)])
    env = dict(os.environ, LITECHECKER_NATIVE_ROOT=str(root))
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    command = _shell_command(root, release, action)
    os.execve(command[0], command, env)
    return 1


if __name__ == "__main__":
    raise SystemExit(_child(sys.argv[1:]))
