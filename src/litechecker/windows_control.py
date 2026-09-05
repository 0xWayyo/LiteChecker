"""Stable user-mode supervisor: owned worker tree, explicit stop, signed updates."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import secrets
import subprocess
import sys
import time

from filelock import FileLock, Timeout

from litechecker.update_launcher import select_release
from litechecker.windows_job import WindowsJob
from litechecker.windows_process_state import (
    NONCE, command, control_path, process_exists, process_matches as _process_matches, python_launch,
    process_record, read_record, release_path, safe_root, version, write_record,
)


_START_TIMEOUT = 25.0
_STOP_TIMEOUT = 30.0
_WORKER_STOP_TIMEOUT = 10.0


def status(root: Path) -> dict:
    """Observe without creating state, acquiring locks, or trusting a bare PID."""
    try:
        root = safe_root(root)
        current = version(select_release(root))
        record = read_record(root, "supervisor.json")
        if record is None:
            return {"state": "stopped", "version": current}
        if not process_exists(record):
            result = {"state": "stopped", "version": current}
            if record.get("last_error") in {"worker-exited", "supervisor-failed"}:
                result["last_error"] = record["last_error"]
            return result
        if not _process_matches(root, record, "supervisor"):
            return {"state": "unknown", "version": current, "last_error": "process-identity-mismatch"}
        worker = read_record(root, "worker.json")
        ready = (worker and worker.get("phase") == "ready"
                 and worker.get("supervisor_instance") == record.get("instance")
                 and _process_matches(root, worker, "worker"))
        result = {"state": "running" if ready else "starting", "version": worker.get("version") if ready else current,
                  "pid": record["pid"]}
        if record.get("phase") == "stopping":
            result["phase"] = "stopping"
        return result
    except Exception:
        return {"state": "unknown", "version": None, "last_error": "control-state-unavailable"}


def _ensure_control(root):
    root = safe_root(root)
    (root / "windows-state").mkdir(mode=0o700, exist_ok=True)
    control_path(root, "start.lock").parent.mkdir(mode=0o700, exist_ok=True)
    return root


async def _spawn_supervisor(root, instance):
    if sys.platform != "win32":
        raise RuntimeError("native-windows-required")
    executable, environment = python_launch(root)
    return subprocess.Popen(command(root, root, "supervisor", instance),
                            executable=str(executable),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=environment, close_fds=True,
                            creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP)


async def start(root: Path) -> dict:
    try:
        root = _ensure_control(root)
        lock = FileLock(control_path(root, "start.lock"), timeout=0, mode=0o600, preserve_lock_file=True)
        with lock:
            observed = status(root)
            if observed["state"] in {"running", "starting"}:
                return {"status": "already-running", **observed}
            if observed["state"] == "unknown":
                return {"status": "failed", **observed}
            instance = secrets.token_hex(16)
            process = await _spawn_supervisor(root, instance)
            deadline = time.monotonic() + _START_TIMEOUT
            while time.monotonic() < deadline:
                observed = status(root)
                record = read_record(root, "supervisor.json")
                if record and record.get("instance") == instance and observed["state"] == "running":
                    return {"status": "started", **observed}
                if process.poll() is not None:
                    return {"status": "failed", **observed, "error": "supervisor-start-failed"}
                await asyncio.sleep(0.1)
            return {"status": "starting", **observed}
    except Timeout:
        observed = status(root)
        return {"status": "already-running" if observed["state"] in {"running", "starting"} else "busy", **observed}
    except Exception:
        return {"status": "failed", "error": "supervisor-start-failed", **status(root)}


async def stop(root: Path) -> dict:
    try:
        root = safe_root(root)
        observed = status(root)
        if observed["state"] == "stopped":
            return {"status": "stopped", **observed}
        record = read_record(root, "supervisor.json")
        if not record or not _process_matches(root, record, "supervisor"):
            return {"status": "failed", **observed, "error": "process-identity-mismatch"}
        write_record(root, "supervisor-stop.json", {"instance": record["instance"]})
        deadline = time.monotonic() + _STOP_TIMEOUT
        while time.monotonic() < deadline:
            if not _process_matches(root, record, "supervisor"):
                return {"status": "stopped", **status(root)}
            await asyncio.sleep(0.1)
        # A signed update may still be completing its bounded transaction.
        # Never call this stopped and never force-kill an updating supervisor.
        return {"status": "stopping", **status(root)}
    except Exception:
        return {"status": "failed", "error": "supervisor-stop-failed", **status(root)}


async def request_update(root: Path) -> dict:
    try:
        root = safe_root(root)
        observed = status(root)
        if observed["state"] == "stopped":
            from litechecker.windows_update import WindowsUpdateAdapter
            from litechecker.updater import check_for_update
            _ensure_control(root)
            with FileLock(control_path(root, "start.lock"), timeout=0, mode=0o600, preserve_lock_file=True):
                # Freeze stopped intent across prepare/activate; Start uses this
                # same lock and cannot sneak a worker into a stopped transaction.
                if status(root)["state"] != "stopped":
                    return {"status": "busy"}
                return await check_for_update(root, WindowsUpdateAdapter(root), force=True)
        record = read_record(root, "supervisor.json")
        if not record or not _process_matches(root, record, "supervisor"):
            return {"status": "failed", "error": "process-identity-mismatch"}
        request = secrets.token_hex(16)
        write_record(root, "update-request.json", {"instance": record["instance"], "request": request})
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            reply = read_record(root, "update-result.json")
            if reply and reply.get("instance") == record["instance"] and reply.get("request") == request:
                return reply["result"]
            if not _process_matches(root, record, "supervisor"):
                return {"status": "failed", "error": "supervisor-exited"}
            await asyncio.sleep(0.2)
        return {"status": "requested"}
    except Timeout:
        return {"status": "busy"}
    except Exception:
        return {"status": "failed", "error": "windows-update-request-failed"}


class Supervisor:
    def __init__(self, root: Path, instance: str):
        self.baseline = self.root = safe_root(root)
        if NONCE.fullmatch(instance) is None:
            raise ValueError("invalid-supervisor-instance")
        self.instance, self.release = instance, self.root
        self.stop_requested = False
        self.worker = self.job = None
        self.worker_instance = None
        self._worker_lock = asyncio.Lock()
        self._record = None

    def is_running(self) -> bool:
        return self.worker is not None and self.worker.poll() is None

    def _publish(self, phase):
        if self._record is not None:
            self._record.update(phase=phase, version=version(self.release))
            write_record(self.root, "supervisor.json", self._record)

    async def _wait_exit(self, timeout):
        deadline = time.monotonic() + timeout
        while self.is_running() and time.monotonic() < deadline:
            await asyncio.sleep(0.05)
        return not self.is_running()

    async def _stop_worker(self):
        if self.is_running():
            write_record(self.root, "worker-stop.json", {"instance": self.worker_instance})
            if not await self._wait_exit(_WORKER_STOP_TIMEOUT):
                self.job.terminate()
                await self._wait_exit(5.0)
        if self.job is not None:
            try:
                # A dead worker is not proof that its descendants exited.
                if self.job.active_processes():
                    self.job.terminate()
                    deadline = time.monotonic() + 5.0
                    while self.job.active_processes() and time.monotonic() < deadline:
                        await asyncio.sleep(0.05)
                    if self.job.active_processes():
                        raise RuntimeError("worker-tree-stop-failed")
            finally:
                self.job.close()
        if self.is_running() and not await self._wait_exit(5.0):
            raise RuntimeError("worker-stop-failed")
        self.worker = self.job = None
        self.worker_instance = None

    async def _start_worker(self):
        if self.stop_requested:
            return
        self._publish("starting")
        instance = secrets.token_hex(16)
        job = WindowsJob()
        process = None
        try:
            executable, environment = python_launch(self.release)
            process = subprocess.Popen(command(self.root, self.release, "worker", instance),
                                       executable=str(executable),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       env=environment, close_fds=True,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            # Worker entry waits at the gate before config initialization or any
            # child process; it is safe to assign immediately after CreateProcess.
            job.assign(process.pid)
            self.worker, self.job, self.worker_instance = process, job, instance
            write_record(self.root, "worker-go.json", {"instance": instance, "supervisor_instance": self.instance})
            deadline = time.monotonic() + _START_TIMEOUT
            while self.is_running() and time.monotonic() < deadline:
                if self.stop_requested:
                    await self._stop_worker()
                    return
                record = read_record(self.root, "worker.json")
                if (record and record.get("instance") == instance and record.get("phase") == "ready"
                        and record.get("supervisor_instance") == self.instance
                        and _process_matches(self.root, record, "worker")):
                    self._publish("ready")
                    return
                await asyncio.sleep(0.05)
            raise RuntimeError("worker-start-failed")
        except BaseException:
            job.close()
            if process is not None and process.poll() is None:
                # This is the exact Popen we created, including assignment failure.
                process.kill()
                await asyncio.to_thread(process.wait, 5.0)
            self.worker = self.job = None
            raise

    async def activate_release(self, release: Path, running: bool):
        candidate = release_path(self.root, release)
        async with self._worker_lock:
            await self._stop_worker()
            self.release = candidate
            if running and not self.stop_requested:
                await self._start_worker()

    async def healthy_release(self, release: Path, running: bool) -> bool:
        if release_path(self.root, release) != self.release:
            return False
        if not running or self.stop_requested:
            return not self.is_running()
        record = read_record(self.root, "worker.json")
        return bool(self.is_running() and record and record.get("instance") == self.worker_instance
                    and record.get("phase") == "ready" and _process_matches(self.root, record, "worker"))

    async def _update(self, request=None):
        from litechecker.windows_update import WindowsUpdateAdapter
        from litechecker.updater import check_for_update
        result = await check_for_update(self.root, WindowsUpdateAdapter(self.root, host=self), force=request is not None)
        if request:
            write_record(self.root, "update-result.json", {"instance": self.instance, "request": request, "result": result})
        return result

    async def run(self):
        _ensure_control(self.root)
        lock = FileLock(control_path(self.root, "supervisor.lock"), timeout=0, mode=0o600, preserve_lock_file=True)
        with lock:
            self._record = process_record(self.root, self.root, "supervisor", self.instance)
            self._publish("starting")
            update = None
            next_update = time.monotonic()
            accepted_request = None
            try:
                await self.activate_release(select_release(self.root), True)
                while True:
                    stop = read_record(self.root, "supervisor-stop.json")
                    if stop and stop.get("instance") == self.instance:
                        self.stop_requested = True
                        self._publish("stopping")
                        async with self._worker_lock:
                            await self._stop_worker()
                        if update is not None:
                            await update  # Complete the signed transaction; activation observes stop intent.
                        break
                    if update is not None and update.done():
                        await update
                        update = None
                    if update is None:
                        if not self.is_running():
                            self._record["last_error"] = "worker-exited"
                            raise RuntimeError("worker-exited")
                        requested = read_record(self.root, "update-request.json")
                        request = (requested.get("request") if requested and requested.get("instance") == self.instance else None)
                        if not isinstance(request, str) or NONCE.fullmatch(request) is None or request == accepted_request:
                            request = None
                        if request or time.monotonic() >= next_update:
                            accepted_request = request or accepted_request
                            next_update = time.monotonic() + 3600
                            update = asyncio.create_task(self._update(request))
                    await asyncio.sleep(0.2)
            finally:
                self.stop_requested = True
                if update is not None and not update.done():
                    update.cancel()
                    await asyncio.gather(update, return_exceptions=True)
                async with self._worker_lock:
                    await self._stop_worker()
                self._publish("stopped")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--instance", required=True)
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        return 2
    try:
        asyncio.run(Supervisor(args.root, args.instance).run())
        return 0
    except (KeyboardInterrupt, asyncio.CancelledError):
        return 130
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
