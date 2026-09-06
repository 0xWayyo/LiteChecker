"""User intent and one per-installation Windows logon shortcut.

The shortcut uses the retained baseline menu ABI. It therefore still selects
the current signed release after updates and never points into cleanup storage.
Opening that menu restores intent before asking for input.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

from filelock import FileLock

from litechecker.update_launcher import checked_path, runtime_python
from litechecker.windows_process_state import NONCE, clean_environment, control_path, read_record, safe_root, write_record


def requested(root: Path) -> bool:
    state = read_record(safe_root(root), "desired-running.json")
    if state is None:
        return False
    if set(state) != {"running"} or type(state["running"]) is not bool:
        raise ValueError("invalid-startup-intent")
    return state["running"]


def _intent_lock(root: Path):
    path = control_path(root, "intent.lock")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    return FileLock(path, timeout=25, mode=0o600, preserve_lock_file=True)


def remember(root: Path, running: bool, *, only_if_missing: bool = False) -> bool | None:
    """Persist before touching the OS; a leftover shortcut must honor Stop."""
    if type(running) is not bool:
        raise ValueError("invalid-startup-intent")
    root = safe_root(root)
    with _intent_lock(root):
        if only_if_missing and read_record(root, "desired-running.json") is not None:
            return None
        write_record(root, "desired-running.json", {"running": running})
        if not running:
            pending = read_record(root, "pending-supervisor.json")
            instance = pending.get("instance") if pending else None
            if isinstance(instance, str) and NONCE.fullmatch(instance):
                # The baseline supervisor already understands this stop ABI,
                # even if it has not published supervisor.json yet.
                write_record(root, "supervisor-stop.json", {"instance": instance})
        try:
            set_autostart(root, running)
            return True
        except Exception:
            # Monitoring remains controllable when OS policy denies startup changes.
            # No exception text: paths/configuration must not leak to reports.
            return False


def reserve_start(root: Path, instance: str) -> bool:
    """Make a future supervisor addressable by Stop before process creation."""
    root = safe_root(root)
    if not isinstance(instance, str) or NONCE.fullmatch(instance) is None:
        raise ValueError("invalid-startup-instance")
    with _intent_lock(root):
        if not requested(root):
            return False
        write_record(root, "pending-supervisor.json", {"instance": instance})
        return True


def shortcut_spec(root: Path) -> dict[str, str]:
    root = safe_root(root)
    python = runtime_python(root, system="Windows")
    entry = checked_path(root, root / "scripts/windows-app-entry.py", regular=True)
    identity = hashlib.sha256(os.path.normcase(str(root)).encode("utf-8")).hexdigest()[:16]
    return {
        "name": f"LiteChecker-{identity}.lnk",
        "target": str(python),
        "arguments": subprocess.list2cmdline(["-I", "-B", str(entry), "menu", "--root", str(root)]),
        "working_directory": str(root),
    }


# No shell interpolation of paths. A shortcut supports long/Unicode paths and
# stores arguments separately (unlike the 260-character Run-key command limit).
_SHORTCUT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$spec = $env:LITECHECKER_STARTUP_SPEC | ConvertFrom-Json
$shell = New-Object -ComObject WScript.Shell
$folder = $shell.SpecialFolders.Item('Startup')
if ([string]::IsNullOrWhiteSpace($folder)) { throw 'Startup folder unavailable' }
$parent = Get-Item -LiteralPath $folder -Force
while ($null -ne $parent) {
    if (($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe startup folder' }
    $parent = $parent.Parent
}
$path = Join-Path $folder $spec.name
$owner = 'LiteChecker startup v1'
if (Test-Path -LiteralPath $path) {
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unsafe shortcut' }
    $old = $shell.CreateShortcut($path)
    if ($old.Description -cne $owner -or $old.TargetPath -ine $spec.target -or $old.Arguments -cne $spec.arguments) { throw 'Unowned shortcut' }
    if (-not $spec.enabled) { Remove-Item -LiteralPath $path -Force }
    exit 0
}
if (-not $spec.enabled) { exit 0 }
$temporary = Join-Path $folder ('LiteChecker-' + [guid]::NewGuid().ToString('N') + '.lnk')
try {
    $shortcut = $shell.CreateShortcut($temporary)
    $shortcut.TargetPath = $spec.target
    $shortcut.Arguments = $spec.arguments
    $shortcut.WorkingDirectory = $spec.working_directory
    $shortcut.Description = $owner
    $shortcut.WindowStyle = 7
    $shortcut.Save()
    # Never replace an entry created concurrently by somebody else.
    [IO.File]::Move($temporary, $path)
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
"""


def set_autostart(root: Path, enabled: bool) -> None:
    from litechecker.windows_update import powershell_path

    if os.name != "nt" or type(enabled) is not bool:
        raise RuntimeError("windows-startup-unavailable")
    spec = {**shortcut_spec(root), "enabled": enabled}
    environment = clean_environment()
    environment["LITECHECKER_STARTUP_SPEC"] = json.dumps(spec, ensure_ascii=True)
    result = subprocess.run(
        [str(powershell_path()), "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
         base64.b64encode(_SHORTCUT_SCRIPT.encode("utf-16le")).decode("ascii")],
        env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, timeout=20, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode:
        raise RuntimeError("windows-startup-unavailable")
