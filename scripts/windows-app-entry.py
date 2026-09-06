#!/usr/bin/env python3
"""Dispatch trusted bundled Windows application commands."""

from __future__ import annotations

import os
from pathlib import Path
import sys


_COMMANDS = {
    "menu": ("litechecker.windows_app", "main"),
    "supervisor": ("litechecker.windows_control", "main"),
    "worker": ("litechecker.windows_worker", "main"),
}


def _bundled_source() -> Path:
    entry = Path(__file__).absolute()
    for path in (entry, *entry.parents):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError("unsafe Windows entry")
    release = entry.resolve(strict=True).parent.parent
    source = release / "src"
    for path in (source, release, *release.parents):
        if path.is_symlink() or path.is_junction():
            raise RuntimeError("unsafe bundled source")
    if not source.is_dir():
        raise RuntimeError("missing bundled source")
    return source.resolve(strict=True)


def run(argv=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in _COMMANDS:
        print("Unknown Windows application action", file=sys.stderr)
        return 2
    for name in tuple(os.environ):
        if name.upper().startswith("PYTHON"):
            os.environ.pop(name, None)
    sys.path.insert(0, str(_bundled_source()))
    if arguments[0] == "menu":
        from litechecker.runtime_lease import launch_menu
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--root", type=Path, required=True)
        args = parser.parse_args(arguments[1:])
        result = launch_menu(args.root.absolute(), windows=True)
        if result is not None:
            return result
    # Supervisor ABI stays at the bootstrap; a worker entry belongs to its
    # already selected release. Only menu dispatch resolves a new active UI.
    module_name, function_name = _COMMANDS[arguments.pop(0)]
    module = __import__(module_name, fromlist=[function_name])
    result = getattr(module, function_name)(arguments)
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(run())
