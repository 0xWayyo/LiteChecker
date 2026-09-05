#!/usr/bin/env python3
"""Run the bundled Windows trial source without installing the local project."""

from __future__ import annotations

from pathlib import Path
import sys


def _bundled_source() -> Path:
    entry = Path(__file__)
    if entry.is_symlink():
        raise RuntimeError("Windows trial entry must be a regular file")
    source = entry.resolve(strict=True).parent.parent / "src"
    if source.is_symlink() or source.is_junction() or not source.is_dir():
        raise RuntimeError("Bundled Windows trial source is unsafe or missing")
    return source.resolve(strict=True)


def run() -> int:
    sys.path.insert(0, str(_bundled_source()))
    from litechecker.windows_trial import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
