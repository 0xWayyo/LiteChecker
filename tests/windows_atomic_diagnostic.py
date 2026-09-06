"""Exercise real Windows atomic writers against a disposable deny-delete reader.

No production state or network is touched. Output contains only fixed operation
labels, exception types/codes, timings and invariant booleans, never file paths,
configuration values or exception messages.
"""

import json
import os
from pathlib import Path
import tempfile
import time

from litechecker.state import _atomic_write_json
from litechecker.update_store import UpdateStore, default_install_state
from test_windows_update_native import _deny_delete
from windows_test_support import secure_test_directory


def _codes(error):
    result = []
    seen = set()
    while error is not None and id(error) not in seen and len(result) < 5:
        seen.add(id(error))
        result.append({"type": type(error).__name__,
                       "winerror": getattr(error, "winerror", None),
                       "errno": getattr(error, "errno", None)})
        error = error.__cause__ or error.__context__
    return result


def _probe(label, path, write, old_value, new_value):
    write(old_value)
    old_bytes = path.read_bytes()
    before = set(path.parent.iterdir())
    failure = []
    with _deny_delete(path):
        started = time.monotonic()
        try:
            write(new_value)
        except Exception as error:
            failure = _codes(error)
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        preserved = path.read_bytes() == old_bytes
        clean = set(path.parent.iterdir()) == before
    write(new_value)
    retry_ok = json.loads(path.read_bytes()) == new_value
    record = {
        "operation": label,
        "held_reader_failure": failure,
        "sharing_violation": any(item["winerror"] in (32, 33) for item in failure),
        "old_json_preserved": preserved,
        "own_temporaries_removed": clean,
        "unheld_retry_succeeded": retry_ok,
        "held_write_ms": elapsed_ms,
    }
    print(json.dumps(record, sort_keys=True), flush=True)
    # A native code other than 32/33 is reported, not assumed to be retryable.
    return any(type(item["winerror"]) is int for item in failure) and preserved and clean and retry_ok


def main():
    if os.name != "nt":
        print("Windows atomic diagnostic requires native Windows")
        return 2
    with tempfile.TemporaryDirectory(prefix="litechecker-atomic-diagnostic-") as temporary:
        root = Path(temporary) / "private-root"
        root.mkdir()
        secure_test_directory(root)
        control = root / "windows-state" / "control" / "supervisor.json"
        control_ok = _probe(
            "control-json", control, lambda value: _atomic_write_json(control, value),
            {"phase": "starting", "revision": 1}, {"phase": "ready", "revision": 2},
        )
        store = UpdateStore(root)
        old = default_install_state()
        new = {**old, "status": "updated"}
        update_ok = _probe("update-install-json", store.install_path, store.write_install, old, new)
        return 0 if control_ok and update_ok else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"diagnostic_failure": _codes(error)}, sort_keys=True))
        raise SystemExit(1) from None
