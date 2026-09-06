"""The release gate must import the extracted matching profile, not the checkout."""
import os
from pathlib import Path
import subprocess
import sys

from litechecker.distribution import host_platform

ROOT = Path(__file__).resolve().parents[1]


def test_matching_profile_gate_builds_extracts_and_validates_offline(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / "scripts/check_release_artifacts.py"),
                             "--platform-smoke", str(tmp_path / "gate")],
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"profile={host_platform()} offline-import=ok" in result.stdout
    root = tmp_path / "gate/public/LiteChecker"
    if os.name == "nt":
        root /= "_app"
    assert (root / "src/litechecker/runtime_lease.py").is_file()
    assert not (root / "tests").exists()
