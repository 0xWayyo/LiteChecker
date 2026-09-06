"""Packaged recovery keeps the retained installation boundary after staging."""
import os
import subprocess

import pytest

from litechecker import distribution, updater
from litechecker.update_store import UpdateStore, validate_source_zip
from platform_package_support import extracted_profile
from test_active_menu import candidate_archive
from test_platform_distribution import install_attempt


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX recovery shell")


@pytest.mark.parametrize("platform", ["linux", "macos"])
@pytest.mark.parametrize("entry", ["baseline", "active-baseline", "active-candidate", "active-settings-menu"])
def test_packaged_recovery_uses_baseline_and_preserves_device_bytes(tmp_path, monkeypatch, platform, entry):
    # Regression: executing the staged installer loses the ZIP manifest and,
    # on Linux, derives the device root from .updates/releases/VERSION.
    source, _ = extracted_profile(tmp_path / "package", platform)
    root = source
    if platform == "macos":
        root = tmp_path / "installed"
        # Use the real installer inventory, stopping before runtime downloads
        # or launchd. In particular, installed macOS omits scripts/install.sh.
        installed = install_attempt(source, root, tmp_path)
        assert installed.returncode == 73, installed.stdout + installed.stderr
        assert not (root / "scripts/install.sh").exists()

    monkeypatch.setattr(distribution, "host_platform", lambda: platform)
    updater.initialize_channel(root, (root / "update-channel.json").read_bytes())
    store = UpdateStore(root)
    candidate = store.stage("0.7.0", validate_source_zip(candidate_archive(source, "0.7.0")))
    assert not (candidate / "CONTENTS.sha256.json").exists()
    state = store.read_install()
    state.update(active="0.7.0", highest_sequence=9, highest_digest="a" * 64)
    store.write_install(state)
    settings = "native-settings.json" if platform == "macos" else ".env.standalone"
    for name, data in {
        settings: b'{"fixture":"retained device settings"}\n' if platform == "macos" else b"LC_INTERVAL_SECONDS=600\n",
        "secrets/telegram_bot_token": b"synthetic-test-token\n",
        "secrets/subscription_url": b"https://fixture.invalid/subscription\n",
        "state/device-id": b"synthetic-device-id\n",
    }.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    bindir = tmp_path / "recovery-bin"
    bindir.mkdir()
    docker_log, forbidden_log = tmp_path / "docker-boundary", tmp_path / "forbidden-action"
    # Only host identity/service boundaries are doubles. Installer and menu
    # files, validation, source derivation and staged filesystem stay real.
    for name, body in {
        "uname": '#!/bin/sh\nprintf "%s\\n" "$FIXTURE_SYSTEM"\n',
        "docker": '#!/bin/sh\nprintf "%s|%s\\n" "$PWD" "$*" >> "$DOCKER_LOG"\nexit 73\n',
        "bash": '''#!/bin/sh
case "$1" in
    */run.sh)
        if [ "$2" = status ]; then printf 'exited\\n'; exit 0; fi
        printf '%s\\n' "$*" >> "$FORBIDDEN_LOG"; exit 74;;
    */native-direct.sh|*/prepare-updater.sh|*/update.sh)
        printf '%s\\n' "$*" >> "$FORBIDDEN_LOG"; exit 74;;
esac
exec /bin/bash "$@"
''',
    }.items():
        path = bindir / name
        path.write_text(body)
        path.chmod(0o700)

    def snapshot(directory):
        return {p.relative_to(directory).as_posix(): p.read_bytes()
                for p in directory.rglob("*") if p.is_file()}

    before = snapshot(root)
    ui_root = candidate if entry in {"active-candidate", "active-settings-menu"} else root
    command = ["/bin/bash", str(ui_root / "scripts/control.sh")]
    if entry != "baseline":
        command += ["--active-menu", str(root)]
    command += ["menu" if entry == "active-settings-menu" else "install"]
    result = subprocess.run(command, input="3\n2\n3\n0\n0\n0\n", text=True,
        capture_output=True, timeout=15, env={**os.environ,
            "PATH": str(bindir) + os.pathsep + os.environ["PATH"],
            "LITECHECKER_NATIVE_ROOT": str(root), "DOCKER_LOG": str(docker_log),
            "FORBIDDEN_LOG": str(forbidden_log),
            "FIXTURE_SYSTEM": "Darwin" if platform == "macos" else "Linux"})
    output = result.stdout + result.stderr
    assert result.returncode == (0 if entry == "active-settings-menu" else 2), output
    if platform == "linux":
        assert docker_log.exists(), output
        assert docker_log.read_text() == f"{root}|compose version\n", output
        assert f"Папка данных: {root}\n" in output
        assert "Не найден Docker Compose" in output
    else:
        assert "Для восстановления скачайте свежий установочный ZIP" in output
        assert not docker_log.exists()
    if entry == "active-settings-menu":
        # Recovery must return to the active UI, not rewrite/revert its source.
        assert output.count("MENU-0.7.0") == 2, output
        assert "Восстановить установку" in output
    assert not forbidden_log.exists(), output
    assert snapshot(root) == before  # Includes settings, trust, high-water and code.
    for name in ("state", "secrets", ".updates", ".env.standalone", "native-settings.json"):
        assert not (candidate / name).exists()
