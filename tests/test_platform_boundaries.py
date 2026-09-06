"""Exercise trimmed source trees: an omitted foreign backend must be optional."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

import pytest


def isolated(tmp_path, excluded, code):
    source = Path(__file__).resolve().parents[1] / "src/litechecker"
    package = tmp_path / "src/litechecker"
    shutil.copytree(source, package, ignore=shutil.ignore_patterns("__pycache__", *excluded))
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)], cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(package.parent), "PYTHONDONTWRITEBYTECODE": "1"},
        text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_windows_worker_loads_without_mac_settings_or_socket_backend(tmp_path):
    # Catches direct_check's eager MacDirectNetwork and direct_service's native settings.
    isolated(tmp_path, ("macos_*.py", "native_*.py", "linux_update.py"), """
        import asyncio
        from types import SimpleNamespace
        from litechecker import windows_worker, windows_app, updater, direct_check
        from litechecker.collector.auth import AgentIdentity
        from litechecker.direct_network import DirectNetworkUnavailable, TCPDirectNetwork
        from litechecker.windows_network import WindowsDirectNetwork
        assert issubclass(WindowsDirectNetwork, TCPDirectNetwork)
        async def unavailable():
            raise DirectNetworkUnavailable("interface_changed")
        settings = SimpleNamespace(identity=AgentIdentity("test", "City", "PC", 600))
        result = asyncio.run(direct_check.run_trial(settings, network_factory=unavailable, platform_label="Windows"))
        assert result.available is False and "Windows" in result.text
    """)


@pytest.mark.parametrize("system, excluded", [
    ("Linux", ("windows_*.py", "macos_*.py", "native_runtime.py", "native_install.py", "install_handoff.py")),
    ("Darwin", ("windows_*.py", "linux_update.py")),
])
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX host adapters")
def test_posix_update_and_cli_work_without_foreign_modules(tmp_path, system, excluded):
    # Catches eager windows_security in launcher/store/atomic_io and native_runtime in updater/setup.
    isolated(tmp_path, excluded, f"""
        import platform
        from pathlib import Path
        platform.system = lambda: {system!r}
        from litechecker import cli, device_setup, updater, update_platform, update_service
        root = Path.cwd()
        adapter = update_platform.platform_adapter(root)
        assert adapter.system == {system!r}
        update_platform.record_desired_running(root, False)
        import asyncio
        assert asyncio.run(adapter.is_running()) is False
        assert update_service.main(["status", "--root", str(root)]) == 0
        assert cli._parser().parse_args(["standalone", "--once"]).once is True
    """)


@pytest.mark.asyncio
async def test_macos_adapter_owns_bound_socket_implementation():
    # An alias to a Mac class still defined in the shared module cannot be omitted.
    from litechecker.macos_network import MacDirectNetwork
    from litechecker.direct_network import TCPDirectNetwork, DirectNetworkUnavailable
    assert MacDirectNetwork.__module__ == "litechecker.macos_network"
    assert issubclass(MacDirectNetwork, TCPDirectNetwork)
    direct = MacDirectNetwork("en0", 1, ("192.168.1.2",), ("192.168.1.1",))
    assert await direct.resolve("8.8.8.8") == ["8.8.8.8"]
    with pytest.raises(DirectNetworkUnavailable, match="unsafe_direct_address"):
        await direct.resolve("127.0.0.1")


def test_platform_security_keeps_posix_private_file_checks_without_windows(tmp_path):
    if sys.platform == "win32":
        pytest.skip("POSIX mode and ownership contract")
    isolated(tmp_path, ("windows_*.py",), """
        from pathlib import Path
        from litechecker import platform_security
        root = Path.cwd() / "private"
        root.mkdir(mode=0o700)
        path = root / "record"
        path.write_bytes(b"test")
        path.chmod(0o600)
        assert platform_security.assert_private_file(path) == path
        path.chmod(0o644)
        try:
            platform_security.assert_private_file(path)
        except ValueError:
            pass
        else:
            raise AssertionError("public private-file accepted")
        link = root / "link"
        link.symlink_to(path)
        try:
            platform_security.reject_reparse_points(link)
        except ValueError:
            pass
        else:
            raise AssertionError("symbolic link accepted")
    """)
