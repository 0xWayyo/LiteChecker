"""Child creation flags at the OS boundary; no real network or Xray required."""
from types import SimpleNamespace

import pytest

from litechecker import measurement, probe
from litechecker.models import TargetConfig


@pytest.mark.asyncio
@pytest.mark.parametrize("platform,flags", [("win32", 0x08000000), ("darwin", 0), ("linux", 0)])
@pytest.mark.parametrize("operation", ["probe", "version"])
async def test_background_xray_never_creates_a_windows_console(monkeypatch, platform, flags, operation):
    module = probe if operation == "probe" else measurement
    monkeypatch.setattr(module, "sys", SimpleNamespace(platform=platform), raising=False)
    captured = []

    async def unavailable_executable(*args, **kwargs):
        captured.append((args, kwargs))
        raise FileNotFoundError("not installed in this controlled boundary")

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", unavailable_executable)
    if operation == "probe":
        monkeypatch.setattr(probe, "_unused_loopback_port", lambda: 32000)
        target = TargetConfig(target_id="controlled", config_fingerprint="controlled", label="test",
                              address="example.invalid", port=443, address_kind="domain",
                              outbound={"protocol": "freedom", "settings": {}})
        with pytest.raises(probe.XrayUnavailable, match="xray-missing"):
            async with probe.XrayProcess("controlled-xray.exe").open(target):
                pytest.fail("a missing executable cannot yield a tunnel")
    else:
        result = await measurement.query_xray_version("controlled-xray.exe", expected_version="1.2.3")
        assert result.error_code == "xray-version-unavailable" and not result.compatible
    assert len(captured) == 1
    assert captured[0][1].get("creationflags", 0) == flags
