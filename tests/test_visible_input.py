"""Typed settings are echoed by the terminal, not printed into application logs."""

from contextlib import contextmanager
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import time

import pytest


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX terminal echo contract")
ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def terminal(command):
    import pty

    master, slave = pty.openpty()
    process = subprocess.Popen(
        command, stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
    )
    os.close(slave)
    try:
        yield master, process
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        os.close(master)


def read_until(fd, needle, timeout=3):
    received = b""
    deadline = time.monotonic() + timeout
    while needle not in received:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
            pytest.fail(f"Terminal did not display {needle!r}; received {received!r}")
        try:
            chunk = os.read(fd, 4096)
        except OSError as error:
            pytest.fail(f"Terminal closed before {needle!r}: {error}; received {received!r}")
        assert chunk, received
        received += chunk
    return received


@pytest.mark.parametrize("label,value", [
    ("Subscription: ", "https://subscription.invalid/fixture"),
    ("Bot token: ", "123456789:terminal-echo-fixture"),
    ("Proxy: ", "socks5://fixture:password@proxy.invalid:1080"),
])
@pytest.mark.parametrize("variant", ["shared", "windows"])
def test_sensitive_settings_are_visible_before_enter(label, value, variant):
    prompt = ("from litechecker.device_setup import _prompt; "
              f"value = _prompt({label!r}, secret=True); " if variant == "shared" else
              "from litechecker.terminal_ui import prompt; "
              f"value = prompt({label!r}); ")
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT / 'src')!r}); "
        + prompt + f"assert value == {value!r}; "
        "print('INPUT_ACCEPTED', flush=True)"
    )
    with terminal([sys.executable, "-I", "-c", code]) as (fd, process):
        read_until(fd, label.encode())
        os.write(fd, value.encode())
        read_until(fd, value.encode())  # Before Enter: genuine terminal echo.
        os.write(fd, b"\n")
        output = read_until(fd, b"INPUT_ACCEPTED")
        assert value.encode() not in output  # No second application-side print.
        assert process.wait(timeout=5) == 0


def test_shell_setup_fallback_echoes_both_fields_and_keeps_files_private(tmp_path):
    script = tmp_path / "run.sh"
    shutil.copyfile(ROOT / "run.sh", script)
    entries = [
        ("Общий токен Telegram-бота".encode(), "123456789:visible-fixture"),
        ("URL подписки".encode(), "https://subscription.invalid/fixture"),
    ]
    with terminal(["bash", str(script), "setup", "--quick"]) as (fd, process):
        for prompt, value in entries:
            read_until(fd, prompt)
            os.write(fd, value.encode())
            read_until(fd, value.encode())
            os.write(fd, b"\n")
        output = read_until(fd, "Настройки сохранены".encode())
        assert all(value.encode() not in output for _, value in entries)
        assert process.wait(timeout=5) == 0
    for name, (_, value) in zip(("telegram_bot_token", "subscription_url"), entries):
        stored = tmp_path / "secrets" / name
        assert stored.read_text().strip() == value
        assert stored.stat().st_mode & 0o777 == 0o600
