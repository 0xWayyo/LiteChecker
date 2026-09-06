"""Drive real prompts one answer at a time, including the PowerShell boundary."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import queue
import shutil
import subprocess
import sys
import threading
import time

import pytest


ROOT = Path(__file__).resolve().parents[1]
SUBSCRIPTION = "https://subscription.invalid/fixture"
TOKEN = "123456:" + "A" * 30
PROXY = "socks5://fixture:password@proxy.invalid:1080"


@contextmanager
def conversation(command):
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=0)
    received = queue.Queue()
    def reader():
        for line in iter(process.stdout.readline, b""):
            received.put(line)
        received.put(None)
    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    transcript = []
    def expect(text, timeout=8):
        deadline = time.monotonic() + timeout
        while True:
            try:
                line = received.get(timeout=max(0.01, deadline - time.monotonic()))
            except queue.Empty:
                pytest.fail(f"No complete prompt BEFORE input: {text!r}; output={transcript!r}")
            assert line is not None, transcript
            decoded = line.decode("utf-8")
            transcript.append(decoded)
            if text in decoded:
                return
    def answer(value):
        process.stdin.write((value + "\n").encode("utf-8"))
        process.stdin.flush()
    try:
        yield process, expect, answer, transcript
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=8)
        process.stdin.close()
        thread.join(timeout=8)
        process.stdout.close()


def menu_command(tmp_path, host):
    from windows_test_support import secure_test_directory
    tmp_path = tmp_path.resolve()
    secure_test_directory(tmp_path)
    entry = ROOT / "scripts/windows-app-entry.py"
    script_root = ROOT
    if os.name == "nt":
        from platform_package_support import extracted_profile
        payload, _ = extracted_profile(tmp_path / "packaged", "windows")
        # Use only the exact public wrapper payload, with settings at the
        # caller's private root so every prompt assertion keeps the same scope.
        shutil.copytree(payload, tmp_path, dirs_exist_ok=True)
        entry = tmp_path / "scripts/windows-app-entry.py"
        script_root = tmp_path
    if host == "python":
        return [sys.executable, "-I", "-B", str(entry), "menu", "--root", str(tmp_path)]
    powershell = shutil.which("powershell.exe")
    assert powershell
    harness = tmp_path / "prompt-boundary.ps1"
    harness.write_text(r'''
param([string]$ScriptPath,[string]$Python,[string]$Entry,[string]$Root)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Invalid PowerShell'}
foreach($fn in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)){
  . ([scriptblock]::Create($fn.Extent.Text))
}
# Only already-tested runtime download/preparation is omitted. Real launcher,
# isolated entry, configuration, validation and main/settings menus execute.
function Assert-SafeRegularFile([string]$Path,[string]$Label) {}
function Protect-PrivateRoot([string]$Path) {}
function Initialize-NativeRuntime([bool]$IncludeXray=$true) {}
$script:PythonExe=$Python
$script:AppEntryScript=$Entry
$script:RootPath=$Root
Invoke-NormalApp
''', encoding="utf-8-sig")
    return [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(harness),
            "-ScriptPath", str(script_root / "scripts/windows-native.ps1"),
            "-Python", sys.executable, "-Entry", str(entry), "-Root", str(tmp_path)]


@pytest.mark.parametrize("host", ["python", pytest.param("powershell", marks=pytest.mark.skipif(
    os.name != "nt", reason="actual Windows PowerShell prompt boundary"))])
def test_every_setup_prompt_is_visible_before_its_answer_and_menu_never_starts_checks(tmp_path, host):
    with conversation(menu_command(tmp_path, host)) as (process, expect, answer, transcript):
        for label, value in (("Ссылка подписки", SUBSCRIPTION), ("Токен бота", TOKEN),
                             ("ID чата", "-12345"), ("Прокси Telegram", PROXY)):
            expect(label)
            assert not (tmp_path / "windows-state/settings.json").exists()
            answer(value)
        expect("Настройки сохранены")
        expect("Выберите цифру")
        answer("3")
        expect("Выберите цифру")
        answer("0")
        expect("Выберите цифру")
        answer("0")
        assert process.wait(timeout=10) == 0
    values = json.loads((tmp_path / "windows-state/settings.json").read_bytes())
    assert values == {"subscription_url": SUBSCRIPTION, "telegram_bot_token": TOKEN,
                      "telegram_chat_id": "-12345", "telegram_proxy_url": PROXY}
    text = "".join(transcript)
    assert all(value not in text for value in (SUBSCRIPTION, TOKEN, PROXY))
    assert "ОСТАНОВЛЕН" in text and "Запустить проверки" in text
    assert not (tmp_path / "windows-state/control/worker.json").exists()


def test_bad_fields_retry_locally_without_discarding_previous_answers(tmp_path, monkeypatch, capsys):
    from litechecker.windows_trial import configure
    values = iter(("http://bad.invalid", SUBSCRIPTION, "bad-token", TOKEN,
                   "chat-title", "-12345", "invalid-proxy", PROXY))
    monkeypatch.setattr("builtins.input", lambda _label="": next(values))
    assert configure(tmp_path, initial=True)
    saved = json.loads((tmp_path / "windows-state/settings.json").read_bytes())
    assert saved["subscription_url"] == SUBSCRIPTION
    assert saved["telegram_bot_token"] == TOKEN
    assert saved["telegram_chat_id"] == "-12345"
    assert saved["telegram_proxy_url"] == PROXY
    output = capsys.readouterr().out
    for part in ("HTTPS", "BotFather", "число", "socks5://"):
        assert part in output
    for secret in (SUBSCRIPTION, TOKEN, PROXY, "bad-token", "invalid-proxy"):
        assert secret not in output


def test_enter_preserves_existing_telegram_and_explicit_minus_removes_only_proxy(tmp_path, monkeypatch):
    from litechecker.windows_trial import configure, save_configuration
    original = dict(subscription_url=SUBSCRIPTION, telegram_bot_token=TOKEN,
                    telegram_chat_id="-12345", telegram_proxy_url=PROXY)
    save_configuration(tmp_path, original)
    answers = iter(("", "", ""))
    monkeypatch.setattr("builtins.input", lambda _label="": next(answers))
    assert configure(tmp_path, telegram=True)
    assert json.loads((tmp_path / "windows-state/settings.json").read_bytes()) == original
    answers = iter(("", "", "-"))
    assert configure(tmp_path, telegram=True)
    assert json.loads((tmp_path / "windows-state/settings.json").read_bytes()) == {
        key: value for key, value in original.items() if key != "telegram_proxy_url"
    }


@pytest.mark.parametrize("interrupt", [EOFError, KeyboardInterrupt])
def test_cancel_keeps_configuration_byte_identical(tmp_path, monkeypatch, interrupt):
    from litechecker.windows_trial import configure, save_configuration
    save_configuration(tmp_path, dict(subscription_url=SUBSCRIPTION, telegram_bot_token=TOKEN,
                                     telegram_chat_id="-12345", telegram_proxy_url=PROXY))
    path = tmp_path / "windows-state/settings.json"
    before = path.read_bytes()
    values = iter(("987654:" + "B" * 30,))
    def answer(_label=""):
        try:
            return next(values)
        except StopIteration:
            raise interrupt
    monkeypatch.setattr("builtins.input", answer)
    assert configure(tmp_path, telegram=True) is False
    assert path.read_bytes() == before


def test_initial_setup_can_skip_telegram_without_requesting_chat_or_proxy(tmp_path, monkeypatch, capsys):
    from litechecker.windows_trial import configure
    answers = iter((SUBSCRIPTION, ""))
    monkeypatch.setattr("builtins.input", lambda _label="": next(answers))
    assert configure(tmp_path, initial=True)
    assert json.loads((tmp_path / "windows-state/settings.json").read_bytes()) == {"subscription_url": SUBSCRIPTION}
    output = capsys.readouterr().out
    assert "ID чата" not in output and "Прокси Telegram" not in output
    assert "без Telegram" in output


@pytest.mark.parametrize("arguments", [["--setup"], ["--configure-telegram"], []])
def test_legacy_trial_cancel_never_reports_saved_or_continues_to_checks(tmp_path, monkeypatch, capsys, arguments):
    from types import SimpleNamespace
    from litechecker import windows_trial

    # Exercise the real CLI flow without changing the host platform globally.
    monkeypatch.setattr(windows_trial, "sys", SimpleNamespace(platform="win32", stdout=object()))
    def cancelled(_label=""):
        raise EOFError
    monkeypatch.setattr("builtins.input", cancelled)
    monkeypatch.setattr(windows_trial, "load_settings", lambda *args: pytest.fail("cancel must not start checks"))
    assert windows_trial.main(["--root", str(tmp_path), *arguments]) == 130
    output = capsys.readouterr().out
    assert "Настройка отменена" in output
    assert "Настройки сохранены" not in output
    assert not (tmp_path / "windows-state/settings.json").exists()
