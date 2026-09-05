"""Credential editing is transactional, private, and format preserving."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from filelock import FileLock


TOKEN = "123456789:abcdefghijklmnopqrstuvwxyzABCDE"
NEW_TOKEN = "987654321:ABCDEFGHIJKLMNOPQRSTUVWXYZabcde"
SUBSCRIPTION = "https://subscription.example/private"
NEW_SUBSCRIPTION = "https://new.example/subscription"


def private_file(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def native_root(tmp_path: Path) -> Path:
    root = tmp_path / "Library/Application Support/LiteChecker"
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    return root


def docker_root(tmp_path: Path, env: bytes | None = None) -> Path:
    root = tmp_path / "LiteChecker"
    root.mkdir(parents=True, mode=0o700)
    if env is not None:
        path = root / ".env.standalone"
        path.write_bytes(env)
        path.chmod(0o600)
    return root


def install_credentials(root: Path, *, proxy: str | None = None) -> None:
    private_file(root / "secrets/subscription_url", SUBSCRIPTION + "\n")
    private_file(root / "secrets/telegram_bot_token", TOKEN + "\n")
    if proxy is not None:
        private_file(root / "secrets/telegram_proxy_url", proxy + "\n")


def scripted(monkeypatch, module, values: list[str]) -> list[tuple[str, bool]]:
    calls: list[tuple[str, bool]] = []
    iterator = iter(values)

    def prompt(label: str, *, secret: bool) -> str:
        calls.append((label, secret))
        return next(iterator)

    monkeypatch.setattr(module, "_prompt", prompt)
    monkeypatch.setattr(module, "_is_interactive", lambda: True)
    return calls


def test_fresh_native_setup_creates_complete_private_configuration(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    entered = [SUBSCRIPTION, TOKEN, "-123456", "", "Рабочий Mac"]
    calls = scripted(monkeypatch, device_setup, entered)

    assert device_setup.configure_device(root, "native", initial=True) == 0

    assert json.loads((root / "native-settings.json").read_text()) == {
        "LC_AGENT_NAME": "Рабочий Mac",
        "LC_INTERVAL_SECONDS": "600",
        "LC_TELEGRAM_CHAT_ID": "-123456",
    }
    assert (root / "secrets/subscription_url").read_text() == SUBSCRIPTION + "\n"
    assert (root / "secrets/telegram_bot_token").read_text() == TOKEN + "\n"
    assert not (root / "secrets/telegram_proxy_url").exists()
    assert all((root / path).stat().st_mode & 0o777 == 0o600 for path in (
        "native-settings.json", "secrets/subscription_url", "secrets/telegram_bot_token"
    ))
    assert calls[0][1] is True and calls[1][1] is True and calls[3][1] is True
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert all(value not in output for value in entered if value)


def test_fresh_docker_setup_writes_runtime_fields_without_needing_preset_secrets(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = docker_root(tmp_path)
    scripted(monkeypatch, device_setup, [SUBSCRIPTION, TOKEN, "42", "", ""])

    assert device_setup.configure_device(root, "docker", initial=True) == 0

    assert (root / ".env.standalone").read_bytes() == (
        b"LC_AGENT_CITY=''\n"
        b"LC_AGENT_NAME=''\n"
        b"LC_HOST_NAME=''\n"
        b"LC_HOST_OS=''\n"
        b"LC_TELEGRAM_CHAT_ID='42'\n"
        b"LC_TELEGRAM_BOT_TOKEN_FILE='/run/secrets/telegram_bot_token'\n"
        b"LC_SUBSCRIPTION_URL_FILE='/run/secrets/subscription_url'\n"
        b"LC_STATE_DIR='/var/lib/litechecker'\n"
        b"LC_INTERVAL_SECONDS='600'\n"
    )


def test_blank_edit_preserves_credentials_chat_proxy_name_and_advanced_native_values(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root, proxy="socks5://user:password@proxy.example:1080")
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_CITY": "Тбилиси",
        "LC_AGENT_NAME": "Existing",
        "LC_MAX_CONCURRENCY": 7,
        "LC_TELEGRAM_CHAT_ID": "-7",
        "LC_INTERVAL_SECONDS": "600",
    }, ensure_ascii=False) + "\n")
    before = {path: (root / path).read_bytes() for path in (
        "secrets/subscription_url", "secrets/telegram_bot_token", "secrets/telegram_proxy_url"
    )}
    calls = scripted(monkeypatch, device_setup, ["", "", "", "", ""])

    assert device_setup.configure_device(root, "native") == 0

    settings = json.loads((root / "native-settings.json").read_text())
    assert settings["LC_AGENT_CITY"] == "Тбилиси"
    assert settings["LC_MAX_CONCURRENCY"] == 7
    assert settings["LC_AGENT_NAME"] == "Existing"
    assert settings["LC_TELEGRAM_CHAT_ID"] == "-7"
    assert all((root / path).read_bytes() == value for path, value in before.items())
    assert "задан" in calls[0][0] and SUBSCRIPTION not in calls[0][0]
    assert "задан" in calls[1][0] and TOKEN not in calls[1][0]
    assert "-7" in calls[2][0]
    assert "https/http/socks5 URL" in calls[3][0]


def test_edit_changes_required_values_and_dash_clears_only_optional_fields(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root, proxy="https://user:password@proxy.example:8443")
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "Old", "LC_TELEGRAM_CHAT_ID": "-10", "LC_INTERVAL_SECONDS": "600"
    }) + "\n")
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "-20", "-", "-"])

    assert device_setup.configure_device(root, "native") == 0

    assert (root / "secrets/subscription_url").read_text().strip() == NEW_SUBSCRIPTION
    assert (root / "secrets/telegram_bot_token").read_text().strip() == NEW_TOKEN
    assert not (root / "secrets/telegram_proxy_url").exists()
    settings = json.loads((root / "native-settings.json").read_text())
    assert settings["LC_TELEGRAM_CHAT_ID"] == "-20"
    assert settings["LC_AGENT_NAME"] == ""


def test_docker_targeted_replacement_preserves_every_unrelated_byte(tmp_path, monkeypatch):
    from litechecker import device_setup

    original = (
        b"# advanced options stay exact\r\n"
        b"LC_AGENT_CITY='Sao Paulo'\r\n"
        b"LC_AGENT_NAME='Old'\r\n"
        b"LC_TELEGRAM_CHAT_ID='-10'\r\n"
        b"LC_MAX_CONCURRENCY='17'\r\n"
        b"CUSTOM_FUTURE=${KEEP_ME:-yes}\r\n"
    )
    root = docker_root(tmp_path, original)
    install_credentials(root)
    scripted(monkeypatch, device_setup, ["", "", "-20", "", "New Узел"])

    assert device_setup.configure_device(root, "docker") == 0

    expected = original.replace(b"LC_AGENT_NAME='Old'", "LC_AGENT_NAME='New Узел'".encode()).replace(
        b"LC_TELEGRAM_CHAT_ID='-10'", b"LC_TELEGRAM_CHAT_ID='-20'"
    )
    assert (root / ".env.standalone").read_bytes() == expected


def test_initial_complete_configuration_returns_without_prompting(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "Existing", "LC_TELEGRAM_CHAT_ID": "-10", "LC_INTERVAL_SECONDS": "600"
    }))
    monkeypatch.setattr(device_setup, "_prompt", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(device_setup, "_is_interactive", lambda: False)

    assert device_setup.configure_device(root, "native", initial=True) == 0


def test_missing_configuration_noninteractive_returns_two_without_writes(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    monkeypatch.setattr(device_setup, "_is_interactive", lambda: False)

    assert device_setup.configure_device(root, "native", initial=True) == 2
    assert not (root / "native-settings.json").exists()
    assert not (root / "secrets").exists()
    assert "интерактив" in capsys.readouterr().err.lower()


def test_cancel_or_invalid_input_leaves_all_configuration_bytes_unchanged(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = docker_root(tmp_path, b"LC_AGENT_NAME='Old'\nLC_TELEGRAM_CHAT_ID='-10'\nADVANCED=keep\n")
    install_credentials(root)
    tracked = [root / ".env.standalone", root / "secrets/subscription_url", root / "secrets/telegram_bot_token"]
    before = {path: path.read_bytes() for path in tracked}
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "not-a-chat", "", "New"])

    assert device_setup.configure_device(root, "docker") == 2
    assert all(path.read_bytes() == value for path, value in before.items())
    error = capsys.readouterr().err
    assert "ID Telegram-чата" in error
    assert "not-a-chat" not in error

    def cancelled(_label: str, *, secret: bool) -> str:
        del secret
        raise KeyboardInterrupt

    monkeypatch.setattr(device_setup, "_prompt", cancelled)
    assert device_setup.configure_device(root, "docker") == 130
    assert all(path.read_bytes() == value for path, value in before.items())


def test_rejects_unsafe_secret_and_config_inputs_without_following_them(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    outside = tmp_path / "outside"
    outside.write_text(SUBSCRIPTION)
    secrets = root / "secrets"
    secrets.mkdir(mode=0o700)
    (secrets / "subscription_url").symlink_to(outside)
    private_file(secrets / "telegram_bot_token", TOKEN)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    monkeypatch.setattr(device_setup, "_prompt", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("prompted")))
    monkeypatch.setattr(device_setup, "_is_interactive", lambda: True)

    assert device_setup.configure_device(root, "native") == 2
    assert outside.read_text() == SUBSCRIPTION

    (secrets / "subscription_url").unlink()
    private_file(secrets / "subscription_url", SUBSCRIPTION)
    (root / "native-settings.json").chmod(0o644)
    assert device_setup.configure_device(root, "native") == 2


def test_rejects_duplicate_or_unfamiliar_quoted_recognized_compose_values_without_mutation(tmp_path, monkeypatch):
    from litechecker import device_setup

    for env in (
        b"LC_AGENT_NAME='One'\nLC_AGENT_NAME='Two'\nLC_TELEGRAM_CHAT_ID='-1'\n",
        b'LC_AGENT_NAME="hard\\nquote"\nLC_TELEGRAM_CHAT_ID=\'-1\'\n',
        b"LC_AGENT_NAME='One'\nLC_TELEGRAM_CHAT_ID='-1'\nADVANCED=one\nADVANCED=two\n",
        b"LC_AGENT_NAME='One'\nLC_TELEGRAM_CHAT_ID='-1'\nthis is not dotenv\n",
    ):
        root = docker_root(tmp_path / str(len(env)), env)
        install_credentials(root)
        before = (root / ".env.standalone").read_bytes()
        prompts: list[str] = []
        monkeypatch.setattr(device_setup, "_prompt", lambda label, **_kwargs: prompts.append(label) or "")
        monkeypatch.setattr(device_setup, "_is_interactive", lambda: True)
        assert device_setup.configure_device(root, "docker") == 2
        assert prompts == []
        assert (root / ".env.standalone").read_bytes() == before


def test_busy_managed_update_lock_returns_immediately_without_mutation(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "Old", "LC_TELEGRAM_CHAT_ID": "-1", "LC_INTERVAL_SECONDS": "600"
    }))
    tracked = [root / "native-settings.json", root / "secrets/subscription_url", root / "secrets/telegram_bot_token"]
    before = {path: path.read_bytes() for path in tracked}
    scripted(monkeypatch, device_setup, ["", "", "-2", "", "New"])
    lock_path = root / ".updates/update.lock"
    lock_path.parent.mkdir(mode=0o700)

    with FileLock(lock_path, timeout=0, mode=0o600, preserve_lock_file=True):
        assert device_setup.configure_device(root, "native") == 2
    assert all(path.read_bytes() == value for path, value in before.items())


def test_concurrent_configuration_change_is_detected_after_prompts_and_preserved(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = docker_root(tmp_path, b"LC_AGENT_NAME='Old'\nLC_TELEGRAM_CHAT_ID='-1'\nADVANCED=first\n")
    install_credentials(root)
    reached_last_prompt = threading.Event()
    continue_prompt = threading.Event()
    values = iter(["", "", "-2", "", "New"])
    count = 0

    def prompt(_label: str, *, secret: bool) -> str:
        nonlocal count
        del secret
        count += 1
        if count == 5:
            reached_last_prompt.set()
            assert continue_prompt.wait(3)
        return next(values)

    monkeypatch.setattr(device_setup, "_prompt", prompt)
    monkeypatch.setattr(device_setup, "_is_interactive", lambda: True)
    result: list[int] = []
    worker = threading.Thread(target=lambda: result.append(device_setup.configure_device(root, "docker")))
    worker.start()
    assert reached_last_prompt.wait(3)
    concurrent = b"LC_AGENT_NAME='Other'\nLC_TELEGRAM_CHAT_ID='-1'\nADVANCED=second\n"
    (root / ".env.standalone").write_bytes(concurrent)
    (root / ".env.standalone").chmod(0o600)
    continue_prompt.set()
    worker.join(3)

    assert result == [2]
    assert (root / ".env.standalone").read_bytes() == concurrent
    assert (root / "secrets/subscription_url").read_text().strip() == SUBSCRIPTION


def test_identity_and_outbox_are_never_modified(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    private_file(root / "state/native-direct/device.json", '{"agent_id":"device-old","state_key":"' + "x" * 32 + '"}\n')
    private_file(root / "state/native-direct/outbox.jsonl", '{"message":"pending"}\n')
    before = {path: (root / path).read_bytes() for path in (
        "state/native-direct/device.json", "state/native-direct/outbox.jsonl"
    )}
    scripted(monkeypatch, device_setup, ["", "", "-2", "", "New"])

    assert device_setup.configure_device(root, "native") == 0
    assert all((root / path).read_bytes() == value for path, value in before.items())


def test_commit_failure_after_first_replacement_rolls_back_every_original_byte(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root, proxy="socks5://old:password@proxy.example:1080")
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "Old", "LC_TELEGRAM_CHAT_ID": "-1", "LC_INTERVAL_SECONDS": "600"
    }) + "\n")
    tracked = list(device_setup._paths(root, "native").values())
    before = {path: path.read_bytes() for path in tracked}
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "-2", "-", "New"])
    real_atomic_write = device_setup.atomic_write
    calls = 0

    def fail_second(path, data, mode):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected write failure containing " + NEW_TOKEN)
        real_atomic_write(path, data, mode)

    monkeypatch.setattr(device_setup, "atomic_write", fail_second)

    assert device_setup.configure_device(root, "native") == 2
    assert all(path.read_bytes() == value for path, value in before.items())
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert NEW_SUBSCRIPTION not in output and NEW_TOKEN not in output


def test_incomplete_rollback_uses_honest_closed_error_without_values(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "-2", "", "New"])
    real_atomic_write = device_setup.atomic_write
    calls = 0

    def fail_from_second(path, data, mode):
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise OSError("injected failure containing " + NEW_TOKEN)
        real_atomic_write(path, data, mode)

    monkeypatch.setattr(device_setup, "atomic_write", fail_from_second)

    assert device_setup.configure_device(root, "native") == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Не удалось завершить сохранение; проверьте настройки" in output
    assert NEW_SUBSCRIPTION not in output and NEW_TOKEN not in output


def test_keyboard_interrupt_after_first_replacement_rolls_back_then_returns_130(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    tracked = list(device_setup._paths(root, "native").values())
    before = {path: path.read_bytes() if path.exists() else None for path in tracked}
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "-2", "", "New"])
    real_atomic_write = device_setup.atomic_write
    calls = 0

    def interrupt_second(path, data, mode):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise KeyboardInterrupt
        real_atomic_write(path, data, mode)

    monkeypatch.setattr(device_setup, "atomic_write", interrupt_second)

    assert device_setup.configure_device(root, "native") == 130
    assert all((path.read_bytes() if path.exists() else None) == data for path, data in before.items())
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "отменена" in output
    assert NEW_SUBSCRIPTION not in output and NEW_TOKEN not in output


def test_keyboard_interrupt_during_rollback_reports_possible_partial_save(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    scripted(monkeypatch, device_setup, [NEW_SUBSCRIPTION, NEW_TOKEN, "-2", "", "New"])
    real_atomic_write = device_setup.atomic_write
    calls = 0

    def interrupt_write_and_rollback(path, data, mode):
        nonlocal calls
        calls += 1
        if calls in {2, 3}:
            raise KeyboardInterrupt
        real_atomic_write(path, data, mode)

    monkeypatch.setattr(device_setup, "atomic_write", interrupt_write_and_rollback)

    assert device_setup.configure_device(root, "native") == 2
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "Не удалось завершить сохранение; проверьте настройки" in output
    assert "изменения не сохранены" not in output
    assert NEW_SUBSCRIPTION not in output and NEW_TOKEN not in output


def test_rejects_symlinked_root_ancestor_and_lexical_parent_segments(tmp_path, monkeypatch):
    from litechecker import device_setup

    real_parent = tmp_path / "real"
    root = native_root(real_parent)
    install_credentials(root)
    private_file(root / "native-settings.json", json.dumps({"LC_TELEGRAM_CHAT_ID": "-1"}))
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    through_link = linked_parent / "Library/Application Support/LiteChecker"
    through_parent = root.parent / "unused" / ".." / root.name
    prompts: list[str] = []
    monkeypatch.setattr(device_setup, "_prompt", lambda label, **_kwargs: prompts.append(label) or "")
    monkeypatch.setattr(device_setup, "_is_interactive", lambda: True)

    assert device_setup.configure_device(through_link, "native", initial=True) == 2
    assert device_setup.configure_device(through_parent, "native", initial=True) == 2
    assert prompts == []


def test_initial_public_defaults_require_explicit_chat_and_show_only_safe_status(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    root = native_root(tmp_path)
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "", "LC_TELEGRAM_CHAT_ID": "-5361201677", "LC_INTERVAL_SECONDS": "600"
    }) + "\n")
    calls = scripted(monkeypatch, device_setup, [SUBSCRIPTION, TOKEN, "", "", ""])
    before = (root / "native-settings.json").read_bytes()

    assert device_setup.configure_device(root, "native", initial=True) == 2
    assert (root / "native-settings.json").read_bytes() == before
    assert not (root / "secrets").exists()
    assert "не задан" in calls[0][0] and "не задан" in calls[1][0]
    assert "-5361201677" in calls[2][0]
    error = capsys.readouterr().err
    assert "ID Telegram-чата" in error
    assert SUBSCRIPTION not in error and TOKEN not in error


def test_initial_public_defaults_accept_explicit_chat_confirmation(tmp_path, monkeypatch):
    from litechecker import device_setup

    root = native_root(tmp_path)
    private_file(root / "native-settings.json", json.dumps({
        "LC_AGENT_NAME": "", "LC_TELEGRAM_CHAT_ID": "-5361201677", "LC_INTERVAL_SECONDS": "600"
    }) + "\n")
    scripted(monkeypatch, device_setup, [SUBSCRIPTION, TOKEN, "-24680", "", ""])

    assert device_setup.configure_device(root, "native", initial=True) == 0
    assert json.loads((root / "native-settings.json").read_text())["LC_TELEGRAM_CHAT_ID"] == "-24680"


def test_each_invalid_entry_names_only_its_field(tmp_path, monkeypatch, capsys):
    from litechecker import device_setup

    cases = (
        (["http://bad.invalid/sub", "", "", "", ""], "URL подписки", "http://bad.invalid/sub"),
        (["", "not-a-token", "", "", ""], "токен Telegram-бота", "not-a-token"),
        (["", "", "zero", "", ""], "ID Telegram-чата", "zero"),
        (["", "", "", "ftp://bad.invalid", ""], "прокси Telegram", "ftp://bad.invalid"),
        (["", "", "", "", "bad\nname"], "название устройства", "bad\nname"),
    )
    for index, (values, field, entered) in enumerate(cases):
        root = native_root(tmp_path / str(index))
        install_credentials(root)
        private_file(root / "native-settings.json", json.dumps({
            "LC_AGENT_NAME": "Old", "LC_TELEGRAM_CHAT_ID": "-1", "LC_INTERVAL_SECONDS": "600"
        }))
        before = {path: path.read_bytes() for path in device_setup._paths(root, "native").values() if path.exists()}
        scripted(monkeypatch, device_setup, values)

        assert device_setup.configure_device(root, "native") == 2
        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert field in output
        assert entered not in output
        assert all(path.read_bytes() == data for path, data in before.items())
