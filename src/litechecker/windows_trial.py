"""Explicit one-shot Windows experiment; never starts a production service."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

from filelock import AsyncFileLock
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from litechecker.atomic_io import atomic_replace
from litechecker.collector.auth import AgentIdentity
from litechecker.collector.reporting import chunk_message
from litechecker.collector.telegram import TelegramClient
from litechecker.config import (
    ProbeSettings, _automatic_device_name, _device_identity, _read_secure_text,
    _validate_telegram_proxy_secret,
)
from litechecker.direct_check import run_trial
from litechecker.runtime import run_with_signals
from litechecker.state import _atomic_write_json
from litechecker.terminal_ui import emit, frame, prompt


_TELEGRAM_SEND_TIMEOUT_SECONDS = 30


class TrialConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    subscription_url: SecretStr = Field(min_length=1, max_length=4096)
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = Field(default=None, pattern=r"^-?[1-9][0-9]{0,19}$")
    telegram_proxy_url: SecretStr | None = None

    @field_validator("subscription_url")
    @classmethod
    def valid_subscription(cls, value):
        raw = value.get_secret_value()
        parsed = urlsplit(raw)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or not raw.isprintable()
                or any(char.isspace() for char in raw)):
            raise ValueError("invalid subscription")
        return value

    @field_validator("telegram_bot_token")
    @classmethod
    def valid_token(cls, value):
        import re
        if value is not None and re.fullmatch(
            r"[0-9]{5,20}:[A-Za-z0-9_-]{20,256}", value.get_secret_value(),
        ) is None:
            raise ValueError("invalid token")
        return value

    _valid_proxy = field_validator("telegram_proxy_url")(_validate_telegram_proxy_secret)


@dataclass(frozen=True)
class WindowsTrialSettings:
    agent: ProbeSettings
    identity: AgentIdentity
    state_dir: Path
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None
    telegram_proxy_url: SecretStr | None = None
    telegram_topic_id: int | None = None


def _state_root(root: Path) -> Path:
    root = root.absolute()
    state = root / "windows-state"
    for path in (state, root, *root.parents):
        if path.is_symlink() or path.is_junction():
            raise ValueError("unsafe local directory")
    if not root.is_dir():
        raise ValueError("missing local directory")
    return state


def save_configuration(root: Path, values: dict) -> None:
    try:
        configuration = TrialConfiguration.model_validate(values)
    except ValueError:
        raise ValueError("Некорректные настройки пробной проверки.") from None
    state = _state_root(root)
    state.mkdir(mode=0o700, exist_ok=True)
    payload = {
        key: value.get_secret_value() if isinstance(value, SecretStr) else value
        for key, value in configuration if value is not None
    }
    _atomic_write_json(state / "settings.json", payload)


def load_settings(root: Path, xray: str) -> WindowsTrialSettings:
    state = _state_root(root)
    try:
        config = TrialConfiguration.model_validate_json(_read_secure_text(state / "settings.json"))
    except (ValueError, OSError):
        raise ValueError("Не удалось прочитать настройки пробной проверки.") from None
    device_id, state_key = _device_identity(state, None)
    agent = ProbeSettings(
        agent_id=device_id, subscription_url=config.subscription_url,
        state_key=state_key, xray_binary=xray,
    )
    return WindowsTrialSettings(
        agent=agent, state_dir=state,
        identity=AgentIdentity(device_id, "Город не определён", _automatic_device_name({}, device_id), 600),
        telegram_bot_token=config.telegram_bot_token,
        telegram_chat_id=config.telegram_chat_id,
        telegram_proxy_url=config.telegram_proxy_url,
    )


def configure(root: Path, *, telegram=False, initial=False) -> bool:
    state = _state_root(root)
    values = {}
    if (state / "settings.json").exists():
        values = json.loads(_read_secure_text(state / "settings.json"))
    frame("LITECHECKER · НАСТРОЙКА", ("Подписка и уведомления" if initial else
          "Telegram" if telegram else "Подписка",))
    emit("  Ввод виден на экране. Enter подтверждает значение; Ctrl+C отменяет настройку.")

    def field(key, label, hint, error, *, optional=False, removable=False):
        current = values.get(key)
        emit("\n  " + label)
        emit("  " + hint)
        if current:
            emit("  Уже задано. Enter — оставить сохранённое значение.")
        elif optional:
            emit("  Enter — пропустить.")
        if removable and current:
            emit("  Минус (-) — удалить сохранённое значение.")
        while True:
            entered = prompt("Значение:").strip()
            value = current if not entered and current else entered or None
            if removable and entered == "-":
                value = None
            proposed = {**values, key: value}
            if value is not None or optional:
                try:
                    TrialConfiguration.model_validate(proposed)
                except ValueError:
                    pass
                else:
                    if value is None:
                        values.pop(key, None)
                    else:
                        values[key] = value
                    return value
            emit("  ⚠️ " + error)

    try:
        if initial or not telegram or not values.get("subscription_url"):
            field("subscription_url", "[1/4] Ссылка подписки" if initial else "Ссылка подписки",
                  "Полная HTTPS-ссылка из вашего VPN-сервиса.",
                  "Нужна полная ссылка, начинающаяся с https://. Попробуйте ещё раз.")
        if telegram or initial:
            token = field("telegram_bot_token", "[2/4] Токен бота" if initial else "[1/3] Токен бота",
                          "Возьмите токен у @BotFather. Без него отчёт останется только на устройстве.",
                          "Нужен токен из @BotFather: цифры, двоеточие и ключ. Попробуйте ещё раз.",
                          optional=True)
            if token:
                field("telegram_chat_id", "[3/4] ID чата" if initial else "[2/3] ID чата",
                      "Число, например -123456789. Для группы ID обычно с минусом.",
                      "Нужно ненулевое целое число, а не название чата. Попробуйте ещё раз.")
                field("telegram_proxy_url", "[4/4] Прокси Telegram" if initial else "[3/3] Прокси Telegram",
                      "Необязательно. Формат: socks5://логин:пароль@IP:порт (также http:// и https://).",
                      "Нужен URL прокси: socks5://логин:пароль@IP:порт. Попробуйте ещё раз.",
                      optional=True, removable=True)
            else:
                values.pop("telegram_chat_id", None)
                values.pop("telegram_proxy_url", None)
                emit("  Проверки будут работать без Telegram. Подключить его можно позже в настройках.")
    except (EOFError, KeyboardInterrupt):
        emit("\n  Настройка отменена. Сохранённые данные не изменены.")
        return False
    save_configuration(root, values)
    emit("\n  ✅ Настройки сохранены")
    emit("  Подписка: задана · Telegram: " + ("настроен" if values.get("telegram_bot_token") else "не подключён"))
    if initial:
        emit("  Проверки ещё не запущены. В меню выберите «1 — Запустить проверки».")
    return True


def _save_text(state: Path, text: str, *, name="last-report.txt") -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".report-", dir=state)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        atomic_replace(temporary, state / name)
    finally:
        Path(temporary).unlink(missing_ok=True)


async def execute_diagnostics(root: Path):
    from litechecker.windows_diagnostics import diagnose

    state = _state_root(root)
    state.mkdir(mode=0o700, exist_ok=True)
    async with AsyncFileLock(
        state / "trial.lock", timeout=0, mode=0o600,
        preserve_lock_file=True, run_in_executor=True,
    ):
        # Replace stale diagnostics before networking; an interrupted run must
        # not leave yesterday's successful diagnosis looking current.
        _save_text(state, "Диагностика начата, но ещё не завершена. Этот файл не подтверждает доступность.",
                   name="last-diagnostics.txt")
        try:
            result = await diagnose()
        except (KeyboardInterrupt, asyncio.CancelledError):
            _save_text(state, "Диагностика остановлена. Текущая доступность не определена.",
                       name="last-diagnostics.txt")
            raise
        _save_text(state, result.text, name="last-diagnostics.txt")
        return result


async def execute(settings: WindowsTrialSettings, *, send=False):
    from litechecker.windows_network import WindowsDirectNetwork

    if send and (not settings.telegram_bot_token or not settings.telegram_chat_id):
        raise ValueError("Сначала настройте Telegram: --configure-telegram.")
    async with AsyncFileLock(
        settings.state_dir / "trial.lock", timeout=0, mode=0o600,
        preserve_lock_file=True, run_in_executor=True,
    ):
        # A new unsuccessful trial must not leave the old successful observation
        # masquerading as the latest result. Files are owned by this experiment.
        for name in ("last-observation.json", "last-report.txt"):
            (settings.state_dir / name).unlink(missing_ok=True)
        async with asyncio.timeout(settings.agent.run_deadline_seconds + 60):
            result = await run_trial(
                settings, send=False, network_factory=WindowsDirectNetwork.discover,
                platform_label="Windows · D2 · Cloudflare DoH", validate_after=True,
            )
        _save_text(settings.state_dir, result.text)
        if send:
            # The local measurement is durable before optional delivery starts.
            # A failed or partial send must not hide it or imply acceptance.
            try:
                async with asyncio.timeout(_TELEGRAM_SEND_TIMEOUT_SECONDS):
                    client = TelegramClient(
                        token=settings.telegram_bot_token.get_secret_value(),
                        chat_id=settings.telegram_chat_id, topic_id=settings.telegram_topic_id,
                        proxy_url=settings.telegram_proxy_url.get_secret_value() if settings.telegram_proxy_url else None,
                        max_attempts=1,
                    )
                    await client.send_chunks(chunk_message(result.text))
            except Exception:
                # Exception messages can include bot/proxy credentials.
                result = replace(result, delivery_accepted=False)
            else:
                result = replace(result, delivery_accepted=True)
        return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Пробный DIRECT Windows; без изменения настроек сети")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--xray", default="xray.exe")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--configure-telegram", action="store_true")
    parser.add_argument("--send", action="store_true", help="отправить один явно пробный отчёт")
    parser.add_argument("--diagnose", action="store_true", help="диагностика сети без подписки и Telegram")
    args = parser.parse_args(argv)
    if sys.platform != "win32":
        print("Эта проба запускается только нативно на Windows, не в WSL.")
        return 2
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        root = args.root.absolute()
        state = _state_root(root)
        if args.diagnose:
            if args.send or args.setup or args.configure_telegram:
                raise ValueError("diagnosis is a separate action")
            print("🧪 Диагностика подключения: до минуты. Стоп: Ctrl+C. Настройки сети не меняются.")
            result = asyncio.run(run_with_signals(execute_diagnostics(root)))
            print(result.text)
            print(f"Диагностика: {state / 'last-diagnostics.txt'}")
            return 0 if result.ok else 1
        if args.setup or args.configure_telegram or not (state / "settings.json").exists():
            if configure(root, telegram=args.configure_telegram) is False:
                return 130
            if args.setup or args.configure_telegram:
                print("Настройки сохранены. Проверка не запущена.")
                return 0
        settings = load_settings(root, args.xray)
        print("🧪 Пробная проверка Windows. Стоп: Ctrl+C. Фонового запуска нет.")
        print("Сейчас проверяется выбранное подключение, а не гарантированный обход любого VPN.")
        print("В отчёте сохраняются IP, город/провайдер по IPinfo и имя устройства.")
        result = asyncio.run(run_with_signals(execute(settings, send=args.send)))
        print(result.text)
        print(f"Отчёт: {settings.state_dir / 'last-report.txt'}")
        if args.send:
            if result.delivery_accepted is True:
                print("Telegram: отчёт принят.")
            else:
                print("Telegram: отправка не подтверждена. Локальный отчёт сохранён.")
                return 1
        return 0 if result.available else 1
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("Пробная проверка остановлена.")
        return 130
    except Exception:
        print("Проверка не завершена. Проверьте настройки, зависимости и подключение; предыдущие результаты не подтверждают текущую доступность.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
