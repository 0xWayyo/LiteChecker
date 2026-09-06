"""Small terminal UI for the native Windows monitor."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys
from typing import Callable

from litechecker.terminal_ui import display_text, emit, frame, prompt


_REPORT_LIMIT = 2 * 1024 * 1024


def _configure_console_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


class _Controls:
    @staticmethod
    def status(root: Path):
        from litechecker.windows_control import status
        return status(root)

    @staticmethod
    async def start(root: Path):
        from litechecker.windows_control import start
        return await start(root)

    @staticmethod
    async def stop(root: Path):
        from litechecker.windows_control import stop
        return await stop(root)

    @staticmethod
    async def request_update(root: Path):
        from litechecker.windows_control import request_update
        return await request_update(root)


def _settings_path(root: Path) -> Path:
    return root / "windows-state" / "settings.json"


def ensure_update_channel(root: Path) -> bool:
    """Install bundled schema-1 trust once; never replace installed trust."""
    from litechecker.update_launcher import read_bytes
    from litechecker.updater import initialize_channel

    root = Path(root).absolute()
    source = root / "update-channel.json"
    if not source.exists() and not source.is_symlink():
        return False
    return initialize_channel(root, read_bytes(root, source, 64 * 1024))


def ensure_initial_settings(root: Path, *, configure_fn=None) -> bool:
    """Complete or cancel the visible setup once, before the first menu."""
    from litechecker.windows_trial import configure

    configure_fn = configure if configure_fn is None else configure_fn
    settings = _settings_path(root)
    if settings.is_symlink() or settings.is_junction():
        raise ValueError("Небезопасный файл настроек")
    if not settings.is_file():
        return configure_fn(root, initial=True) is not False
    return True


def _show_report(root: Path, output_fn: Callable[[str], None]) -> None:
    report = root / "windows-state" / "last-report.txt"
    if not report.exists():
        output_fn("Отчёта пока нет")
        return
    if report.is_symlink() or report.is_junction() or not report.is_file():
        output_fn("Не получилось открыть отчёт")
        return
    if report.stat().st_size > _REPORT_LIMIT:
        output_fn("Отчёт слишком большой")
        return
    output_fn(report.read_text(encoding="utf-8"))


def _state_text(result: dict) -> tuple[str, str]:
    state = result.get("state") if isinstance(result, dict) else "unknown"
    version = result.get("version") if isinstance(result, dict) else None
    suffix = f" · {version}" if isinstance(version, str) and version else ""
    if state in {"running", "starting"} and result.get("phase") == "stopping":
        return f"🟡 ОСТАНАВЛИВАЕТСЯ{suffix}", "Остановить проверки"
    if state == "running":
        return f"🟢 РАБОТАЕТ{suffix}", "Остановить проверки"
    if state == "starting":
        return f"🟡 ЗАПУСКАЕТСЯ{suffix}", "Остановить проверки"
    if state == "stopped":
        return f"🔴 ОСТАНОВЛЕН{suffix}", "Запустить проверки"
    return f"❔ СТАТУС НЕИЗВЕСТЕН{suffix}", "Обновить статус"


def _run(coro) -> dict:
    result = asyncio.run(coro)
    return result if isinstance(result, dict) else {}


def _update_message(result: dict) -> str:
    status = result.get("status")
    return {
        "updated": "Обновление установлено",
        "current": "Установлена последняя версия",
        "requested": "Обновление выполняется",
        "pending": "Обновление выполняется",
        "busy": "Обновление выполняется. Запустите мониторинг после его завершения",
        "unconfigured": "Обновления не настроены",
        "disabled": "Обновления отключены",
        "rolled-back": "Сохранена предыдущая рабочая версия",
    }.get(status, "Не получилось проверить обновления")


def _stop_for_settings(root: Path, controls, output_fn) -> bool:
    try:
        current = controls.status(root)
    except Exception:
        output_fn("Настройки не изменены: статус неизвестен")
        return False
    state = current.get("state") if isinstance(current, dict) else "unknown"
    if state == "stopped":
        return True
    if state not in {"running", "starting"}:
        output_fn("Настройки не изменены: статус неизвестен")
        return False
    try:
        output_fn("Останавливаем проверки для изменения настроек…")
        stopped = _run(controls.stop(root))
        verified = controls.status(root)
    except Exception:
        output_fn("Настройки не изменены: не получилось остановить мониторинг")
        return False
    if stopped.get("status") not in {"stopped", "stopping"} or verified.get("state") != "stopped":
        output_fn("Настройки не изменены: не получилось остановить мониторинг")
        return False
    output_fn("Мониторинг остановлен. После настройки запустите его снова")
    return True


def _settings_menu(root, *, controls, input_fn, output_fn, configure_fn, diagnostics_fn) -> None:
    while True:
        frame("НАСТРОЙКИ", output=output_fn)
        output_fn("1. Ссылка подписки")
        output_fn("2. Telegram")
        output_fn("3. Диагностика сети")
        output_fn("0. Назад")
        try:
            choice = input_fn("Выберите цифру и нажмите Enter:").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "0":
            return
        try:
            if choice in {"1", "2"}:
                if not _stop_for_settings(root, controls, output_fn):
                    continue
                saved = configure_fn(root, telegram=choice == "2")
                if saved is not False:
                    output_fn("Настройки сохранены. Для запуска вернитесь в главное меню")
            elif choice == "3":
                output_fn("Проверяем сеть. Ожидайте завершения диагностики…")
                _run(diagnostics_fn(root))
                output_fn(f"Диагностика: {root / 'windows-state' / 'last-diagnostics.txt'}")
            else:
                output_fn("Нет такого пункта")
        except Exception:
            output_fn("Не получилось выполнить действие. Попробуйте снова")


def run_menu(
    root: Path,
    *,
    controls=None,
    input_fn=prompt,
    output_fn=emit,
    configure_fn=None,
    diagnostics_fn=None,
) -> int:
    from litechecker.windows_trial import configure, execute_diagnostics

    root = Path(root).absolute()
    controls = _Controls() if controls is None else controls
    configure_fn = configure if configure_fn is None else configure_fn
    diagnostics_fn = execute_diagnostics if diagnostics_fn is None else diagnostics_fn
    while True:
        try:
            current = controls.status(root)
        except Exception:
            current = {"state": "unknown"}
        if not isinstance(current, dict):
            current = {"state": "unknown"}
        label, action = _state_text(current)
        hint = "Проверки работают в фоне" if current.get("state") == "running" and current.get("phase") != "stopping" else (
            "Проверки не выполняются" if current.get("state") == "stopped" else "Enter — обновить статус")
        frame("LITECHECKER", (label, hint), output=output_fn)
        output_fn("  Windows · Данные: " + display_text(str(root / "windows-state")))
        output_fn(f"\n  1  {action}")
        output_fn("  2  Последний отчёт")
        output_fn("  3  Настройки")
        output_fn("  4  Проверить обновления")
        output_fn("\n  0  Закрыть окно")
        output_fn("\n  Закрытие окна не останавливает проверки. Enter — обновить статус.")
        try:
            choice = input_fn("Выберите цифру и нажмите Enter:").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        if not choice:
            continue
        if choice == "0":
            return 0
        if choice == "1":
            state = current.get("state") if isinstance(current, dict) else "unknown"
            if state == "unknown":
                continue
            try:
                if state in {"running", "starting"}:
                    output_fn("Останавливаем проверки…")
                    result = _run(controls.stop(root))
                    output_fn(
                        "Мониторинг остановлен" if result.get("status") == "stopped"
                        else "Мониторинг останавливается" if result.get("status") == "stopping"
                        else "Не получилось остановить мониторинг"
                    )
                else:
                    output_fn("Запускаем проверки…")
                    result = _run(controls.start(root))
                    output_fn(
                        "Мониторинг запускается" if result.get("status") in {"started", "starting"}
                        else "Мониторинг уже работает" if result.get("status") == "already-running"
                        else "Не получилось запустить мониторинг"
                    )
            except Exception:
                output_fn("Не получилось выполнить действие. Попробуйте снова")
        elif choice == "2":
            try:
                _show_report(root, output_fn)
            except Exception:
                output_fn("Не получилось открыть отчёт")
        elif choice == "3":
            _settings_menu(
                root, controls=controls, input_fn=input_fn, output_fn=output_fn,
                configure_fn=configure_fn, diagnostics_fn=diagnostics_fn,
            )
        elif choice == "4":
            try:
                output_fn("Ищем обновление. Если оно есть, установим его автоматически…")
                output_fn(_update_message(_run(controls.request_update(root))))
            except Exception:
                output_fn("Не получилось проверить обновления")
        else:
            output_fn("Нет такого пункта")


def main(argv=None) -> int:
    _configure_console_streams()
    parser = argparse.ArgumentParser(description="LiteChecker Windows")
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        ensure_update_channel(args.root.absolute())
        if not ensure_initial_settings(args.root.absolute()):
            return 0
        return run_menu(args.root.absolute())
    except Exception:
        print("Не получилось открыть LiteChecker. Проверьте папку и настройки")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
