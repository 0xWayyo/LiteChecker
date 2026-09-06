"""Interactive, transactional LiteChecker credential configuration."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from litechecker.native_config import NATIVE_CONFIG_KEYS
from litechecker.native_runtime import atomic_write, read_bounded_regular
from litechecker.telegram_proxy import validate_telegram_proxy_url
from litechecker.updater import _try_lock


_MAX_INPUT = 4096
_TOKEN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{20,256}\Z", re.ASCII)
_CHAT = re.compile(r"-?[1-9][0-9]{0,19}\Z", re.ASCII)
_ENV_LINE = re.compile(
    r"(?P<prefix>[ \t]*(?P<key>LC_AGENT_NAME|LC_TELEGRAM_CHAT_ID)[ \t]*=[ \t]*)"
    r"(?P<value>.*?)(?P<ending>\r?\n)?\Z"
)
_ANY_ENV_LINE = re.compile(
    r"[ \t]*(?:export[ \t]+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)[ \t]*=.*\Z"
)
_DOCKER_DEFAULT = (
    "LC_AGENT_CITY=''\n"
    "LC_AGENT_NAME={name}\n"
    "LC_HOST_NAME=''\n"
    "LC_HOST_OS=''\n"
    "LC_TELEGRAM_CHAT_ID={chat}\n"
    "LC_TELEGRAM_BOT_TOKEN_FILE='/run/secrets/telegram_bot_token'\n"
    "LC_SUBSCRIPTION_URL_FILE='/run/secrets/subscription_url'\n"
    "LC_STATE_DIR='/var/lib/litechecker'\n"
    "LC_INTERVAL_SECONDS='600'\n"
)


@dataclass(frozen=True)
class _Loaded:
    config: bytes | None
    subscription: str | None
    token: str | None
    proxy: str | None
    chat: str | None
    name: str | None
    native: dict[str, str | bool | int] | None = None


class _InputError(ValueError):
    """One closed, user-safe validation message."""


class _CommitFailure(RuntimeError):
    def __init__(self, *, rollback_complete: bool) -> None:
        super().__init__("configuration commit failed")
        self.rollback_complete = rollback_complete


def _is_interactive() -> bool:
    return sys.stdin.isatty()


def _prompt(label: str, *, secret: bool) -> str:
    # `secret` classifies the setting for callers; typing is intentionally
    # visible. Let the terminal echo it, without printing values into logs.
    return input(label)


def _private_directory(path: Path, *, required: bool) -> None:
    if not path.exists() and not path.is_symlink():
        if required:
            raise ValueError("missing directory")
        return
    if path.is_symlink():
        raise ValueError("unsafe directory")
    metadata = path.stat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        or (os.name == "posix" and metadata.st_mode & 0o077)
    ):
        raise ValueError("unsafe directory")


def _validate_root(root: Path) -> Path:
    supplied = Path(root)
    if ".." in supplied.parts:
        raise ValueError("unsafe root")
    root = supplied.absolute()
    if any(candidate.is_symlink() for candidate in (root, *root.parents)) or not root.is_dir():
        raise ValueError("unsafe root")
    metadata = root.stat()
    if not stat.S_ISDIR(metadata.st_mode) or (
        hasattr(os, "geteuid") and metadata.st_uid != os.geteuid()
    ):
        raise ValueError("unsafe root")
    return root


def _read_optional(path: Path) -> bytes | None:
    if not path.exists() and not path.is_symlink():
        return None
    return read_bounded_regular(path, private=True)


def _secret(data: bytes | None) -> str | None:
    if data is None:
        return None
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ValueError("invalid private value") from None
    if not value or len(value) > _MAX_INPUT or _has_control(value):
        raise ValueError("invalid private value")
    return value


def _has_control(value: str) -> bool:
    return any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in value)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate setting")
        result[key] = value
    return result


def _parse_native(data: bytes | None) -> tuple[dict[str, str | bool | int] | None, str | None, str | None]:
    if data is None:
        return None, None, None
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ValueError("invalid native settings") from None
    if (
        not isinstance(payload, dict)
        or any(key not in NATIVE_CONFIG_KEYS for key in payload)
        or any(type(value) not in (str, bool, int) for value in payload.values())
    ):
        raise ValueError("invalid native settings")
    name = payload.get("LC_AGENT_NAME")
    chat = payload.get("LC_TELEGRAM_CHAT_ID")
    if name is not None and not isinstance(name, str):
        raise ValueError("invalid native name")
    if chat is not None and not isinstance(chat, str):
        chat = str(chat) if type(chat) is int else None
    return payload, chat, name


def _decode_env_value(encoded: str) -> str:
    raw = encoded.strip()
    if not raw:
        return ""
    if raw.startswith('"') or raw.endswith('"'):
        raise ValueError("unsupported quoted setting")
    if raw.startswith("'"):
        if len(raw) < 2 or not raw.endswith("'"):
            raise ValueError("invalid quoted setting")
        inner = raw[1:-1]
        decoded: list[str] = []
        index = 0
        while index < len(inner):
            if inner[index:index + 2] == "\\'":
                decoded.append("'")
                index += 2
            elif inner[index] == "'":
                raise ValueError("invalid quoted setting")
            else:
                decoded.append(inner[index])
                index += 1
        return "".join(decoded)
    if any(character.isspace() or character in "'\"\\$`#" for character in raw):
        raise ValueError("unsafe unquoted setting")
    return raw


def _parse_docker(data: bytes | None) -> tuple[str | None, str | None]:
    if data is None:
        return None, None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid compose settings") from None
    assignments: set[str] = set()
    found: dict[str, str] = {}
    for line in text.splitlines(keepends=True):
        body = line.removesuffix("\n").removesuffix("\r")
        if not body.strip() or body.lstrip().startswith("#"):
            continue
        assignment = _ANY_ENV_LINE.fullmatch(body)
        if assignment is None or _has_control(body):
            raise ValueError("malformed compose setting")
        assigned_key = assignment.group("key")
        if assigned_key in assignments:
            raise ValueError("duplicate compose setting")
        assignments.add(assigned_key)
        match = _ENV_LINE.fullmatch(line)
        if match is None:
            if assigned_key in {"LC_AGENT_NAME", "LC_TELEGRAM_CHAT_ID"}:
                raise ValueError("unsupported recognized setting")
            continue
        key = match.group("key")
        value = _decode_env_value(match.group("value"))
        if len(value) > _MAX_INPUT or _has_control(value):
            raise ValueError("unsafe compose setting")
        found[key] = value
    return found.get("LC_TELEGRAM_CHAT_ID"), found.get("LC_AGENT_NAME")


def _paths(root: Path, system: str) -> dict[str, Path]:
    return {
        "config": root / ("native-settings.json" if system == "native" else ".env.standalone"),
        "subscription": root / "secrets/subscription_url",
        "token": root / "secrets/telegram_bot_token",
        "proxy": root / "secrets/telegram_proxy_url",
    }


def _load(root: Path, system: str) -> tuple[_Loaded, dict[Path, bytes | None]]:
    paths = _paths(root, system)
    _private_directory(root / "secrets", required=False)
    raw = {path: _read_optional(path) for path in paths.values()}
    if system == "native":
        native, chat, name = _parse_native(raw[paths["config"]])
    else:
        native = None
        chat, name = _parse_docker(raw[paths["config"]])
    loaded = _Loaded(
        config=raw[paths["config"]],
        subscription=_secret(raw[paths["subscription"]]),
        token=_secret(raw[paths["token"]]),
        proxy=_secret(raw[paths["proxy"]]),
        chat=chat,
        name=name,
        native=native,
    )
    return loaded, raw


def _valid_subscription(value: str | None) -> bool:
    if value is None or len(value) > _MAX_INPUT or _has_control(value) or any(character.isspace() for character in value):
        return False
    try:
        parsed = urlsplit(value)
        return parsed.scheme == "https" and bool(parsed.hostname) and parsed.username is None and parsed.password is None
    except ValueError:
        return False


def _valid_token(value: str | None) -> bool:
    return value is not None and _TOKEN.fullmatch(value) is not None


def _valid_chat(value: str | None) -> bool:
    return value is not None and _CHAT.fullmatch(value) is not None


def _valid_name(value: str | None) -> bool:
    return value is not None and len(value) <= 128 and not _has_control(value)


def _valid_proxy(value: str | None) -> bool:
    if value is None:
        return True
    try:
        validate_telegram_proxy_url(value)
        return True
    except ValueError:
        return False


def _complete(loaded: _Loaded) -> bool:
    return (
        loaded.config is not None
        and _valid_subscription(loaded.subscription)
        and _valid_token(loaded.token)
        and _valid_chat(loaded.chat)
        and _valid_proxy(loaded.proxy)
        and (loaded.name is None or _valid_name(loaded.name))
    )


def _entered(current: str | None, value: str, *, removable: bool) -> str | None:
    if not value:
        return current
    if removable and value == "-":
        return None
    return value


def _status(value: str | None) -> str:
    return "задан" if value is not None else "не задан"


def _collect(current: _Loaded, *, require_explicit_chat: bool) -> _Loaded:
    subscription = _entered(current.subscription, _prompt(
        f"URL подписки (сейчас: {_status(current.subscription)}) "
        "[Enter — оставить текущий]: ", secret=True
    ), removable=False)
    token = _entered(current.token, _prompt(
        f"Токен Telegram-бота (сейчас: {_status(current.token)}) "
        "[Enter — оставить текущий]: ", secret=True
    ), removable=False)
    shown_chat = current.chat if _valid_chat(current.chat) else "не задан"
    entered_chat = _prompt(
        f"ID Telegram-чата (сейчас: {shown_chat}) [Enter — оставить текущий]: ",
        secret=False,
    )
    chat = _entered(current.chat, entered_chat, removable=False)
    proxy = _entered(current.proxy, _prompt(
        f"Прокси Telegram (сейчас: {_status(current.proxy)}; формат: https/http/socks5 URL) "
        "[Enter — оставить, - — удалить]: ", secret=True
    ), removable=True)
    entered_name = _prompt(
        "Название устройства [Enter — оставить, - — авто]: ", secret=False
    )
    name = "" if entered_name == "-" else (_entered(current.name, entered_name, removable=False) or "")
    proposed = _Loaded(
        config=current.config,
        subscription=subscription,
        token=token,
        proxy=proxy,
        chat=chat,
        name=name,
        native=current.native,
    )
    if not _valid_subscription(proposed.subscription):
        raise _InputError("Некорректный URL подписки. Нужен HTTPS URL.")
    if not _valid_token(proposed.token):
        raise _InputError("Некорректный токен Telegram-бота.")
    if require_explicit_chat and not entered_chat:
        raise _InputError("Некорректный ID Telegram-чата. Введите его явно.")
    if not _valid_chat(proposed.chat):
        raise _InputError("Некорректный ID Telegram-чата. Укажите целое число.")
    if not _valid_proxy(proposed.proxy):
        raise _InputError("Некорректный прокси Telegram. Нужен https/http/socks5 URL.")
    if not _valid_name(proposed.name or ""):
        raise _InputError("Некорректное название устройства.")
    return proposed


def _quote_env(value: str) -> str:
    return "'" + value.replace("'", "\\'") + "'"


def _docker_bytes(original: bytes | None, chat: str, name: str) -> bytes:
    if original is None:
        return _DOCKER_DEFAULT.format(chat=_quote_env(chat), name=_quote_env(name)).encode("utf-8")
    text = original.decode("utf-8")
    values = {"LC_AGENT_NAME": name, "LC_TELEGRAM_CHAT_ID": chat}
    found: set[str] = set()
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        match = _ENV_LINE.fullmatch(line)
        if match is None:
            output.append(line)
            continue
        key = match.group("key")
        found.add(key)
        output.append(match.group("prefix") + _quote_env(values[key]) + (match.group("ending") or ""))
    missing = [key for key in ("LC_AGENT_NAME", "LC_TELEGRAM_CHAT_ID") if key not in found]
    if missing:
        newline = "\r\n" if "\r\n" in text else "\n"
        if output and not output[-1].endswith(("\n", "\r")):
            output.append(newline)
        output.extend(f"{key}={_quote_env(values[key])}{newline}" for key in missing)
    return "".join(output).encode("utf-8")


def _configuration_bytes(system: str, proposed: _Loaded) -> bytes:
    assert proposed.chat is not None and proposed.name is not None
    if system == "docker":
        return _docker_bytes(proposed.config, proposed.chat, proposed.name)
    settings = dict(proposed.native or {})
    settings["LC_AGENT_NAME"] = proposed.name
    settings["LC_TELEGRAM_CHAT_ID"] = proposed.chat
    settings["LC_INTERVAL_SECONDS"] = "600"
    return (json.dumps(settings, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _rollback(before: dict[Path, bytes | None]) -> bool:
    complete = True
    for path, original in reversed(tuple(before.items())):
        try:
            current = _read_optional(path)
            if current == original:
                continue
            if original is None:
                if path.is_symlink():
                    raise ValueError("unsafe rollback path")
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, original, 0o600)
            if _read_optional(path) != original:
                raise OSError("rollback verification failed")
        except BaseException:
            complete = False
    return complete


def _commit(root: Path, system: str, before: dict[Path, bytes | None], proposed: _Loaded) -> None:
    lock = _try_lock(root / ".updates/update.lock", root)
    if lock is None:
        raise _InputError("Настройки заняты обновлением. Повторите позже.")
    try:
        _current, current_raw = _load(root, system)
        if current_raw != before:
            raise _InputError("Настройки изменились параллельно. Откройте их заново.")
        paths = _paths(root, system)
        subscription = (proposed.subscription + "\n").encode("utf-8")
        token = (proposed.token + "\n").encode("utf-8")
        proxy = None if proposed.proxy is None else (proposed.proxy + "\n").encode("utf-8")
        configuration = _configuration_bytes(system, proposed)
        try:
            atomic_write(paths["subscription"], subscription, 0o600)
            atomic_write(paths["token"], token, 0o600)
            if proxy is None:
                paths["proxy"].unlink(missing_ok=True)
            else:
                atomic_write(paths["proxy"], proxy, 0o600)
            atomic_write(paths["config"], configuration, 0o600)
        except BaseException as error:
            rollback_complete = _rollback(before)
            if isinstance(error, KeyboardInterrupt) and rollback_complete:
                raise
            raise _CommitFailure(rollback_complete=rollback_complete) from None
    finally:
        lock.release()


def configure_device(root: Path, system: str, *, initial: bool = False) -> int:
    """Configure one native or Docker installation without starting services."""
    try:
        if system not in {"native", "docker"}:
            raise ValueError("unsupported system")
        checked_root = _validate_root(root)
        loaded, before = _load(checked_root, system)
        if initial and _complete(loaded):
            return 0
        if not _is_interactive():
            print("Настройка не завершена: нужен интерактивный терминал.", file=sys.stderr)
            return 2
        proposed = _collect(loaded, require_explicit_chat=initial)
        _commit(checked_root, system, before, proposed)
    except (EOFError, KeyboardInterrupt):
        print("Настройка отменена; изменения не сохранены.", file=sys.stderr)
        return 130
    except _InputError as error:
        print(str(error), file=sys.stderr)
        return 2
    except _CommitFailure as error:
        if error.rollback_complete:
            print("Не удалось сохранить настройки; исходные настройки восстановлены.", file=sys.stderr)
        else:
            print("Не удалось завершить сохранение; проверьте настройки.", file=sys.stderr)
        return 2
    except Exception:
        print("Не удалось проверить настройки; изменения не внесены.", file=sys.stderr)
        return 2
    print("Настройки сохранены.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--system", required=True, choices=("native", "docker"))
    parser.add_argument("--initial", action="store_true")
    arguments = parser.parse_args(argv)
    return configure_device(arguments.root, arguments.system, initial=arguments.initial)


if __name__ == "__main__":
    raise SystemExit(main())
