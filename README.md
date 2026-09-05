# LiteChecker

LiteChecker проверяет доступность VLESS/REALITY-подписки с одного или нескольких
устройств и отправляет диагностические отчёты. Версия: `0.3.0`.

## Быстрый старт

Откройте [последний релиз](https://github.com/0xWayyo/LiteChecker/releases/latest),
скачайте прикреплённый клиентский ZIP (не архив `Source code`), распакуйте его и
запустите installer для своей ОС:

- macOS: откройте `INSTALL.command` — native DIRECT работает без Docker;
- Windows: откройте `INSTALL.bat` — установка выполняется в Ubuntu/WSL2;
- Linux: выполните `bash INSTALL.sh`.

В клиентском ZIP — установщики, необходимый runtime, короткая инструкция и
обновлятор. Тесты, CI, инструменты разработки, подробные руководства и примеры
центрального collector остаются только в исходном репозитории.

## Сборка из checkout

Исходный checkout намеренно не содержит `CONTENTS.sha256.json`. Разработчику
нужно сначала собрать клиентский архив и запускать installer из распакованной
копии. Установите [`uv`](https://docs.astral.sh/uv/getting-started/installation/),
затем из корня checkout создайте окружение строго по `uv.lock` и запустите
упаковщик через него:

```bash
uv sync --frozen --no-dev
uv run --frozen --no-dev python scripts/package_agent.py
```

Для одного диагностического прогона на macOS откройте `TRY-DIRECT.command`.
Флаг packager `--direct-trial` сохранён как совместимый alias и не создаёт второй
вид архива.

## Документация

- [Установка агента](docs/installation/agent.md)
- [Эксплуатация и развёртывание](docs/operations/full-reference.md)
- [Пробный DIRECT](docs/operations/direct-trial.md)
- [Обновления](docs/operations/updates.md)
- [Разработка и выпуск релиза](https://github.com/0xWayyo/LiteChecker/blob/main/docs/development/releases.md)

Шаблоны конфигурации находятся в [`examples/`](examples/). Рабочие файлы
`.env.standalone`, `.env.agent`, `.env.collector`, `.env` и `agents.json`
создаются или копируются рядом с root compose-файлами и не должны попадать в Git.

Центральный collector — опциональный режим. Для него установите extra:

```bash
uv sync --frozen --extra collector
```

Обычные native/standalone/updater команды не требуют FastAPI или uvicorn.
