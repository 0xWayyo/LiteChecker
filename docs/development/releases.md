# Выпуск трёх платформ LiteChecker

Production 0.6.3 использует один исходный commit, версию `0.6.3`, sequence `11`
и существующий ключ Ed25519. `scripts/release.py` работает локально, без загрузки
в GitHub. Старые релизы 0.5.x не изменяются. Для выпуска используются
`package_platforms.py`, `package_desktop.py` и `release.py`; пользовательские
архивы содержат только публичные файлы своего платформенного профиля.

## Проверки перед сборкой

Из проверенного checkout выполните `uv sync --locked --group dev`, затем:

```sh
.venv/bin/python -m pytest -q
.venv/bin/python -m pytest tests/test_platform_distribution.py tests/test_platform_updates.py -q
```

До публикации обязательны зелёные CI на macOS, Linux и Windows. На соответствующих
хостах проверяются распакованные платформенные исходники, подготовка закреплённых
runtime и offline validation. Windows дополнительно выполняет настоящий полный
ввод PowerShell, NTFS ACL, Job Objects, процессы и обновления. Пропуски Windows
тестов на macOS не заменяют этот gate. Для тестов используйте только временный
сгенерированный ключ и тестовые настройки; live-подписки, Telegram и изменение
VPN или служб хоста не требуются.

CI выполняет `uv run --no-sync python scripts/check_release_artifacts.py
--platform-smoke dist/platform-smoke`: все профили собираются одним снимком,
сверяются общие байты и проверяются target/version/CONTENTS, затем импортируются
только файлы распакованного пакета текущей ОС. macOS готовит закреплённый runtime
командой `native-direct.sh prepare --root CANDIDATE` из `_app` публичного wrapper
без установки launchd.
Linux собирает Dockerfile именно из профиля и запускает CLI с `--network none`.
Windows проверяет настоящий публичный BAT, полный ввод PowerShell и подготовку
закреплённого Python/Xray из `_app`. Wheel/sdist остаются отдельным авторским gate.

Новое открытие меню выбирает проверенный active source и его runtime. Данные
остаются у baseline. PID, время создания и точная команда живого меню проверяются
перед очисткой; старое меню удерживает свою версию даже через несколько обновлений.
На POSIX наследуемая блокировка дополнительно удерживает среду работающего
мастера настроек, даже если само меню было принудительно завершено.
Завершённый процесс и устаревший JSON не удерживают релиз. Windows supervisor
продолжает исполнять baseline до остановки: worker и UI обязаны сохранять этот
процессный ABI. Горячей замены работающего supervisor нет. Baseline не очищается.

Публикация выполняется только с явного разрешения владельца после проверок.
До публикации draft его файлы не должны менять stable channel.

## Одна команда для production

Путь к существующему приватному ключу автор передаёт явно; файл должен быть
обычным, без символических ссылок, с правами `0600`. Не создавайте новый production
ключ: установленное доверие не сбрасывается. Значение ключа не передаётся в CLI.
Создание приватных ключей и подпись выполняются на macOS/Linux. Публичные профили
собираются и на Windows; отсутствие POSIX `fchmod` не считается гарантией
приватных NTFS-прав, поэтому запись приватного ключа там отклоняется.

```sh
.venv/bin/python scripts/release.py build-platforms \
  --version 0.6.3 --sequence 11 --repository 0xWayyo/LiteChecker \
  --private-key /absolute/path/signing-private.key \
  --output dist/releases/0.6.3
```

Команда читает явный список публичных файлов один раз, строит три профиля,
проверяет их CONTENTS, marker, версию и канал, подписывает и повторно проверяет
каждую подпись. Локальные `secrets/`, настройки, рабочие состояния, тесты и
авторские инструменты не читаются и не включаются. Приватный ключ читается только
из указанного пути; его байты в архиве блокируют подпись. Общие модули во всех
использующих их профилях побайтно одинаковы.

| Артефакт | Назначение |
| --- | --- |
| `LiteChecker-0.6.3-Windows.zip` | Установка Windows: `LiteChecker.bat`, `_app` и инструкция |
| `LiteChecker-0.6.3-macOS.zip` | Установка macOS: `INSTALL.command`, `_app` и инструкция |
| `LiteChecker-0.6.3-Linux.zip` | Установка Linux с Docker и тот же подписанный источник обновления |
| `LiteChecker-0.6.3-windows-update-source.zip` | Технический плоский источник обновления Windows |
| `LiteChecker-0.6.3-macos-update-source.zip` | Технический плоский источник обновления macOS |
| `release-windows.json`, `release-macos.json`, `release-linux.json` | Подписанные метаданные schema 2 каждого target |
| Пять `*.zip.sha256` | Проверка доставки; не заменяет подпись |

Всего 13 файлов. Общий `package_desktop.py` собирает Windows и macOS wrappers:
все байты файлов и CONTENTS исходника сохранены в `_app`; подписанная metadata
ссылается на отдельный неизменённый source ZIP. Внешний macOS launcher также
входит в проверяемый source как `scripts/macos-launcher.command`.
Для Linux установочный ZIP одновременно служит источником обновлений.
Версия исходного pyproject и lock должна совпадать с `--version`.

Ни один существующий файл результата не перезаписывается. Для повторной сборки
выбирайте другую пустую папку. Опубликованный ошибочный пакет исправляйте новым
sequence и версией: даже неудавшаяся загрузка аутентифицированного объявления
может сохранить high-water. Никогда не сбрасывайте ключ, канал или high-water.

## Отдельная упаковка и подпись

Для offline CI можно создать временную пару ключей через `release.py keygen`
с явными `--private-key` и `--public-key` в тестовой папке. Для упаковки без
доступа к приватному ключу:

```sh
.venv/bin/python scripts/package_platforms.py \
  --version 0.6.3 --repository 0xWayyo/LiteChecker \
  --public-key /absolute/path/signing-public.key --output dist/platform-sources
.venv/bin/python scripts/release.py build \
  --platform macos --archive dist/platform-sources/LiteChecker-0.6.3-macos-update-source.zip \
  --version 0.6.3 --sequence 11 --repository 0xWayyo/LiteChecker \
  --private-key /absolute/path/signing-private.key --output dist/macos-signed
```

Каждый source содержит `distribution.json` schema 1 и `update-channel.json`
schema 2 с собственным `platform`, ключом и адресом
`https://github.com/0xWayyo/LiteChecker/releases/latest/download/release-PLATFORM.json`.
Schema 2 payload подписывает `platform`, `version`, `sequence`, `published_at`
и `artifact`. Канонизация: `json.dumps(payload, sort_keys=True,
separators=(",", ":"), ensure_ascii=True)`. Архив, marker, версия, ключ и URL
канала проверяются до выпуска. Не используйте schema 1 для production.

## Установка и публикация

Версия 0.6.3 подходит для новых установок и подписанного обновления с 0.6.0/0.6.1/0.6.2;
настройки, ID и существующее доверие сохраняются. macOS использует компактный wrapper:
`INSTALL.command`, `_app` и инструкция. Внутри `_app` остаётся плоский source,
установка по-прежнему идёт в `~/Library/Application Support/LiteChecker`.
Handoff очищает только проверенное содержимое `_app`, оставляя там
`LiteChecker.command`. Внешний `INSTALL.command` после этого открывает его.
До копирования файлов установщик
проверяет canonical marker и канал существующей установки; несовместимая папка
остаётся без изменений. Совместимый повтор после прерывания сохраняет настройки
и доверие. Ручное переформатирование JSON канала не поддерживается установщиком;
используйте штатное меню. Старую папку не удаляйте и не переносите автоматически.

После всех CI gates автор создаёт draft Release `v0.6.3` из проверенного commit,
загружает все 13 файлов и проверяет имена и SHA-256. Публикация и latest выполняются
отдельно после проверки; инструменты сборки ничего не публикуют.
