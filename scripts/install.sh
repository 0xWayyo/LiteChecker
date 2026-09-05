#!/usr/bin/env bash
# Shared launcher: configure this device once, then start its background checker.
set +x
set -euo pipefail
umask 077
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$project_dir"

system=$(uname -s)
fail() { printf '\n%s\n' "$*" >&2; exit 2; }

printf '%s\n' 'LiteChecker — установка и запуск' ''
printf '%s\n' 'Автоопределение: компьютер + ОС; город и сеть через IPinfo по внешнему IP.'
if [[ "$system" == Darwin ]]; then
    printf '%s\n' 'IPinfo не получает токен, подписку или имя компьютера. Отключение: LC_AUTO_CITY=false и LC_AUTO_NETWORK=false в native-settings.json.' ''
else
    printf '%s\n' 'IPinfo не получает токен, подписку или имя компьютера. Отключение: LC_AUTO_CITY=false и LC_AUTO_NETWORK=false в .env.standalone.' ''
fi
if [[ -n "${WSL_DISTRO_NAME:-}" && "$project_dir" == /mnt/* ]]; then
    exec bash "$project_dir/scripts/install-wsl.sh" "$project_dir"
fi
if [[ "$system" == Darwin ]]; then
    exec bash "$project_dir/scripts/install-macos.sh" "$project_dir"
fi

if ! command -v docker >/dev/null 2>&1; then
    if [[ "$system" == Darwin || -n "${WSL_DISTRO_NAME:-}" ]]; then
        fail 'Установите и откройте Docker Desktop: https://www.docker.com/products/docker-desktop/
В Windows включите Settings → Resources → WSL Integration для Ubuntu.
Когда Docker запустится, снова откройте этот установщик.'
    fi
    fail 'Сначала установите Docker Engine и плагин Docker Compose:
https://docs.docker.com/engine/install/
После установки проверьте доступ к Docker для своего пользователя и снова запустите INSTALL.sh.'
fi
if ! docker compose version >/dev/null 2>&1; then
    fail 'Не найден Docker Compose. Обновите Docker Desktop или установите плагин Compose:
https://docs.docker.com/compose/install/
Затем снова запустите установщик.'
fi
if ! docker info >/dev/null 2>&1; then
    if [[ "$system" == Darwin || -n "${WSL_DISTRO_NAME:-}" ]]; then
        fail 'Docker пока недоступен. Откройте Docker Desktop и дождитесь запуска.
В Windows включите Settings → Resources → WSL Integration для Ubuntu.
Затем снова откройте этот установщик.'
    fi
    fail 'Docker пока недоступен. Запустите службу Docker и проверьте права своего пользователя.
Команда docker info должна выполняться без sudo. Затем снова запустите INSTALL.sh.
Инструкция: https://docs.docker.com/engine/install/linux-postinstall/'
fi

[[ ! -L state ]] || fail 'Папка state не должна быть символической ссылкой.'
[[ ! -e state || -d state ]] || fail 'state должна быть обычной папкой.'
[[ ! -L state/install.log ]] || fail 'Журнал state/install.log не должен быть символической ссылкой.'
[[ ! -e state/install.log || -f state/install.log ]] || fail 'state/install.log должен быть обычным файлом.'
[[ ! -L .env.standalone ]] || fail 'Файл .env.standalone не должен быть символической ссылкой.'
if [[ -e .env.standalone ]]; then
    [[ -f .env.standalone ]] || fail '.env.standalone должен быть обычным файлом.'
    printf '%s\n' 'Использую сохранённые настройки этого устройства.'
else
    bash run.sh setup --quick
fi

mkdir -p state
chmod 700 state
: >> state/install.log
chmod 600 state/install.log
printf '\n%s\n' 'Загружаю компоненты и запускаю LiteChecker. Это может занять несколько минут.'
if bash run.sh start > state/install.log 2>&1; then
    :
else
    install_exit=$?
    printf '\nНе удалось запустить LiteChecker. Журнал установки: %s/state/install.log\n' "$project_dir" >&2
    tail -n 20 state/install.log >&2
    exit "$install_exit"
fi
bash run.sh status
if [[ -f update-channel.json || -f .updates/channel.json ]]; then
    if bash scripts/prepare-updater.sh --root "$project_dir" \
        && { [[ ! -f update-channel.json ]] || bash scripts/update.sh configure --channel "$project_dir/update-channel.json"; } \
        && bash scripts/update.sh schedule; then
        printf '%s\n' 'Проверка подписанных обновлений настроена.'
    else
        printf '%s\n' 'Внимание: чекер запущен, но автообновления не настроены. См. docs/operations/updates.md.' >&2
    fi
fi
printf '\n%s\n' 'Контейнер запущен в фоне. Дождитесь первого отчёта в Telegram; это окно можно закрыть.'
printf '%s\n' 'Проверка работает, пока компьютер включён, не спит и Docker запущен.'
printf 'Папка установки: %s\n' "$project_dir"
printf '%s\n' 'Остановить: bash run.sh stop' 'Посмотреть журнал: bash run.sh logs'
