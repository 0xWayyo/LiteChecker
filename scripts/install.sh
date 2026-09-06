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
if [[ "$system" == Darwin ]]; then
    exec bash "$project_dir/scripts/install-macos.sh" "$project_dir"
fi

# First-install identity must be checked before Docker, setup or runtime writes.
# Unprofiled developer fixtures have neither a channel nor production guide.
profile_refusal='Пакет или сохранённый канал не соответствует Linux. Файлы устройства сохранены. Распакуйте Linux ZIP в новую папку; старый канал не сбрасывайте.'
if [[ -e distribution.json || -L distribution.json || -e update-channel.json || -L update-channel.json || -e LINUX.md ]]; then
    [[ "$system" == Linux ]] || fail "$profile_refusal"
    [[ -f CONTENTS.sha256.json && ! -L CONTENTS.sha256.json ]] || fail "$profile_refusal"
    [[ -d scripts && ! -L scripts && -f scripts/install-profile.sh && ! -L scripts/install-profile.sh ]] || fail "$profile_refusal"
    # Verify the shared reader before executing it; then use the reader
    # before hashing marker/channel inputs (which might themselves be unsafe).
    expected=$(awk '$1 == "\"scripts/install-profile.sh\":" {value=$2; gsub(/[\",]/, "", value); print value}' CONTENTS.sha256.json)
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "$profile_refusal"
    if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum scripts/install-profile.sh);
    else actual=$(shasum -a 256 scripts/install-profile.sh); fi
    [[ "${actual%% *}" == "$expected" ]] || fail "$profile_refusal"
    source "$project_dir/scripts/install-profile.sh"
    marker=$(profile_line "$project_dir/distribution.json" 4096) || fail "$profile_refusal"
    [[ "$marker" == '{"platform":"linux","schema":1}' ]] || fail "$profile_refusal"
    incoming_channel=$(profile_line "$project_dir/update-channel.json" 65536) || fail "$profile_refusal"
    channel_pattern='^\{"enabled":true,"manifest_urls":\["https://github\.com/[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}/releases/latest/download/release-linux\.json"\],"platform":"linux","public_key":"[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=","schema":2\}$'
    [[ "$incoming_channel" =~ $channel_pattern ]] || fail "$profile_refusal"
    for relative in distribution.json update-channel.json; do
        expected=$(awk -v key="\"$relative\":" '$1 == key {value=$2; gsub(/[\",]/, "", value); print value}' CONTENTS.sha256.json)
        [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || fail "$profile_refusal"
        if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$relative");
        else actual=$(shasum -a 256 "$relative"); fi
        [[ "${actual%% *}" == "$expected" ]] || fail "$profile_refusal"
    done
    if [[ -e .updates/channel.json || -L .updates/channel.json ]]; then
        installed_channel=$(profile_line "$project_dir/.updates/channel.json" 65536) || fail "$profile_refusal"
        disabled_channel=${incoming_channel/\"enabled\":true/\"enabled\":false}
        [[ "$installed_channel" == "$incoming_channel" || "$installed_channel" == "$disabled_channel" ]] || fail "$profile_refusal"
    fi
fi

if ! command -v docker >/dev/null 2>&1; then
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
    fail 'Docker пока недоступен. Запустите службу Docker и проверьте права своего пользователя.
Команда docker info должна выполняться без sudo. Затем снова запустите INSTALL.sh.
Инструкция: https://docs.docker.com/engine/install/linux-postinstall/'
fi

[[ ! -L state ]] || fail 'Папка state не должна быть символической ссылкой.'
[[ ! -e state || -d state ]] || fail 'state должна быть обычной папкой.'
[[ ! -L state/install.log ]] || fail 'Журнал state/install.log не должен быть символической ссылкой.'
[[ ! -e state/install.log || -f state/install.log ]] || fail 'state/install.log должен быть обычным файлом.'
[[ ! -L .env.standalone ]] || fail 'Файл .env.standalone не должен быть символической ссылкой.'
if [[ -t 0 && -f scripts/prepare-updater.sh && ! -L scripts/prepare-updater.sh ]]; then
    printf '%s\n' 'Подготавливаю среду для пошагового ввода настроек.'
    bash scripts/prepare-updater.sh --root "$project_dir"
    PYTHONPATH="$project_dir/src" PYTHONDONTWRITEBYTECODE=1 \
        "$project_dir/.updater-runtime/venv/bin/python" -m litechecker.device_setup \
        --root "$project_dir" --system docker --initial
elif [[ -e .env.standalone ]]; then
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
start_checker() {
    # The wizard prepares the updater before the first start. Managed start
    # deliberately uses --no-build, so an explicit install must build the
    # baseline image first. Active signed-release selection stays in updater.
    if [[ -x .updater-runtime/venv/bin/python && -f scripts/update.sh && ! -L scripts/update.sh ]]; then
        bash run.sh build || return $?
    fi
    bash run.sh start
}
if start_checker > state/install.log 2>&1; then
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
        printf '%s\n' 'Внимание: чекер запущен, но автообновления не настроены. См. LINUX.md.' >&2
    fi
fi
printf '\n%s\n' 'Контейнер запущен в фоне. Дождитесь первого отчёта в Telegram; это окно можно закрыть.'
printf '%s\n' 'Проверка работает, пока компьютер включён, не спит и Docker запущен.'
printf 'Папка установки: %s\n' "$project_dir"
printf '%s\n' 'Управление: снова запустите bash INSTALL.sh.' 'В меню доступны запуск, остановка, настройки, журнал и ручное обновление.'
