#!/usr/bin/env bash
# Linux/macOS/WSL2 launcher. No local Python installation needed.
set +x
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
umask 077

die() { printf '%s\n' "$*" >&2; exit 2; }

dotenv() {
    # Compose single-quoted values are literal, including $ and #.
    local value="$2"
    value=${value//\'/\\\'}
    printf "%s='%s'\n" "$1" "$value"
}

detect_host() {
    local system release
    system=$(uname -s 2>/dev/null || true)
    LC_HOST_NAME=$(hostname -s 2>/dev/null || true)
    case "$system" in
        Darwin)
            LC_HOST_OS=macOS
            LC_HOST_NAME=$(scutil --get ComputerName 2>/dev/null || printf '%s' "$LC_HOST_NAME")
            ;;
        Linux)
            release=$(uname -r 2>/dev/null || true)
            case "$release" in
                *[Mm]icrosoft*|*WSL*) LC_HOST_OS='Windows / WSL' ;;
                *) LC_HOST_OS=Linux ;;
            esac
            ;;
        *) LC_HOST_OS="$system" ;;
    esac
    export LC_HOST_NAME LC_HOST_OS
}

detect_host

action=${1:-help}
if [[ "$(uname -s 2>/dev/null || true)" == Darwin ]]; then
    case "$action" in
        start|check|stop|logs|status)
            exec bash "$(pwd -P)/scripts/native-direct.sh" "$action"
            ;;
    esac
fi

setup() {
    [[ ! -e .env.standalone && ! -L .env.standalone ]] || die 'Настройки уже есть. Измените .env.standalone вручную; ID сохраняется в state/standalone.'
    local city='' name='' chat='' token='' subscription=''
    if [[ "${1:-}" != --quick ]]; then
        read -r -p 'Город [Enter — определить через IPinfo]: ' city
        read -r -p "Название [Enter — автоматически: ${LC_HOST_NAME:-устройство} (${LC_HOST_OS:-ОС})]: " name
        read -r -p 'ID Telegram-чата [-5361201677]: ' chat
    fi
    chat=${chat:--5361201677}
    [[ "$chat" =~ ^-?[0-9]+$ ]] || die 'ID чата должен быть числом (для группы — с минусом).'
    for item in secrets state state/standalone secrets/telegram_bot_token secrets/subscription_url; do
        [[ ! -L "$item" ]] || die "Символическая ссылка недопустима: $item"
    done
    if [[ ! -s secrets/telegram_bot_token ]]; then
        read -r -s -p 'Общий токен Telegram-бота (ввод скрыт): ' token
        printf '\n'
        [[ -n "$token" ]] || die 'Токен не может быть пустым.'
    fi
    if [[ ! -s secrets/subscription_url ]]; then
        read -r -s -p 'URL подписки (ввод скрыт): ' subscription
        printf '\n'
        [[ "$subscription" == https://* ]] || die 'URL подписки должен начинаться с https://'
    fi
    mkdir -p secrets state/standalone
    chmod 700 secrets state state/standalone
    [[ -z "$token" ]] || printf '%s\n' "$token" > secrets/telegram_bot_token
    [[ -z "$subscription" ]] || printf '%s\n' "$subscription" > secrets/subscription_url
    chmod 600 secrets/telegram_bot_token secrets/subscription_url
    (
        set -o noclobber
        {
            dotenv LC_AGENT_CITY "$city"
            dotenv LC_AGENT_NAME "$name"
            dotenv LC_HOST_NAME "$LC_HOST_NAME"
            dotenv LC_HOST_OS "$LC_HOST_OS"
            dotenv LC_TELEGRAM_CHAT_ID "$chat"
            dotenv LC_TELEGRAM_BOT_TOKEN_FILE /run/secrets/telegram_bot_token
            dotenv LC_SUBSCRIPTION_URL_FILE /run/secrets/subscription_url
            dotenv LC_STATE_DIR /var/lib/litechecker
            dotenv LC_INTERVAL_SECONDS 600
        } > .env.standalone
    )
    printf '%s\n' 'Настройки сохранены. Для проверки: bash run.sh check. Для фонового запуска: bash run.sh start.'
}

case "$action" in
    setup) setup "${2:-}"; exit 0 ;;
    start|check|stop|logs|status|build) ;;
    *) printf '%s\n' 'Использование: bash run.sh setup|check|start|stop|logs|status|build'; exit 0 ;;
esac
[[ -f .env.standalone ]] || die 'Сначала выполните: bash run.sh setup'
command -v docker >/dev/null || die 'Установите Docker с Compose.'
docker compose version >/dev/null
if [[ -x .updater-runtime/venv/bin/python && -f scripts/update.sh && ! -L scripts/update.sh ]]; then
    case "$action" in
        start|stop) exec bash scripts/update.sh "$action" ;;
        check) exec bash scripts/update.sh probe ;;
    esac
fi
export LITECHECKER_UID="$(id -u)"
export LITECHECKER_GID="$(id -g)"
compose=(docker compose --env-file .env.standalone -f compose.standalone.yml)
case "$action" in
    start|check|build)
        proxy_file=secrets/telegram_proxy_url
        if [[ -e "$proxy_file" || -L "$proxy_file" ]]; then
            [[ ! -L secrets && ! -L "$proxy_file" && -f "$proxy_file" && -r "$proxy_file" && -s "$proxy_file" ]] || die 'Файл secrets/telegram_proxy_url должен быть обычным непустым файлом без символических ссылок.'
            [[ "$(< "$proxy_file")" =~ [^[:space:]] ]] || die 'Файл secrets/telegram_proxy_url не должен быть пустым.'
            [[ -f compose.telegram-proxy.yml && ! -L compose.telegram-proxy.yml ]] || die 'Не найден обычный файл compose.telegram-proxy.yml.'
            chmod 700 secrets
            chmod 600 "$proxy_file"
            compose+=(-f compose.telegram-proxy.yml)
        fi
        ;;
esac
case "$action" in
    start)
        "${compose[@]}" build checker
        "${compose[@]}" up -d --force-recreate checker
        "${compose[@]}" ps
        ;;
    check)
        "${compose[@]}" build checker
        "${compose[@]}" run --rm checker standalone --once
        ;;
    build) "${compose[@]}" build checker ;;
    stop) "${compose[@]}" stop checker ;;
    logs) "${compose[@]}" logs --tail 100 -f checker ;;
    status)
        if [[ "${2:-}" == --state ]]; then
            "${compose[@]}" ps --all --format '{{.State}}' checker
        else
            "${compose[@]}" ps
        fi
        ;;
esac
