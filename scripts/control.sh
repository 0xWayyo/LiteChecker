#!/usr/bin/env bash
# One user-facing menu; service lifecycle stays in the managed launcher.
set +x
set -uo pipefail
umask 077
source_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || exit 2
active_menu=false
data_root=''
if [[ "${1:-}" == --active-menu ]]; then
    [[ $# == 3 && -d "$2" && ! -L "$2" ]] || exit 2
    active_menu=true; data_root=$2; shift 2
fi
system=$(uname -s)
case "$system" in
    Darwin) root=${LITECHECKER_NATIVE_ROOT:-"$HOME/Library/Application Support/LiteChecker"}; kind=native; runtime=.native-direct; settings=native-settings.json ;;
    Linux)
        root=${data_root:-$source_root}
        kind=docker; runtime=.updater-runtime; settings=.env.standalone
        ;;
    *) printf '%s\n' 'Поддерживаются macOS и Linux.' >&2; exit 2 ;;
esac
export LITECHECKER_NATIVE_ROOT="$root"

fail() { printf '\n%s\n' "$1" >&2; return "${2:-2}"; }
regular() {
    local item=$1 parent
    [[ -f "$item" && ! -L "$item" ]] || return 1
    parent=${item%/*}
    [[ "$parent" != "$item" ]] || parent=.
    while [[ "$parent" != / && "$parent" != . ]]; do
        [[ -d "$parent" && ! -L "$parent" ]] || return 1
        parent=${parent%/*}
        [[ -n "$parent" ]] || parent=/
    done
}

# A prepared baseline selects and pins the next UI; the actual bash PID holds
# its exact managed-script lease after exec. Initial install stays shell-only.
if ! $active_menu; then
    case "${1:-menu}" in
        menu|folder|settings)
            if [[ -x "$root/$runtime/venv/bin/python" && -f "$root/scripts/update.sh" ]]; then
                exec bash "$root/scripts/update.sh" "${1:-menu}"
            fi
            if [[ -e "$source_root/distribution.json" || -e "$source_root/update-channel.json" || -e "$source_root/MACOS.md" || -e "$source_root/LINUX.md" ]]; then
                refusal='Пакет не соответствует этой ОС или повреждён. Распакуйте ZIP для своей системы.'
                regular "$source_root/CONTENTS.sha256.json" && regular "$source_root/scripts/install-profile.sh" || { fail "$refusal"; exit 2; }
                expected=$(awk '$1 == "\"scripts/install-profile.sh\":" {value=$2; gsub(/[",]/, "", value); print value}' "$source_root/CONTENTS.sha256.json")
                if command -v sha256sum >/dev/null 2>&1; then actual=$(sha256sum "$source_root/scripts/install-profile.sh");
                else actual=$(shasum -a 256 "$source_root/scripts/install-profile.sh"); fi
                [[ "$expected" =~ ^[0-9a-f]{64}$ && "${actual%% *}" == "$expected" ]] || { fail "$refusal"; exit 2; }
                source "$source_root/scripts/install-profile.sh"
                marker=$(profile_line "$source_root/distribution.json" 4096) || { fail "$refusal"; exit 2; }
                target=linux; [[ "$system" != Darwin ]] || target=macos
                [[ "$marker" == "{\"platform\":\"$target\",\"schema\":1}" ]] || { fail "$refusal"; exit 2; }
            fi
            ;;
    esac
fi

installed() {
    regular "$root/$settings" && regular "$root/run.sh" \
        && regular "$root/secrets/telegram_bot_token" && [[ -s "$root/secrets/telegram_bot_token" ]] \
        && regular "$root/secrets/subscription_url" && [[ -s "$root/secrets/subscription_url" ]]
}

probe_state() {
    service_state=unconfigured
    installed || return 0
    service_state=unknown
    local result code line observed
    if [[ "$kind" == native ]]; then
        result=$(bash "$root/run.sh" status 2>&1); code=$?
    else
        result=$(bash "$root/run.sh" status --state 2>&1); code=$?
    fi
    if [[ $code -ne 0 ]]; then
        if [[ "$kind" == native ]]; then
            case "$result" in *'Could not find service'*|*'Could not find specified service'*) service_state=stopped;; esac
        fi
    elif [[ "$kind" == native ]]; then
        # The first state belongs to the job, not a nested launchd coalition.
        while IFS= read -r line; do
            if [[ "$line" =~ ^[[:space:]]*state[[:space:]]*=[[:space:]]*(.*)$ ]]; then
                observed=${BASH_REMATCH[1]}
                case "$observed" in
                    running) service_state=running;;
                    'spawn scheduled'|waiting|spawning|starting|exiting|'not running') service_state=starting;;
                esac
                break
            fi
        done <<< "$result"
    else
        case "$result" in
            running) service_state=running;;
            restarting|created|removing) service_state=starting;;
            exited|dead|'') service_state=stopped;;
            paused) service_state=paused;;
        esac
    fi
}

status_text() {
    probe_state
    case "$service_state" in
        running) printf '%s\n' 'Работает';;
        stopped) printf '%s\n' 'Остановлен';;
        starting) printf '%s\n' 'Запускается или перезапускается';;
        paused) printf '%s\n' 'Приостановлен в Docker';;
        unconfigured) printf '%s\n' 'Не установлен или требует настройки';;
        *) printf '%s\n' 'Не удалось определить — откройте последние события';;
    esac
}

lifecycle() {
    regular "$root/run.sh" || { fail 'Сначала выберите установку / восстановление.'; return; }
    local code
    bash "$root/run.sh" "$1" >/dev/null 2>&1; code=$?
    if [[ $code -ne 0 ]]; then fail 'Не удалось выполнить действие. Состояние не подтверждено; откройте журнал.' "$code"; return; fi
    case "$1" in
        start) printf '%s\n' 'Команда запуска выполнена. Фактический статус показан в меню.' ;;
        stop) printf '%s\n' 'Команда остановки выполнена. Фактический статус показан в меню.' ;;
    esac
}

settings_python() {
    local runtime_root=$root current target directory links=0
    if $active_menu; then runtime_root=$source_root; fi
    local python="$runtime_root/$runtime/venv/bin/python"
    for directory in "$runtime_root" "$runtime_root/$runtime" "$runtime_root/$runtime/venv" "$runtime_root/$runtime/venv/bin"; do
        [[ -d "$directory" && ! -L "$directory" ]] || return 1
    done
    current=$python
    while [[ -L "$current" ]]; do
        links=$((links + 1)); [[ $links -le 20 ]] || return 1
        target=$(readlink "$current") || return 1
        case "$target" in /*) current=$target;; *) current="$(dirname -- "$current")/$target";; esac
    done
    [[ -f "$current" && -x "$current" ]] || return 1
    directory=$(cd -- "$(dirname -- "$current")" && pwd -P) || return 1
    case "$directory/$(basename -- "$current")" in "$runtime_root/$runtime/"*) printf '%s\n' "$python";; *) return 1;; esac
}

edit_settings() {
    local answer python code
    python=$(settings_python) || { fail 'Среда настроек ещё не готова. Выберите установку / восстановление.'; return; }
    printf '%s\n' 'Перед изменением настроек чекер будет остановлен.' 'После сохранения запустите его отдельным пунктом меню.'
    read -r -p 'Продолжить? [y/N]: ' answer || return 0
    case "$answer" in y|Y|д|Д|да|Да) ;; *) printf '%s\n' 'Отменено. Настройки и работа чекера не изменены.'; return 0;; esac
    lifecycle stop || return $?
    PYTHONPATH="$source_root/src" PYTHONDONTWRITEBYTECODE=1 "$python" -m litechecker.device_setup --root "$root" --system "$kind"
    code=$?
    printf '%s\n' 'Чекер остаётся остановленным. Для возобновления выберите «Запустить».'
    return "$code"
}

recent_logs() {
    local code checker_uid checker_gid
    if [[ "$kind" == native ]]; then
        local log="$root/state/native-direct/service.log"
        if [[ ! -e "$log" && ! -L "$log" ]]; then printf '%s\n' 'Журнал ещё не создан.'; return 0; fi
        regular "$log" || { fail 'Журнал не является безопасным обычным файлом.'; return; }
        tail -n 80 -- "$log"
        code=$?
    else
        regular "$root/.env.standalone" && regular "$root/compose.standalone.yml" || { fail 'Установка не завершена.'; return; }
        checker_uid=$(id -u) && checker_gid=$(id -g) || { fail 'Не удалось определить пользователя для чтения журнала.'; return; }
        (cd -- "$root" && LITECHECKER_UID="$checker_uid" LITECHECKER_GID="$checker_gid" docker compose --env-file .env.standalone -f compose.standalone.yml logs --tail 80 checker)
        code=$?
    fi
    if [[ $code -ne 0 ]]; then fail 'Не удалось прочитать журнал. Проверьте доступ к файлу или работу Docker и повторите пункт.' "$code"; return; fi
    printf '\n%s\n' 'Показаны последние 80 строк. Повторите пункт, чтобы обновить журнал.'
}

updates() {
    regular "$root/scripts/update.sh" || { fail 'Обновлятор ещё не установлен. Выберите установку / восстановление.'; return; }
    printf '%s\n' 'Проверяю подписанный релиз. Если он новее — установлю с сохранением настроек.'
    local result code
    result=$(bash "$root/scripts/update.sh" check --force 2>&1); code=$?
    if [[ $code -ne 0 ]]; then fail 'Обновление не завершено. Текущие файлы и результат отката проверьте в статусе обновлений.' "$code"; return; fi
    update_result "$result"
}

update_result() {
    local compact=${1//[[:space:]]/} installed_version=''
    if [[ "$compact" =~ \"version\":\"([0-9]+\.[0-9]+\.[0-9]+)\" && ${#BASH_REMATCH[1]} -le 32 ]]; then
        installed_version=" ${BASH_REMATCH[1]}"
    fi
    case "$compact" in
        *'"status":"updated"'*) printf 'Новая версия%s установлена. Настройки сохранены.\n' "$installed_version";;
        *'"status":"current"'*) printf 'Установлена актуальная версия%s.\n' "$installed_version";;
        *'"status":"disabled"'*) printf '%s\n' 'Канал обновлений отключён. Включите его командой: bash scripts/update.sh enable';;
        *'"status":"unconfigured"'*) printf '%s\n' 'Канал обновлений не настроен. Установите свежий пакет с GitHub.';;
        *'"status":"busy"'*) printf '%s\n' 'Другая проверка обновлений или сохранение настроек ещё выполняется. Повторите позже.';;
        *'"status":"rolled-back"'*) printf '%s\n' 'Новая версия не прошла проверку; выполнен откат.';;
        *'"status":"failed"'*) fail 'Последняя операция обновления завершилась ошибкой.'; return;;
        *) printf '%s\n' 'Новая версия пока не установлена. При доступном канале проверка выполняется раз в час.';;
    esac
    if [[ "$compact" == *'"warning":'* ]]; then printf '%s\n' 'Есть предупреждение об очистке служебных файлов; оно не отменяет результат обновления.'; fi
}

install_now() {
    local install_root=$source_root
    # Managed releases supply the UI, while recovery belongs to the retained
    # baseline ZIP and its data root. Installed macOS keeps fresh-ZIP guidance.
    if $active_menu; then install_root=$root; fi
    regular "$install_root/scripts/install.sh" || { fail 'Для восстановления скачайте свежий установочный ZIP с GitHub.'; return; }
    printf 'Папка данных: %s\n' "$root"
    bash "$install_root/scripts/install.sh" || return $?
    if ! $active_menu && [[ "$kind" == native ]] && regular "$root/scripts/control.sh"; then
        local python
        python=$(settings_python) || { fail 'Установка завершена, но среду управления проверить не удалось.'; return; }
        PYTHONPATH="$root/src" PYTHONDONTWRITEBYTECODE=1 "$python" -m litechecker.install_handoff \
            --source "$source_root" --root "$root" || printf '%s\n' 'Установка сохранена. Автоматическая уборка пропущена или завершилась не полностью.'
        source_root=$root
    fi
}

dispatch() {
    case "$1" in
        install) install_now ;;
        status) printf 'Состояние: '; status_text ;;
        start|stop) lifecycle "$1" ;;
        settings) edit_settings ;;
        logs) recent_logs ;;
        update) updates ;;
        updates)
            regular "$root/scripts/update.sh" || { fail 'Обновлятор ещё не установлен.'; return; }
            local result code
            result=$(bash "$root/scripts/update.sh" status 2>&1); code=$?
            if [[ $code -ne 0 ]]; then fail 'Не удалось получить статус обновлений.' "$code"; return; fi
            update_result "$result"
            ;;
        folder)
            printf 'Папка программы и данных:\n%s\n' "$root"
            printf 'Настройки: %s/%s\n' "$root" "$settings"
            printf '%s\n' 'Менять токен, подписку и прокси удобнее пунктом «Настройки».'
            ;;
        *) fail 'Неизвестное действие.' ;;
    esac
}

# The menu has no Python/UI dependency, including before the first install.
interactive=false; screen=false; color=''; reset=''; bold=''; dim=''
if [[ -t 0 && -t 1 ]]; then
    interactive=true
    if [[ "${TERM:-dumb}" != dumb ]]; then
        screen=true
        if [[ -z "${NO_COLOR+x}" ]]; then
            reset=$'\033[0m'; bold=$'\033[1m'; dim=$'\033[2m'
        fi
    fi
fi

# Count UTF-8 code points independently of the terminal locale. Only controlled
# Russian/ASCII labels enter the frame; each known emoji adds one extra cell.
label_length() {
    local LC_ALL=C text=$1 index byte
    REPLY=0
    for ((index=0; index<${#text}; index++)); do
        printf -v byte '%d' "'${text:index:1}"
        byte=$((byte & 255))
        if ((byte < 128 || byte >= 192)); then REPLY=$((REPLY + 1)); fi
    done
}

frame_row() {
    local text=$1 extra=${2:-0} padding
    label_length "$text"
    padding=$((frame_width - REPLY - extra - 2))
    ((padding >= 0)) || padding=0
    printf '  │  %s%*s│\n' "$text" "$padding" ''
}

clear_view() { if $screen; then printf '\033[H\033[2J'; else printf '\n'; fi; }

header() {
    local title="$1${2:-}" columns=${COLUMNS:-80} geometry left right rule
    if $interactive; then
        geometry=$(stty size 2>/dev/null) || geometry=''
        [[ "$geometry" =~ ^[0-9]+[[:space:]]+([0-9]+)$ ]] && columns=${BASH_REMATCH[1]}
    fi
    [[ "$columns" =~ ^[0-9]{1,4}$ ]] || columns=80
    frame_width=$((10#$columns - 4))
    ((frame_width > 50)) && frame_width=50
    ((frame_width < 28)) && frame_width=28
    printf -v rule '%*s' "$frame_width" ''
    rule=${rule// /─}
    label_length "$title"
    left=$(((frame_width - REPLY) / 2)); right=$((frame_width - REPLY - left))
    printf '  ┌%s┐\n  │%*s%s%s%s%*s│\n  ├%s┤\n' "$rule" "$left" '' "$bold" "$title" "$reset" "$right" '' "$rule"
}

menu_version() {
    # This script is pinned to its source release by the managed launcher.
    # Source profiles always include pyproject, including before Python setup.
    local value=''
    if regular "$source_root/pyproject.toml"; then
        value=$(head -c 65536 "$source_root/pyproject.toml" | awk '
            { sub(/\r$/, "") }
            /^\[/ { project = ($0 == "[project]") }
            project && /^version[[:space:]]*=/ {
                sub(/^version[[:space:]]*=[[:space:]]*"/, "")
                sub(/"[[:space:]]*$/, "")
                print; exit
            }')
    fi
    if [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && ${#value} -le 32 ]]; then
        printf ' · v%s' "$value"
    else
        printf ' · v?'
    fi
}

menu_view() {
    local icon label hint
    primary=refresh
    case "$service_state" in
        running) icon=🟢; label=РАБОТАЕТ; hint='Проверки работают в фоне'; primary=stop; primary_label='Остановить проверки';;
        stopped) icon=🔴; label=ОСТАНОВЛЕН; hint='Проверки не выполняются'; primary=start; primary_label='Запустить проверки';;
        starting) icon=🟡; label=ЗАПУСКАЕТСЯ; hint='Ожидаем запуска процесса'; primary=stop; primary_label='Остановить проверки';;
        paused) icon=🟡; label=ПРИОСТАНОВЛЕН; hint='Пауза задана в Docker'; primary=stop; primary_label='Остановить проверки';;
        unconfigured) icon=🔧; label='НУЖНА НАСТРОЙКА'; hint='Подключите подписку и бота'; primary=install; primary_label='Установить и настроить';;
        *) icon=❔; label='СТАТУС НЕИЗВЕСТЕН'; hint='Откройте последние события'; primary_label='Обновить статус';;
    esac
    clear_view
    header LITECHECKER "$(menu_version)"
    frame_row "$icon $label" 1
    frame_row "$hint"
    local rule
    printf -v rule '%*s' "$frame_width" ''; rule=${rule// /─}
    printf '  └%s┘\n\n' "$rule"
    printf '  %s1  %s%s\n' "$bold" "$primary_label" "$reset"
    if [[ "$service_state" != unconfigured ]]; then
        printf '%s\n' '  2  Последние события' '  3  Настройки' '  4  Проверить обновления'
    fi
    printf '\n%s\n' '  0  Закрыть окно'
    printf '\n  %s%s%s\n' "$dim" 'Закрытие окна не останавливает проверки.' "$reset"
    if $interactive; then printf '  %s%s%s\n' "$dim" 'Статус обновляется автоматически.' "$reset"; fi
    [[ -z "$notice" ]] || printf '\n  %s\n' "$notice"
    printf '\n  Выберите цифру и нажмите Enter: '
}

read_choice() {
    selection=''
    if $interactive; then
        local code started=$SECONDS
        IFS= read -r -t 5 selection; code=$?
        # macOS Bash 3.2 uses 1 for both timeout and EOF; newer Bash uses >128.
        # An immediate EOF still exits. An EOF at the deadline costs one refresh.
        if ((code > 128 || (code != 0 && SECONDS - started >= 4))); then return 2; fi
        return "$code"
    fi
    IFS= read -r selection
}

discard_previous_choice() {
    # Input entered while an OS status call was in flight belongs to the old
    # labels. Discard it after showing the new view, then wait for a fresh line.
    # -t 0 is not a polling operation on macOS Bash 3.2; use a bounded idle wait.
    local discarded index
    for ((index=0; index<32; index++)); do
        IFS= read -r -t 1 discarded || return 0
        # Closing has the same meaning in every view and never controls a service.
        [[ "$discarded" != 0 ]] || return 2
    done
    return 1
}

back_after_output() {
    if $interactive; then
        printf '\n  Enter — назад: '
        IFS= read -r ignored || true
    fi
}

settings_menu() {
    local page=settings done=false
    while ! $done; do
        clear_view
        if [[ "$page" == settings ]]; then
            printf '  %sНАСТРОЙКИ%s\n\n' "$bold" "$reset"
            printf '%s\n' '  1  Подписка, Telegram и устройство' '  2  Дополнительно' '' '  0  Назад'
        else
            printf '  %sДОПОЛНИТЕЛЬНО%s\n\n' "$bold" "$reset"
            printf '%s\n' '  1  Папка с данными' '  2  Статус обновлений' '  3  Восстановить установку' '' '  0  Назад'
        fi
        printf '\n  Выберите цифру и нажмите Enter: '
        read_choice; local code=$?
        [[ $code == 2 ]] && continue
        [[ $code == 0 ]] || break
        [[ -n "$selection" ]] || continue
        case "$page:$selection" in
            settings:0) done=true;;
            settings:1) clear_view; dispatch settings; back_after_output;;
            settings:2) page=additional;;
            additional:0) page=settings;;
            additional:1) clear_view; dispatch folder; back_after_output;;
            additional:2) clear_view; dispatch updates; back_after_output;;
            additional:3) clear_view; dispatch install; back_after_output;;
        esac
    done
}

action=${1:-menu}
if [[ "$action" != menu ]]; then dispatch "$action"; exit $?; fi
if $screen; then
    printf '\033[?1049h'
    trap 'printf "\033[0m\033[?1049l"' EXIT
fi
trap 'exit 130' INT
trap 'exit 143' TERM
notice=''; last_state=''; redraw=true
while true; do
    probe_state
    transition=false
    if $interactive && [[ -n "$last_state" && "$service_state" != "$last_state" ]]; then
        transition=true
        notice='Состояние изменилось. Повторите выбор по новому меню.'
    fi
    if $redraw || [[ "$service_state" != "$last_state" ]]; then
        menu_view
        if $transition; then discard_previous_choice || break; fi
        last_state=$service_state
        shown_state=$service_state
        shown_action=$primary
        redraw=false
    fi
    read_choice; code=$?
    [[ $code == 2 ]] && continue
    [[ $code == 0 ]] || break
    [[ -n "$selection" ]] || continue
    notice=''; redraw=true
    case "$selection" in
        0) break;;
        1)
            probe_state
            if [[ "$service_state" != "$shown_state" ]]; then
                notice='Состояние изменилось. Выберите действие ещё раз.'
            else
                case "$shown_action" in
                    start|stop) notice=$(dispatch "$shown_action" 2>&1);;
                    install) clear_view; dispatch install; back_after_output;;
                    refresh) ;;
                esac
            fi
            ;;
        2) if [[ "$shown_state" != unconfigured ]]; then clear_view; dispatch logs; back_after_output; fi;;
        3) if [[ "$shown_state" != unconfigured ]]; then settings_menu; fi;;
        4) if [[ "$shown_state" != unconfigured ]]; then clear_view; dispatch update; back_after_output; fi;;
        *) notice='Выберите одну из цифр в меню.';;
    esac
done
exit 0
