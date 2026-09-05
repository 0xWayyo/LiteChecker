#!/usr/bin/env bash
# Install the native DIRECT payload and launchd service for the current user.
set +x
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 2; }
source_root=$(cd -- "${1:-$(dirname -- "${BASH_SOURCE[0]}")/..}" && pwd -P)
root=${LITECHECKER_NATIVE_ROOT:-"$HOME/Library/Application Support/LiteChecker"}
launch_agents=${LITECHECKER_LAUNCH_AGENTS_DIR:-"$HOME/Library/LaunchAgents"}
plist="$launch_agents/com.litechecker.direct.plist"

[[ "$(uname -s)" == Darwin ]] || die 'Этот установщик предназначен для macOS.'
[[ ! -L "$source_root" && -d "$source_root" ]] || die 'Исходная папка установки небезопасна.'
[[ ! -L "$root" ]] || die 'Папка native установки не должна быть символической ссылкой.'
[[ ! -e "$root" || -d "$root" ]] || die 'Путь native установки должен быть папкой.'

require_source_directory() {
    [[ ! -L "$1" && -d "$1" ]] || die 'Каталог исходного пакета отсутствует или небезопасен.'
}
require_destination_directory() {
    [[ ! -L "$1" && ( ! -e "$1" || -d "$1" ) ]] || die 'Каталог canonical установки небезопасен.'
}
for directory in "$source_root/scripts" "$source_root/src" "$source_root/src/litechecker" "$source_root/src/litechecker/collector"; do
    require_source_directory "$directory"
done
for directory in "$root/scripts" "$root/src" "$root/src/litechecker" "$root/src/litechecker/collector" "$launch_agents"; do
    require_destination_directory "$directory"
done

manifest="$source_root/CONTENTS.sha256.json"
[[ ! -L "$manifest" && -f "$manifest" ]] || die 'Не найден безопасный CONTENTS.sha256.json пакета.'

verify_payload() {
    local relative=$1 incoming="$source_root/$1" expected actual
    [[ ! -L "$incoming" && -f "$incoming" ]] || die "Файл установки отсутствует или небезопасен: $relative"
    expected=$(awk -v key="\"$relative\":" '$1 == key {value=$2; gsub(/[\",]/, "", value); print value}' "$manifest")
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "Файл не описан однозначно в manifest: $relative"
    actual=$(shasum -a 256 "$incoming")
    actual=${actual%% *}
    [[ "$actual" == "$expected" ]] || die "Контрольная сумма файла не совпала: $relative"
}

payload=(pyproject.toml uv.lock run.sh compose.standalone.yml compose.telegram-proxy.yml scripts/native-direct.sh scripts/install-macos.sh)
for relative in scripts/update.sh scripts/prepare-updater.sh update-channel.json UPDATES.md; do
    if [[ -e "$source_root/$relative" || -L "$source_root/$relative" ]]; then
        payload+=("$relative")
    fi
done
for incoming in "$source_root"/src/litechecker/*.py "$source_root"/src/litechecker/collector/*.py; do
    [[ -e "$incoming" ]] || continue
    payload+=("${incoming#"$source_root"/}")
done
for relative in "${payload[@]}"; do
    verify_payload "$relative"
done

mkdir -p "$root/scripts" "$root/src/litechecker/collector" "$launch_agents"
chmod 700 "$root" "$root/scripts" "$root/src" "$root/src/litechecker" "$root/src/litechecker/collector"

copy_payload() {
    local relative=$1 incoming="$source_root/$1" outgoing="$root/$1"
    [[ ! -L "$incoming" && -f "$incoming" ]] || die "Файл установки отсутствует или небезопасен: $relative"
    [[ ! -L "$outgoing" ]] || die "Файл canonical установки не должен быть ссылкой: $relative"
    cp -p -- "$incoming" "$outgoing"
}

for relative in pyproject.toml uv.lock run.sh scripts/native-direct.sh scripts/install-macos.sh; do
    copy_payload "$relative"
done
for relative in scripts/update.sh scripts/prepare-updater.sh; do
    if [[ -f "$source_root/$relative" ]]; then
        copy_payload "$relative"
        chmod 700 "$root/$relative"
    fi
done
if [[ -f "$source_root/UPDATES.md" ]]; then
    copy_payload UPDATES.md
    chmod 600 "$root/UPDATES.md"
fi
for incoming in "$source_root"/src/litechecker/*.py "$source_root"/src/litechecker/collector/*.py; do
    [[ -e "$incoming" ]] || continue
    relative=${incoming#"$source_root"/}
    copy_payload "$relative"
done
chmod 700 "$root/run.sh" "$root/scripts/native-direct.sh" "$root/scripts/install-macos.sh"
find "$root/src" -type f -exec chmod 600 {} +
chmod 600 "$root/pyproject.toml" "$root/uv.lock"

printf '%s\n' 'Подготавливаю закреплённые Python, зависимости и Xray для DIRECT.'
bash "$root/scripts/native-direct.sh" prepare --root "$root"
PYTHONPATH="$root/src" "$root/.native-direct/venv/bin/python" -m litechecker.native_install \
    --source "$source_root" --root "$root" --plist "$plist"

# Loading production settings is the last native preflight. A legacy container
# is not touched until runtime, secrets, settings, Xray and plist pass the same
# validation used by the daemon itself.
PYTHONPATH="$root/src" "$root/.native-direct/venv/bin/python" -c \
    'import sys; from pathlib import Path; from litechecker.direct_service import service_settings; service_settings(Path(sys.argv[1]), Path(sys.argv[2]))' \
    "$root" "$root/.native-direct/xray"

stopped_legacy=''
stop_legacy() {
    command -v docker >/dev/null 2>&1 || return 0
    local candidates id metadata project service working_dir config_files command
    candidates=$(docker ps -q \
        --filter label=com.docker.compose.project=litechecker-standalone \
        --filter label=com.docker.compose.service=checker 2>/dev/null) || return 0
    for id in $candidates; do
        metadata=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.project.working_dir"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{json .Config.Cmd}}' "$id" 2>/dev/null) || continue
        IFS='|' read -r project service working_dir config_files command <<< "$metadata"
        if [[ "$project" == litechecker-standalone \
              && "$service" == checker \
              && "$working_dir" == "$source_root" \
              && ( "$config_files" == "$source_root/compose.standalone.yml" \
                   || "$config_files" == "$source_root/compose.standalone.yml,$source_root/compose.telegram-proxy.yml" ) \
              && "$command" == '["standalone"]' ]]; then
            if docker stop "$id" >/dev/null; then
                stopped_legacy="$stopped_legacy $id"
            else
                rollback_legacy
                die 'Не удалось безопасно остановить прежний контейнер LiteChecker.'
            fi
        fi
    done
}

rollback_legacy() {
    local id
    command -v docker >/dev/null 2>&1 || return 0
    for id in $stopped_legacy; do
        docker start "$id" >/dev/null 2>&1 || true
    done
}

stop_legacy
if bash "$root/scripts/native-direct.sh" start; then
    :
else
    status=$?
    rollback_legacy
    exit "$status"
fi
bash "$root/scripts/native-direct.sh" status
if [[ -f "$root/.updates/channel.json" && -f "$root/scripts/update.sh" ]]; then
    if ! bash "$root/scripts/update.sh" schedule; then
        printf '%s\n' 'Внимание: чекер запущен, но планировщик обновлений не установлен. См. UPDATES.md.' >&2
    fi
fi
printf '\n%s\n' 'LiteChecker DIRECT установлен и запущен без Docker.'
printf 'Папка установки: %s\n' "$root"
printf '%s\n' 'Остановить: bash run.sh stop' 'Посмотреть журнал: bash run.sh logs'
