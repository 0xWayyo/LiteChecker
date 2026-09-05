#!/usr/bin/env bash
# Prepare and control the per-user macOS DIRECT service.
set +x
set -euo pipefail
umask 077

die() { printf '%s\n' "$*" >&2; exit 2; }

label=com.litechecker.direct
root=${LITECHECKER_NATIVE_ROOT:-"$HOME/Library/Application Support/LiteChecker"}
launch_agents=${LITECHECKER_LAUNCH_AGENTS_DIR:-"$HOME/Library/LaunchAgents"}
action=${1:-help}
shift || true
if [[ "${1:-}" == --root ]]; then
    [[ -n "${2:-}" ]] || die 'Не указан путь native runtime.'
    root=$2
    shift 2
fi
[[ $# -eq 0 ]] || die 'Неизвестные аргументы native launcher.'

runtime="$root/.native-direct"
python="$runtime/venv/bin/python"
xray="$runtime/xray"
plist="$launch_agents/$label.plist"
service_target="gui/$(id -u)/$label"

validate_runtime_python() {
    for item in "$runtime" "$runtime/venv" "$runtime/venv/bin" "$runtime/python"; do
        [[ ! -L "$item" ]] || die 'Native runtime содержит небезопасную ссылку.'
    done
    local current=$python target resolved_dir resolved_python links=0
    while [[ -L "$current" ]]; do
        links=$((links + 1))
        [[ $links -le 20 ]] || die 'Цепочка ссылок native Python слишком длинная.'
        target=$(readlink "$current") || die 'Не удалось проверить native Python.'
        case "$target" in
            /*) current=$target ;;
            *) current="$(dirname -- "$current")/$target" ;;
        esac
    done
    [[ -f "$current" && -x "$current" ]] || die 'Native Python не является исполняемым файлом.'
    resolved_dir=$(cd -- "$(dirname -- "$current")" && pwd -P) || die 'Не удалось проверить native Python.'
    resolved_python="$resolved_dir/$(basename -- "$current")"
    case "$resolved_python" in
        "$runtime"/*) ;;
        *) die 'Native Python выходит за пределы private runtime.' ;;
    esac
}

prepare() {
    [[ "$(uname -s)" == Darwin ]] || die 'Native DIRECT поддерживается только на macOS.'
    for item in "$root" "$runtime" "$runtime/uv" "$runtime/xray" "$runtime/venv" "$runtime/venv/bin" "$runtime/cache" "$runtime/python"; do
        [[ ! -L "$item" ]] || die 'Native runtime не должен содержать символические ссылки в служебных путях.'
    done
    [[ ! -e "$root" || -d "$root" ]] || die 'Папка native установки недопустима.'
    mkdir -p "$root" "$runtime"
    chmod 700 "$root" "$runtime"
    if [[ -e "$python" || -L "$python" ]]; then
        validate_runtime_python
    fi
    case "$(uname -m)" in
        arm64)
            uv_arch=aarch64-apple-darwin
            uv_sha=3f61099e261e449527141dbf125629fab33ad696468c8c90cebbac40185a306c
            xray_arch=macos-arm64-v8a
            xray_sha=2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf
            ;;
        x86_64)
            uv_arch=x86_64-apple-darwin
            uv_sha=76638fdcfa91357858771551a1c88de1f7c3b270b33ab1866f8a0618d9e442d8
            xray_arch=macos-64
            xray_sha=f5b0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203
            ;;
        *) die 'Архитектура Mac не поддерживается.' ;;
    esac

    download=''
    cleanup_download() {
        if [[ -n "$download" ]]; then
            rm -f -- "$download/uv.tar.gz" "$download/xray.zip" "$download/uv" "$download/xray"
            rmdir -- "$download" 2>/dev/null || true
        fi
    }
    trap cleanup_download EXIT
    if [[ ! -x "$runtime/uv" || ! -x "$runtime/xray" ]]; then
        download=$(mktemp -d "$runtime/download.XXXXXXXX")
    fi
    fetch() {
        /usr/bin/curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
            --connect-timeout 15 --max-time 180 "$1" -o "$2"
        printf '%s  %s\n' "$3" "$2" | /usr/bin/shasum -a 256 -c - >/dev/null \
            || die 'SHA-256 не совпал. Установка остановлена.'
    }
    if [[ ! -x "$runtime/uv" ]]; then
        fetch "https://github.com/astral-sh/uv/releases/download/0.8.22/uv-$uv_arch.tar.gz" "$download/uv.tar.gz" "$uv_sha"
        /usr/bin/tar -xzf "$download/uv.tar.gz" -O "uv-$uv_arch/uv" > "$download/uv"
        chmod 700 "$download/uv"
        mv -- "$download/uv" "$runtime/uv"
    fi
    if [[ ! -x "$runtime/xray" ]]; then
        fetch "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-$xray_arch.zip" "$download/xray.zip" "$xray_sha"
        /usr/bin/unzip -p "$download/xray.zip" xray > "$download/xray"
        chmod 700 "$download/xray"
        mv -- "$download/xray" "$runtime/xray"
    fi
    export UV_PROJECT_ENVIRONMENT="$runtime/venv"
    export UV_CACHE_DIR="$runtime/cache"
    export UV_PYTHON_INSTALL_DIR="$runtime/python"
    export UV_PYTHON_PREFERENCE=only-managed
    (cd -- "$root" && "$runtime/uv" sync --frozen --no-dev --python 3.12.11)
    [[ -x "$xray" ]] || die 'Native runtime подготовлен не полностью.'
    validate_runtime_python
    trap - EXIT
    cleanup_download
}

require_install() {
    [[ ! -L "$root" && -d "$root" ]] || die 'Native установка не найдена или небезопасна.'
    [[ ! -L "$xray" && -x "$xray" ]] || die 'Native runtime не найден. Сначала запустите установщик.'
    validate_runtime_python
}

bootstrap_launch_agent() {
    local attempt=1 status=0
    local delay=${LITECHECKER_LAUNCHCTL_RETRY_DELAY_SECONDS:-1}
    [[ "$delay" =~ ^[0-9]+$ ]] || die 'Некорректная задержка повтора launchd.'
    while true; do
        if launchctl bootstrap "gui/$(id -u)" "$plist"; then
            return 0
        else
            status=$?
        fi
        # launchctl uses EX_IOERR (5) while a just-booted-out job is still
        # draining. Other failures are configuration/permission errors and
        # must be returned immediately instead of being hidden by retries.
        if [[ $status -ne 5 || $attempt -ge 10 ]]; then
            return "$status"
        fi
        attempt=$((attempt + 1))
        sleep "$delay"
    done
}

case "$action" in
    prepare)
        prepare
        ;;
    start)
        require_install
        if [[ -f "$root/scripts/update.sh" && ! -L "$root/scripts/update.sh" ]]; then
            LITECHECKER_NATIVE_ROOT="$root" exec bash "$root/scripts/update.sh" start
        fi
        [[ ! -L "$plist" && -f "$plist" ]] || die 'Файл launchd не найден или небезопасен.'
        launchctl bootout "$service_target" >/dev/null 2>&1 || true
        bootstrap_launch_agent
        printf '%s\n' 'LiteChecker DIRECT запущен.'
        ;;
    stop)
        if [[ -f "$root/scripts/update.sh" && ! -L "$root/scripts/update.sh" ]]; then
            LITECHECKER_NATIVE_ROOT="$root" exec bash "$root/scripts/update.sh" stop
        fi
        launchctl bootout "$service_target"
        printf '%s\n' 'LiteChecker DIRECT остановлен.'
        ;;
    status)
        launchctl print "$service_target"
        ;;
    logs)
        require_install
        tail -n 100 -F "$root/state/native-direct/service.log"
        ;;
    check)
        require_install
        if [[ -f "$root/scripts/update.sh" && ! -L "$root/scripts/update.sh" ]]; then
            LITECHECKER_NATIVE_ROOT="$root" exec bash "$root/scripts/update.sh" probe
        fi
        "$python" -m litechecker.direct_service --root "$root" --xray "$xray" --once
        ;;
    *)
        printf '%s\n' 'Использование: bash run.sh start|stop|status|logs|check'
        ;;
esac
