#!/usr/bin/env bash
# Windows drives do not reliably enforce the required private file permissions.
# Transfer only runtime/build inputs and shared presets into the WSL Linux home.
set +x
set -euo pipefail
umask 077
fail() { printf '\n%s\n' "$*" >&2; exit 2; }
[[ $# == 1 && -d "$1" ]] || fail 'Не найдена распакованная папка LiteChecker.'
source_dir=$(cd -- "$1" && pwd -P)
linux_home=$(cd -- "$HOME" && pwd -P)
[[ "$linux_home" != /mnt/* && "$linux_home" != / ]] || fail 'Домашняя папка Ubuntu должна находиться в Linux, например /home/ivan, а не на диске Windows.'
install_dir="$linux_home/LiteChecker"

for name in scripts src src/litechecker src/litechecker/collector secrets; do
    [[ ! -L "$source_dir/$name" ]] || fail "В архиве обнаружена символическая ссылка: $name"
done
for name in telegram_bot_token subscription_url telegram_proxy_url; do
    [[ ! -L "$source_dir/secrets/$name" ]] || fail "Секрет в архиве не должен быть символической ссылкой: $name"
done
for directory in "$install_dir" "$install_dir/scripts" "$install_dir/src" "$install_dir/src/litechecker" "$install_dir/src/litechecker/collector" "$install_dir/secrets" "$install_dir/state" "$install_dir/state/standalone"; do
    [[ ! -L "$directory" ]] || fail "Папка установки не должна быть символической ссылкой: $directory"
done
for directory in "$source_dir" "$install_dir"; do
    proxy_file="$directory/secrets/telegram_proxy_url"
    if [[ -e "$proxy_file" || -L "$proxy_file" ]]; then
        [[ ! -L "$proxy_file" && -f "$proxy_file" && -r "$proxy_file" && -s "$proxy_file" ]] || fail 'Секрет telegram_proxy_url должен быть обычным непустым файлом без символических ссылок.'
        [[ "$(< "$proxy_file")" =~ [^[:space:]] ]] || fail 'Секрет telegram_proxy_url не должен быть пустым.'
    fi
done
if [[ "$source_dir" == "$install_dir" ]]; then
    exec bash "$install_dir/scripts/install.sh"
fi

mkdir -p "$install_dir/scripts" "$install_dir/src/litechecker/collector" "$install_dir/secrets"
chmod 700 "$install_dir" "$install_dir/secrets"
copy_input() {
    local name="$1"
    [[ -f "$source_dir/$name" && ! -L "$source_dir/$name" ]] || fail "В архиве отсутствует обычный файл: $name"
    [[ ! -L "$install_dir/$name" ]] || fail "Файл установки не должен быть символической ссылкой: $name"
    cp -- "$source_dir/$name" "$install_dir/$name"
    chmod 600 "$install_dir/$name"
}
for name in Dockerfile .dockerignore pyproject.toml uv.lock compose.standalone.yml compose.telegram-proxy.yml run.sh INSTALL.sh scripts/install.sh scripts/install-wsl.sh; do
    copy_input "$name"
done
for name in scripts/update.sh scripts/prepare-updater.sh update-channel.json UPDATES.md; do
    if [[ -e "$source_dir/$name" || -L "$source_dir/$name" ]]; then
        copy_input "$name"
    fi
done
for file in "$source_dir"/src/litechecker/*.py "$source_dir"/src/litechecker/collector/*.py; do
    copy_input "${file#"$source_dir"/}"
done
for name in telegram_bot_token subscription_url telegram_proxy_url; do
    destination="$install_dir/secrets/$name"
    [[ ! -L "$destination" ]] || fail "Секрет в папке установки не должен быть символической ссылкой: $name"
    if [[ ! -e "$destination" && -f "$source_dir/secrets/$name" ]]; then
        copy_input "secrets/$name"
    fi
    if [[ -f "$destination" ]]; then
        chmod 600 "$destination"
    fi
done
chmod 700 "$install_dir/run.sh" "$install_dir/INSTALL.sh" "$install_dir/scripts/install.sh" "$install_dir/scripts/install-wsl.sh"
printf 'Файлы LiteChecker размещены в Ubuntu: %s\n' "$install_dir"
exec bash "$install_dir/scripts/install.sh"
