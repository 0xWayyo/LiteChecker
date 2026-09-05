#!/usr/bin/env bash
# Optional one-shot native macOS experiment. Never changes VPN/routes/firewall.
set +x
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
root="$PWD"
die() { printf '%s\n' "$*" >&2; exit 1; }
[[ "$(uname -s)" == Darwin ]] || die 'Этот пробный режим пока поддерживает только macOS.'
runtime="$root/.native-direct"

printf '%s\n' 'LiteChecker: разовая проба физического подключения, без изменения вашего VPN.'
printf '%s\n' 'При первом запуске загрузятся проверенные по SHA-256 uv/Xray и Python с зависимостями.'
printf '%s\n' 'Подписка и проверки идут через выбранный интерфейс. Telegram использует свой прокси, если настроен; сравнение IPinfo — обычный маршрут.'

bash "$root/scripts/native-direct.sh" prepare --root "$root"
"$runtime/venv/bin/python" -m litechecker.direct_check --root "$root" --xray "$runtime/xray" --send "$@"
