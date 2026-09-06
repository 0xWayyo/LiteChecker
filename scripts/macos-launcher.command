#!/bin/bash
# The only public entry: install first, then use the proven handoff launcher.
set +x
set -uo pipefail
bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 2
payload="$bundle_dir/_app"
fail() {
    printf '%s\n' 'Не удалось открыть LiteChecker: папка _app отсутствует, повреждена или заменена ссылкой.' 'Распакуйте ZIP заново. Оставьте INSTALL.command рядом с папкой _app.' >&2
    if [[ -t 0 ]]; then read -r -p 'Нажмите Enter, чтобы закрыть окно… ' _ || true; fi
    exit 2
}
[[ -d "$payload" && ! -L "$payload" ]] || fail
entry="$payload/INSTALL.command"
if [[ -e "$payload/LiteChecker.command" || -L "$payload/LiteChecker.command" ]]; then
    entry="$payload/LiteChecker.command"
fi
[[ -f "$entry" && ! -L "$entry" ]] || fail
exec /bin/bash "$entry"
