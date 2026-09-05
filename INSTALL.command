#!/usr/bin/env bash
# Finder opens this script in Terminal; leave its result visible.
set +x
set -uo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || exit 2
bash "$project_dir/scripts/install.sh"
install_exit=$?
if [[ -t 0 ]]; then
    printf '\n'
    read -r -p 'Нажмите Enter, чтобы закрыть окно… ' _ || true
fi
exit "$install_exit"
