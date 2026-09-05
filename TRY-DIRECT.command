#!/bin/bash
set +x
cd -- "$(dirname -- "$0")" || exit 1
bash scripts/try-direct.sh "$@"
status=$?
if [[ -t 0 ]]; then
    printf '\nНажмите Enter, чтобы закрыть окно.'
    read -r _
fi
exit "$status"
