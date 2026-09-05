#!/usr/bin/env bash
# Stable entrypoint; Python validates the active version before execution.
set +x
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
case "$(uname -s)" in
    Darwin) root=${LITECHECKER_NATIVE_ROOT:-"$HOME/Library/Application Support/LiteChecker"}; runtime="$root/.native-direct" ;;
    Linux) runtime="$root/.updater-runtime" ;;
    *) printf '%s\n' 'updater-platform-unsupported' >&2; exit 1 ;;
esac
python="$runtime/venv/bin/python"
for path in "$root" "$runtime" "$runtime/venv" "$runtime/venv/bin" "$root/src" "$root/src/litechecker" "$root/src/litechecker/update_launcher.py"; do
    [[ ! -L "$path" ]] || { printf '%s\n' 'updater-path-unsafe' >&2; exit 1; }
done
[[ -x "$python" ]] || { printf '%s\n' 'updater-host-runtime-required' >&2; exit 1; }
current=$python
links=0
while [[ -L "$current" ]]; do
    links=$((links + 1))
    [[ $links -le 20 ]] || { printf '%s\n' 'updater-python-unsafe' >&2; exit 1; }
    target=$(readlink "$current")
    case "$target" in /*) current=$target;; *) current="$(dirname -- "$current")/$target";; esac
done
[[ -f "$current" && -x "$current" ]] || { printf '%s\n' 'updater-python-unsafe' >&2; exit 1; }
directory=$(cd -- "$(dirname -- "$current")" && pwd -P)
case "$directory/$(basename -- "$current")" in "$runtime"/*) ;; *) printf '%s\n' 'updater-python-unsafe' >&2; exit 1;; esac
exec "$python" "$root/src/litechecker/update_launcher.py" --root "$root" "${@:-status}"
