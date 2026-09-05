#!/usr/bin/env bash
# Pinned Linux/WSL host updater runtime. Never invokes checker or Docker services.
set +x
set -euo pipefail
umask 077
die() { printf '%s\n' "$1" >&2; exit 1; }
[[ "${1:-}" == --root && -n "${2:-}" && $# -eq 2 ]] || die 'updater-root-required'
root=$2
[[ "$root" == /* && ! -L "$root" && -d "$root" ]] || die 'updater-root-unsafe'
[[ "$(uname -s)" == Linux ]] || die 'updater-platform-unsupported'
runtime="$root/.updater-runtime"
python="$runtime/venv/bin/python"
for path in "$runtime" "$runtime/uv" "$runtime/venv" "$runtime/venv/bin" "$runtime/python" "$runtime/cache"; do
    [[ ! -L "$path" ]] || die 'updater-runtime-unsafe'
done
validate_python() {
    local current=$python target directory links=0
    while [[ -L "$current" ]]; do
        links=$((links + 1))
        [[ $links -le 20 ]] || die 'updater-python-unsafe'
        target=$(readlink "$current") || die 'updater-python-unsafe'
        case "$target" in /*) current=$target;; *) current="$(dirname -- "$current")/$target";; esac
    done
    [[ -f "$current" && -x "$current" ]] || die 'updater-python-unsafe'
    directory=$(cd -- "$(dirname -- "$current")" && pwd -P) || die 'updater-python-unsafe'
    case "$directory/$(basename -- "$current")" in "$runtime"/*) ;; *) die 'updater-python-unsafe';; esac
}
if [[ -e "$python" || -L "$python" ]]; then validate_python; fi
case "$(uname -m)" in
    x86_64) arch=x86_64-unknown-linux-gnu; digest=741ff1f5742c5a4a25d2f829e8395355e43f7a5ae2ebc6368e9ae2df0efb69cf ;;
    aarch64|arm64) arch=aarch64-unknown-linux-gnu; digest=726b72a137fda33565143325f7d31c42cd30ff9ccdf067e00d124d37b4081cb2 ;;
    *) die 'updater-architecture-unsupported' ;;
esac
mkdir -p "$runtime"
chmod 700 "$runtime"
if [[ ! -x "$runtime/uv" ]]; then
    temporary=$(mktemp -d "$runtime/download.XXXXXXXX")
    cleanup() { rm -f -- "$temporary/uv.tar.gz" "$temporary/uv"; rmdir -- "$temporary" 2>/dev/null || true; }
    trap cleanup EXIT
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location --max-redirs 5 --connect-timeout 15 --max-time 180 "https://github.com/astral-sh/uv/releases/download/0.8.22/uv-$arch.tar.gz" -o "$temporary/uv.tar.gz"
    printf '%s  %s\n' "$digest" "$temporary/uv.tar.gz" | sha256sum -c - >/dev/null || die 'updater-bootstrap-digest-mismatch'
    tar -xzf "$temporary/uv.tar.gz" -O "uv-$arch/uv" > "$temporary/uv"
    chmod 700 "$temporary/uv"
    mv -- "$temporary/uv" "$runtime/uv"
    cleanup
    trap - EXIT
fi
export UV_PROJECT_ENVIRONMENT="$runtime/venv"
export UV_PYTHON_INSTALL_DIR="$runtime/python"
export UV_CACHE_DIR="$runtime/cache"
export UV_PYTHON_PREFERENCE=only-managed
(cd -- "$root" && "$runtime/uv" sync --frozen --no-dev --python 3.12.11)
validate_python
printf '%s\n' 'updater-host-runtime-ready'
