#!/usr/bin/env bash
set +x
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec bash "$project_dir/scripts/install.sh"
