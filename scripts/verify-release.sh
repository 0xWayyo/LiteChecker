#!/usr/bin/env bash
set -euo pipefail

if test "$#" -gt 1; then
  echo "usage: verify-release.sh [offline|live]" >&2
  exit 64
fi

export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/litechecker-release-uv-cache}"

RELEASE_MODE="${1:-offline}"
case "$RELEASE_MODE" in
  offline)
    DO_LIVE_CHECKS=0
    ;;
  live)
    if ! docker info >/dev/null 2>&1; then
      echo "release-docker-required" >&2
      exit 1
    fi
    DO_LIVE_CHECKS=1
    ;;
  *)
    echo "verification-mode-invalid" >&2
    exit 1
    ;;
esac

if test -n "$(git status --porcelain --untracked-files=all)"; then
  echo "release-worktree-not-clean" >&2
  exit 1
fi

# Scan every tracked runtime, build-context, deployment, and operator input before build.
if git grep -I -q -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|lc_[A-Za-z0-9_-]{43}|[0-9]{6,20}:[A-Za-z0-9_-]{30,}' -- \
  Dockerfile .dockerignore pyproject.toml uv.lock README.md Caddyfile \
  compose.example.yml compose.agent.example.yml \
  docs examples deploy scripts src; then
  echo "tracked-secret-pattern-detected" >&2
  exit 1
fi

uv sync --all-groups --all-extras --frozen
uv run --no-sync pytest
uv run --no-sync python -m compileall -q src tests
uv build --offline
uv run --no-sync python scripts/check_release_artifacts.py
uv run --no-sync litechecker --help >/dev/null
uv run --no-sync litechecker agent --help >/dev/null
uv run --no-sync litechecker collector --help >/dev/null
uv run --no-sync litechecker agent-health --help >/dev/null
uv run --no-sync litechecker-smoke-subscription --help >/dev/null
uv run --no-sync python -c 'import xml.etree.ElementTree as ET; ET.parse("deploy/com.litechecker.agent.plist")'

if test "$DO_LIVE_CHECKS" = "1"; then
  docker compose -f compose.example.yml config --no-interpolate -q
  docker compose -f compose.agent.example.yml config --no-interpolate -q
  docker build --pull --tag litechecker:release-check .
  # caddy validate uses the pinned runtime image and placeholder-only config.
  docker run --rm \
    -e CADDY_DOMAIN=collector.example.invalid -e CADDY_EMAIL=admin@example.invalid \
    -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
    caddy:2.10.2-alpine@sha256:4c6e91c6ed0e2fa03efd5b44747b625fec79bc9cd06ac5235a779726618e530d \
    caddy validate --config /etc/caddy/Caddyfile >/dev/null
  # Exact embedded xray version gate uses the same parser as agent and smoke.
  docker run --rm --entrypoint /opt/litechecker/.venv/bin/python \
    litechecker:release-check -c \
    'import asyncio; from litechecker.agent import query_xray_version; r=asyncio.run(query_xray_version("/usr/local/bin/xray", expected_version="26.3.27")); assert r.compatible and r.version == "26.3.27"'
  docker run --rm litechecker:release-check --help >/dev/null
  uv run --no-sync litechecker-smoke-subscription --probe
fi
