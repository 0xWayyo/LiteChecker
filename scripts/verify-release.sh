#!/usr/bin/env bash
set -euo pipefail

if ! test "$#" -eq 0; then
  echo "usage: verify-release.sh" >&2
  exit 64
fi

export UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/litechecker-release-uv-cache}"

RELEASE_MODE="${LC_RELEASE_MODE:-release}"
case "$RELEASE_MODE" in
  release)
    if ! test "${LC_RELEASE_REAL_SMOKE:-0}" = "1"; then
      echo "release-live-smoke-required" >&2
      exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
      echo "release-docker-required" >&2
      exit 1
    fi
    DOCKER_AVAILABLE=1
    ;;
  development-offline)
    echo "NON_RELEASE_DEVELOPMENT_VERIFICATION: live aggregate smoke is not a release gate" >&2
    if docker info >/dev/null 2>&1; then
      DOCKER_AVAILABLE=1
    else
      DOCKER_AVAILABLE=0
    fi
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
  .env.agent.example .env.collector.example .env.compose.example \
  agents.example.json deploy scripts src; then
  echo "tracked-secret-pattern-detected" >&2
  exit 1
fi

uv sync --all-groups --frozen
uv run pytest
uv run python -m compileall -q src tests
uv build
uv run python scripts/check_release_artifacts.py
uv run litechecker --help >/dev/null
uv run litechecker agent --help >/dev/null
uv run litechecker collector --help >/dev/null
uv run litechecker agent-health --help >/dev/null
uv run litechecker-smoke-subscription --help >/dev/null
docker compose -f compose.example.yml config --no-interpolate -q
docker compose -f compose.agent.example.yml config --no-interpolate -q
uv run python -c 'import xml.etree.ElementTree as ET; ET.parse("deploy/com.litechecker.agent.plist")'

if test "$DOCKER_AVAILABLE" = "1"; then
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
else
  echo "NON_RELEASE_DEVELOPMENT_VERIFICATION: docker checks skipped" >&2
fi

if test "${LC_RELEASE_REAL_SMOKE:-0}" = "1"; then
  uv run litechecker-smoke-subscription --probe
fi

if test "$RELEASE_MODE" = "development-offline"; then
  echo "NON_RELEASE_DEVELOPMENT_VERIFICATION_COMPLETE: NOT A RELEASE PASS" >&2
fi
