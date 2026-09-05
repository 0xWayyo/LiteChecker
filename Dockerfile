# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM ghcr.io/xtls/xray-core:26.3.27@sha256:592ec4d11f656db95598d01e76dbcc6e002d67360b96a5436500a938230f52c7 AS xray
FROM ghcr.io/astral-sh/uv:0.8.22@sha256:9874eb7afe5ca16c363fe80b294fe700e460df29a55532bbfea234a0f12eddb1 AS uv

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS builder
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/litechecker/.venv
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
COPY pyproject.toml uv.lock ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7 AS runtime
ENV PATH="/opt/litechecker/.venv/bin:${PATH}" \
    LC_STATE_DIR=/var/lib/litechecker \
    LC_XRAY_BINARY=/usr/local/bin/xray \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/opt/litechecker/.venv
RUN groupadd --gid 10001 litechecker \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent litechecker \
    && install -d -o 10001 -g 10001 -m 0700 /var/lib/litechecker
COPY --from=builder --chown=10001:10001 /opt/litechecker/.venv /opt/litechecker/.venv
COPY --from=xray --chown=10001:10001 /usr/local/bin/xray /usr/local/bin/xray
USER 10001:10001
VOLUME ["/var/lib/litechecker"]
ENTRYPOINT ["/opt/litechecker/.venv/bin/python", "-m", "litechecker.cli"]
CMD ["--help"]
