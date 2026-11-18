# MCP Shield container image (TS-B8). Build: docker build -t mcp-shield .
FROM python:3.12-slim

# uv, pinned to the version that wrote uv.lock
COPY --from=ghcr.io/astral-sh/uv:0.13.9 /uv /uvx /bin/

# httpx2 (the MCP SDK's HTTP client) verifies TLS against the OS certificate store
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_CACHE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Dependencies first (cached layer), then the project itself
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
COPY demo ./demo
COPY examples ./examples
RUN uv sync --locked --no-dev

# Run as an unprivileged user; audit data lives on a volume
RUN useradd --create-home --uid 10001 shield \
 && mkdir -p /data && chown -R shield:shield /data /app
USER shield
VOLUME ["/data"]
ENV SHIELD_DATA=/data
EXPOSE 8765 8501

HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=5 \
  CMD ["python", "-m", "mcp_shield.healthcheck"]

CMD ["shield", "run", "--http", "--host", "0.0.0.0", "--config", "examples/docker/shield.yaml"]
