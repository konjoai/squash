# syntax=docker/dockerfile:1.7
# Squash API — production Docker image
# Multi-stage build: builder → slim runtime
# Deploy: fly deploy --config fly.toml

FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools in a single layer
RUN pip install --no-cache-dir build==1.2.1

COPY pyproject.toml README.md ./
COPY squash/ ./squash/

RUN python -m build --wheel --outdir /dist

# ── Runtime image ──────────────────────────────────────────────────────────────

FROM python:3.12-slim

LABEL org.opencontainers.image.title="squash-ai" \
      org.opencontainers.image.description="Squash violations, not velocity. EU AI Act compliance automation." \
      org.opencontainers.image.source="https://github.com/konjoai/squash" \
      org.opencontainers.image.licenses="Apache-2.0"

# Non-root user for container security
RUN useradd --uid 1000 --create-home --shell /bin/bash squash

WORKDIR /app

# System deps: weasyprint (PDF export), libpq (Postgres), curl (health check)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libffi8 \
        libgdk-pixbuf-2.0-0 \
        shared-mime-info \
        libpq5 \
        curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /dist/*.whl /tmp/

RUN pip install --no-cache-dir \
        /tmp/squash_ai-*.whl \
        "fastapi>=0.111" \
        "uvicorn[standard]>=0.29" \
        "httpx>=0.27" \
        "cryptography>=42.0" \
        "cyclonedx-python-lib>=7.0" \
        "psycopg2-binary>=2.9" \
        "stripe>=8.0" \
        "sentry-sdk[fastapi]>=2.0" \
    && rm -f /tmp/*.whl

# Copy source for CLI access inside container
COPY --chown=squash:squash squash/ /app/squash/

# Data volume for SQLite and attestation artifacts
RUN mkdir -p /data && chown squash:squash /data

USER squash

ENV PYTHONUNBUFFERED=1 \
    SQUASH_LOG_LEVEL=INFO \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 4444

HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:4444/health/ping || exit 1

CMD ["uvicorn", "squash.api:app", \
     "--host", "0.0.0.0", \
     "--port", "4444", \
     "--workers", "2", \
     "--log-level", "info", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*", \
     "--access-log"]
