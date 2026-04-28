FROM python:3.12-slim AS builder

WORKDIR /build
COPY pyproject.toml .
COPY squash/ ./squash/
COPY README.md .

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /dist

# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

# Non-root user for security
RUN useradd --create-home --shell /bin/bash squash

WORKDIR /app

# System deps for weasyprint (PDF export) and psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libffi-dev \
        libgdk-pixbuf2.0-0 \
        shared-mime-info \
        libpq-dev \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /dist/*.whl /tmp/

RUN pip install --no-cache-dir \
        /tmp/squash_ai-*.whl \
        "fastapi>=0.111" \
        "uvicorn[standard]>=0.29" \
        "cryptography>=42.0" \
        "cyclonedx-python-lib>=7.0" \
        "psycopg2-binary>=2.9" \
        "sentry-sdk>=2.0" \
    && rm /tmp/*.whl

# Copy source for CLI access
COPY --chown=squash:squash squash/ /app/squash/

USER squash

ENV PYTHONUNBUFFERED=1 \
    SQUASH_LOG_LEVEL=INFO

EXPOSE 4444

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4444/health')"

CMD ["uvicorn", "squash.api:app", "--host", "0.0.0.0", "--port", "4444", \
     "--workers", "2", "--log-level", "info", "--proxy-headers"]
