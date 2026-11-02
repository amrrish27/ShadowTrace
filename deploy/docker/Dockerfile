# syntax=docker/dockerfile:1
# Multi-stage build: node builds the SPA, python runs the API and the worker.
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.13-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app
RUN addgroup --system --gid 1001 shadowtrace \
 && adduser --system --uid 1001 --ingroup shadowtrace --home /app shadowtrace
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY lab/ ./lab/
COPY scripts/ ./scripts/
COPY --from=frontend /app/frontend/dist ./frontend/dist
RUN mkdir -p /var/lib/shadowtrace && chown -R shadowtrace:shadowtrace /var/lib/shadowtrace /app
USER shadowtrace
ENV ST_ENV=production \
    ST_DATABASE_PATH=/var/lib/shadowtrace/shadowtrace.db \
    ST_ALLOWED_HOSTS=localhost
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3).status == 200 else 1)"
# `--forwarded-allow-ips` must name the reverse proxy, never 127.0.0.1: inside a
# container the proxy is a different host, so the default would make uvicorn drop every
# forwarded header. It is read from the same variable the application checks
# (`ST_TRUSTED_PROXIES`) so the two allow-lists cannot drift apart. `exec` keeps the
# Python process as PID 1 so SIGTERM still reaches uvicorn.
CMD ["sh", "-c", "exec python -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${ST_TRUSTED_PROXIES:-172.30.0.2}\""]
