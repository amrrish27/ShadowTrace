#!/usr/bin/env bash
# ==========================================================================
#  ShadowTrace -- one-command local start (Linux / macOS / WSL).
#
#    ./start.sh            # api on :8000, lab on :8099
#    API_PORT=8080 ./start.sh
#
#  Same contract as start.cmd: one shared database, the same environment for
#  the API and the worker, the lab started by the API supervisor, a readiness
#  check that proves each process is alive, and the log tail when it is not.
#  Stop with ./stop.sh.
# ==========================================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PORT="${API_PORT:-8000}"
LAB_PORT="${LAB_PORT:-8099}"
cd "$ROOT"

if [ -x "$ROOT/.venv313/bin/python" ]; then
  PY="$ROOT/.venv313/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="$(command -v python3)"
else
  echo "[fail] no python3 found; create the virtualenv first:"
  echo "         python3 -m venv .venv313 && .venv313/bin/pip install -r requirements.txt"
  exit 1
fi

"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
  echo "[fail] Python 3.10+ is required; $PY is $("$PY" -V 2>&1)"
  exit 1
}
"$PY" -c 'import fastapi, uvicorn' 2>/dev/null || {
  echo "[fail] backend dependencies missing for $PY"
  echo "        $PY -m pip install -r requirements.txt"
  exit 1
}

if [ ! -f "$ROOT/frontend/dist/index.html" ]; then
  if command -v npm >/dev/null 2>&1; then
    if [ ! -d "$ROOT/frontend/node_modules" ]; then
      echo "[info] frontend dependencies missing -- running npm ci once (network)"
      ( cd "$ROOT/frontend" && npm ci ) || {
        echo "[fail] npm ci failed in frontend; run it by hand to see the full error"
        exit 1
      }
    fi
    echo "[info] building the frontend bundle once"
    ( cd "$ROOT/frontend" && npm run build ) || {
      echo "[fail] npm run build failed in frontend"
      exit 1
    }
  else
    echo "[warn] frontend/dist is missing and npm is unavailable; the API will answer JSON only"
  fi
fi

mkdir -p "$ROOT/data" "$ROOT/logs"

# The signing key (lab grants) is generated once per installation and reused, so it is not
# a published constant that any reader of the archive can reuse.
if [ ! -s "$ROOT/data/secret.key" ]; then
  "$PY" -c 'import secrets,sys;sys.stdout.write(secrets.token_urlsafe(48))' > "$ROOT/data/secret.key"
  echo "[ok]   generated data/secret.key (signing key for this installation)"
fi
export ST_ENV=development
export ST_SECRET_KEY
ST_SECRET_KEY="$(cat "$ROOT/data/secret.key")"
export ST_DATABASE_PATH="$ROOT/data/shadowtrace.db"
export ST_BASE_URL="http://localhost:$API_PORT"
export ST_ALLOWED_HOSTS="localhost,127.0.0.1"
export ST_CORS_ORIGINS="http://localhost:$API_PORT,http://127.0.0.1:$API_PORT"
export ST_COOKIE_SECURE=false
export ST_LOG_LEVEL=INFO
export ST_SCANNING_ENABLED=true
# The one approved private destination: the bundled lab, exact host:port.
export ST_PRIVATE_ALLOWLIST="127.0.0.1:$LAB_PORT"
export ST_LAB_ENABLED=true
export ST_LAB_HOST=127.0.0.1
export ST_LAB_PORT="$LAB_PORT"
export ST_LAB_AUTOSTART=true
export ST_DEMO_MODE=false
export ST_BOOTSTRAP_ADMIN_EMAIL=admin@example.test
export ST_BOOTSTRAP_ADMIN_PASSWORD='Bootstrap-Admin-Pass-9!'
export ST_BOOTSTRAP_ORG_NAME="ShadowTrace Local"

echo "ShadowTrace local start"
echo "  project : $ROOT"
echo "  python  : $PY"
echo "  database: $ST_DATABASE_PATH"

( cd "$ROOT/backend" && "$PY" -m app.cli init ) || {
  echo "[fail] database migrations failed (see the error above)"
  exit 1
}

# Read the user count BEFORE the API starts: the API bootstraps the administrator during
# startup, so probing afterwards would always report "users exist" and the credential would
# never be printed on a genuine first run.
ST_USERS="$("$PY" "$ROOT/scripts/wait_healthy.py" --user-count --db "$ST_DATABASE_PATH" 2>/dev/null || echo -1)"
if [ "$ST_USERS" = "0" ]; then
  echo "[ok]   first run: the bootstrap administrator will be created"
fi

START_EPOCH="$("$PY" -c 'import time,sys;sys.stdout.write(str(int(time.time())))')"
: > "$ROOT/logs/api.log"
: > "$ROOT/logs/worker.log"
( cd "$ROOT/backend" && exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$API_PORT" ) \
  > "$ROOT/logs/api.log" 2>&1 &
echo $! > "$ROOT/data/api.pid"
( cd "$ROOT/backend" && exec "$PY" -m app.workers.worker ) \
  > "$ROOT/logs/worker.log" 2>&1 &
echo $! > "$ROOT/data/worker.pid"
echo "[info] api pid $(cat "$ROOT/data/api.pid"), worker pid $(cat "$ROOT/data/worker.pid")"

"$PY" "$ROOT/scripts/wait_healthy.py" --url "http://127.0.0.1:$API_PORT/api/v1/health" \
  --label "API" --timeout 90 --log-file "$ROOT/logs/api.log" --require-log-line "application_started" \
  --tail "$ROOT/logs/api.log" --tail-lines 30 || {
  echo "[fail] the API did not start; stopping the worker"
  "$ROOT/stop.sh" >/dev/null 2>&1
  exit 1
}

if ! "$PY" "$ROOT/scripts/wait_healthy.py" --url "http://127.0.0.1:$LAB_PORT/healthz" \
  --label "training lab" --timeout 60; then
  echo "[warn] the training lab is not healthy; the Lab page shows the supervisor error"
fi

"$PY" "$ROOT/scripts/wait_healthy.py" --worker --db "$ST_DATABASE_PATH" --since "$START_EPOCH" --timeout 60 \
  --tail "$ROOT/logs/worker.log" --tail-lines 30 || {
  echo "[fail] the worker is not heartbeating, so scans would never run; stopping"
  "$ROOT/stop.sh" >/dev/null 2>&1
  exit 1
}

# ST_USERS was captured before the API started, so it still says whether bootstrap ran now.
echo
echo "ShadowTrace is ready"
echo "  UI + API      http://127.0.0.1:$API_PORT/"
echo "  training lab  http://127.0.0.1:$LAB_PORT/"
if [ "$ST_USERS" = "0" ]; then
  echo "  sign in       admin@example.test / Bootstrap-Admin-Pass-9!   (first run: created just now)"
else
  echo "  sign in       the administrator account already in this database"
  echo "                bootstrap was skipped (users exist); to reset a password offline:"
  echo "                  cd backend && ../.venv313/bin/python -m app.cli reset-password --email admin@example.test"
fi
echo "  logs          logs/api.log   logs/worker.log"
echo "  stop          ./stop.sh"
