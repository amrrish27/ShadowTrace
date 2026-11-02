#!/usr/bin/env bash
# Stop what start.sh started: SIGTERM first (uvicorn runs its shutdown hook, which
# stops the lab child and finishes the in-flight scan), then SIGKILL after 10s.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

stop_one() {
  local name="$1" pidfile="$2"
  if [ ! -f "$pidfile" ]; then
    echo "[info] $name was not started by start.sh (no $pidfile)"
    return 0
  fi
  local pid
  pid="$(cat "$pidfile")"
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "[info] $name (pid $pid) is not running"
    rm -f "$pidfile"
    return 0
  fi
  echo "[stop] $name (pid $pid): SIGTERM"
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then
    echo "[stop] $name ignored SIGTERM -- SIGKILL"
    kill -9 "$pid" 2>/dev/null
  fi
  rm -f "$pidfile"
}

# Worker first: it must not pick up a new scan while the API is going down.
stop_one worker "$ROOT/data/worker.pid"
stop_one api "$ROOT/data/api.pid"

if command -v curl >/dev/null 2>&1; then
  if curl -fsS -m 2 "http://127.0.0.1:${LAB_PORT:-8099}/healthz" >/dev/null 2>&1; then
    echo "[warn] something still answers on port ${LAB_PORT:-8099}; it was started outside"
    echo "       start.sh (make lab), so stop.sh leaves it alone."
  fi
fi
echo "[ok]   stopped."
