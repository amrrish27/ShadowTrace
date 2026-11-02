"""Launch one ShadowTrace service and record its PID so the stop script can find it again.

`start.cmd` used to identify its processes by *window title*, so `stop.cmd` killed whatever
happened to carry that title -- including a second stack on another port, or an unrelated
window a user had named the same way -- and missed the process entirely if the window had
been renamed. Starting through this launcher makes ownership explicit: the PID is written to
`data/<service>.pid` before the service runs, and `scripts/service_pid.py` refuses to hand
that PID back unless the process still looks like this launcher.

    python scripts/run_service.py api --port 8000
    python scripts/run_service.py worker

The service runs **in this process** (same PID), so the pidfile cannot point at a shell that
has already exited. Nothing here takes a command from the user: the two services are fixed.

The pidfile is removed from a ``finally`` block: Ctrl+C and a window close both run it, so the
normal shutdown path leaves nothing behind. ``kill -TERM`` does **not** -- Python's default
SIGTERM handler terminates without unwinding, and uvicorn's own handler can end the process
after its grace period. That is why the file is not the authority: `service_pid.py` refuses a
PID that is no longer this launcher, and `stop.cmd` deletes the file once it has stopped the
process. A leftover file therefore costs one "not ours" message, never a wrong kill.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND = REPO_ROOT / "backend"
DATA = REPO_ROOT / "data"
SERVICES = ("api", "worker")


def pidfile_for(service: str) -> Path:
    return DATA / f"{service}.pid"


def _write_pid(service: str) -> Path:
    DATA.mkdir(parents=True, exist_ok=True)
    path = pidfile_for(service)
    path.write_text(f"{os.getpid()}\n", encoding="utf-8")
    return path


def _clear_pid(path: Path) -> None:
    try:
        if path.read_text(encoding="utf-8").strip() == str(os.getpid()):
            path.unlink()
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_service", description="Run one ShadowTrace service")
    parser.add_argument("service", choices=SERVICES)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)

    # `python scripts/run_service.py` puts `scripts/` on sys.path, not the working directory.
    if str(BACKEND) not in sys.path:
        sys.path.insert(0, str(BACKEND))

    path = _write_pid(args.service)
    try:
        if args.service == "api":
            import uvicorn

            uvicorn.run("app.main:app", host=args.host, port=args.port, log_level="info")
        else:
            from app.workers.worker import main as worker_main

            worker_main([])
    finally:
        _clear_pid(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
