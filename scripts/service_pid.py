"""Answer "which PID did `start.cmd` start for this service, and is it still that process?"

`stop.cmd` asks this instead of matching window titles. The checks exist so a stale pidfile
can never turn into "kill an unrelated process": a PID is only printed when the process is
alive *and* its command line still says it is this launcher for that service (a PID can be
recycled after a reboot, and on Windows a recycled PID is not hypothetical).

Exit codes, because `stop.cmd` branches on them:

    0  verified: the PID on stdout belongs to this service
    2  usage error
    3  no pidfile (the service was not started by run_service.py)
    4  pidfile present but the process is gone, or is not this launcher
    5  the process exists but its command line could not be read -> refuse to guess
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA = REPO_ROOT / "data"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_PIDFILE = 3
EXIT_STALE = 4
EXIT_UNKNOWN = 5


def pidfile_for(service: str) -> Path:
    return DATA / f"{service}.pid"


def _read_pid(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return -1


def _alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, pid is an int
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout
        return f'"{pid}"' in out
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:  # exists, owned by another user
        return True
    return True


def _command_line(pid: int) -> str | None:
    """The process command line, or None when it cannot be read (do not guess)."""
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        powershell = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / (
            "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
        try:
            result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, pid is an int
                [
                    str(powershell),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine",
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        text = (result.stdout or "").strip()
        return text or None
    proc = Path(f"/proc/{pid}/cmdline")
    if proc.exists():
        try:
            return proc.read_bytes().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            return None
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, pid is an int
            ["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (result.stdout or "").strip() or None


def _is_our_launcher(command_line: str, service: str) -> bool:
    lowered = command_line.lower()
    return "run_service.py" in lowered and service in lowered.split()


def check(service: str) -> tuple[int, str]:
    path = pidfile_for(service)
    if not path.is_file():
        return EXIT_NO_PIDFILE, f"no pidfile at {path}"
    pid = _read_pid(path)
    if pid <= 0:
        return EXIT_STALE, f"{path} does not contain a PID"
    if not _alive(pid):
        return EXIT_STALE, f"PID {pid} from {path} is no longer running"
    command_line = _command_line(pid)
    if command_line is None:
        return EXIT_UNKNOWN, f"could not read the command line of PID {pid}"
    if not _is_our_launcher(command_line, service):
        return EXIT_STALE, f"PID {pid} is not this launcher for {service}: {command_line[:160]}"
    return EXIT_OK, str(pid)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="service_pid", description="Verified service PID")
    parser.add_argument("service", choices=("api", "worker"))
    parser.add_argument("--explain", action="store_true", help="print the reason on failure too")
    args = parser.parse_args(argv)
    code, message = check(args.service)
    if code == EXIT_OK:
        print(message)
    elif args.explain or code == EXIT_UNKNOWN:
        print(message, file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
