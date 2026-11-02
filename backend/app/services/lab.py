"""Controlled supervisor for the bundled ShadowLab training application.

Security boundary
-----------------
This module runs **one** fixed command: the repository's own
``lab/app/lab.py --host <loopback> --port <port>``, started with ``shell=False`` and an
argv list built here. There is no API input that reaches the command line, no user
supplied path, no environment passthrough and no arbitrary filesystem access. The UI can
start, stop, restart and reset the lab — nothing else.

* The lab binds to a loopback address only (``ST_LAB_HOST`` is validated at startup).
* The whole feature is refused in a production configuration (``config._validate``).
* Every mutating action is admin-only, CSRF-protected (global middleware) and audited by
  the API layer.

Health is checked with a plain TCP connect plus a raw HTTP ``GET /healthz`` over a
loopback socket — deliberately *not* through ``SafeHttpClient``, because the probe must
work before (and independently of) any scan policy, and it must never leave the machine.
"""
from __future__ import annotations

import json
import logging
import os
import socket
# subprocess is imported for exactly one call site: the lab supervisor below starts the
# bundled lab with a fixed argv, shell=False and a scrubbed environment. Nothing from a
# request reaches it. B404 is therefore reviewed, not accidental.
import subprocess  # nosec B404
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional

from ..config import get_settings

log = logging.getLogger("shadowtrace.lab")

#: Environment variables the child needs in order to *start*, none of which carry a secret.
#: CPython on Windows cannot initialise without ``SYSTEMROOT`` (and fails to import socket
#: or ssl without the rest of the system ones); a child that dies during startup never binds
#: its port, which surfaced only as "did not become healthy within the start timeout".
#: POSIX equivalents are included so the same code works under WSL/Linux/macOS.
CHILD_ENV_ALLOWLIST = (
    # Windows
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    # POSIX
    "HOME",
    "TMPDIR",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
)


REPO_ROOT = Path(__file__).resolve().parents[3]
LAB_ENTRYPOINT = REPO_ROOT / "lab" / "app" / "lab.py"
SCENARIOS_FILE = REPO_ROOT / "lab" / "app" / "scenarios.json"
MAX_LOG_LINES = 200
START_TIMEOUT_SECONDS = 20.0
#: The `lab` field ShadowLab reports on /healthz; an adopted process must match it.
LAB_MARKER = "shadowlab"


class LabUnavailable(RuntimeError):
    """Raised when the supervisor is asked to act while the lab cannot be used."""


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_get(host: str, port: int, path: str, timeout: float = 1.5) -> Optional[str]:
    """Minimal loopback HTTP GET. Returns the body, or None when nothing answers.

    A raw socket is used on purpose: this is a liveness probe for a process on the same
    machine, it must not be subject to (or able to bypass) scan policy, and it must not
    pull an HTTP client library into the API process.
    """
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n"
        "User-Agent: ShadowTrace-lab-supervisor\r\n\r\n"
    )
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(request.encode("ascii"))
            chunks = []
            while True:
                data = conn.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(len(chunk) for chunk in chunks) > 64 * 1024:
                    break
    except OSError:
        return None
    raw = b"".join(chunks).decode("latin-1", errors="replace")
    if "\r\n\r\n" not in raw:
        return None
    head, _, body = raw.partition("\r\n\r\n")
    status_line = head.splitlines()[0] if head.splitlines() else ""
    if " 200 " not in f" {status_line} ":
        return None
    return body


def load_scenarios() -> List[Dict[str, Any]]:
    """The scenario catalogue shipped with the lab (read-only, fixed path)."""
    try:
        raw = json.loads(SCENARIOS_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        log.warning("lab_scenarios_unavailable path=%s", SCENARIOS_FILE)
        return []
    scenarios = raw.get("scenarios") if isinstance(raw, dict) else raw
    return [item for item in (scenarios or []) if isinstance(item, dict)]


class LabSupervisor:
    """Owns the lab child process. One instance per API process."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._process: Optional[subprocess.Popen] = None
        self._started_at: Optional[float] = None
        self._last_error = ""
        self._disabled = False
        self._log: Deque[str] = deque(maxlen=MAX_LOG_LINES)
        self._reader: Optional[threading.Thread] = None

    # -- state -----------------------------------------------------------
    @property
    def host(self) -> str:
        return get_settings().lab_host

    @property
    def port(self) -> int:
        return get_settings().lab_port

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def mark_disabled(self) -> None:
        self._disabled = True

    def _pid(self) -> Optional[int]:
        process = self._process
        if process is None:
            return None
        if process.poll() is not None:
            return None
        return process.pid

    def status(self) -> Dict[str, object]:
        """A complete, honest status object for the Lab page."""
        with self._lock:
            settings = get_settings()
            pid = self._pid()
            listening = _port_open(self.host, self.port)
            body = _http_get(self.host, self.port, "/healthz") if listening else None
            healthy = False
            lab_id = ""
            if body:
                try:
                    payload = json.loads(body)
                    lab_id = str(payload.get("lab") or "")
                    # `status: ok` alone is not proof: any local process can answer that.
                    # The marker is what makes "healthy" mean "this is ShadowLab".
                    healthy = payload.get("status") == "ok" and lab_id == LAB_MARKER
                except ValueError:
                    healthy = False
            enabled = settings.lab_enabled and not self._disabled
            uptime = int(time.time() - self._started_at) if (self._started_at and pid) else 0
            return {
                "enabled": enabled,
                "managed": pid is not None,
                "running": listening,
                "healthy": healthy,
                "lab_id": lab_id,
                "pid": pid,
                "url": self.url,
                "host": self.host,
                "port": self.port,
                "uptime_seconds": uptime,
                "entrypoint": str(LAB_ENTRYPOINT.name),
                "warning": (
                    "ShadowLab is an intentionally vulnerable training application. "
                    "It is bound to loopback only and must never be exposed to a network."
                ),
                "last_error": self._last_error,
                "log_tail": list(self._log)[-40:],
            }

    # -- process control -------------------------------------------------
    def _assert_enabled(self) -> None:
        settings = get_settings()
        if not settings.lab_enabled or self._disabled:
            raise LabUnavailable(
                "The training lab is disabled on this deployment (ST_LAB_ENABLED=false)."
            )
        if not LAB_ENTRYPOINT.is_file():
            raise LabUnavailable("The bundled lab entrypoint is missing from this deployment.")

    def _command(self) -> List[str]:
        # Fixed argv. Nothing from a request can influence it.
        return [
            sys.executable,
            "-u",
            str(LAB_ENTRYPOINT),
            "--host",
            self.host,
            "--port",
            str(self.port),
        ]

    def _child_env(self) -> Dict[str, str]:
        """The environment the lab child runs with: enough to start, no secrets.

        Deliberately *not* ``{**os.environ}``: the API's environment holds ``ST_SECRET_KEY``
        and the bootstrap credential, and the lab is an intentionally vulnerable application.
        An allow-list is the only version of this that stays correct when a new secret is
        added to the API later.
        """
        env = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONUNBUFFERED": "1",
            "ST_LAB_PORT": str(self.port),
        }
        for name in CHILD_ENV_ALLOWLIST:
            value = os.environ.get(name)
            if value is not None:
                env[name] = value
        return env

    def _drain(self, process: subprocess.Popen) -> None:
        stream = process.stdout
        if stream is None:  # pragma: no cover - stdout is always piped
            return
        for raw in iter(stream.readline, b""):
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                self._log.append(line)
        try:
            stream.close()
        except OSError:  # pragma: no cover - closing a closed pipe
            pass

    def start(self) -> Dict[str, object]:
        with self._lock:
            self._assert_enabled()
            if _port_open(self.host, self.port):
                # Something already answers on the port: adopt it rather than fighting it.
                if self._pid() is None:
                    self._log.append(
                        f"adopted an already-running lab on {self.host}:{self.port} (not managed by this API)"
                    )
                return self.status()
            if self._pid() is not None:  # pragma: no cover - defensive
                return self.status()
            env = self._child_env()  # no secrets from the API environment reach the lab
            try:
                # argv comes from the deployment settings (loopback host, int port), never
                # from a request; shell=False and an environment with no secrets.
                process = subprocess.Popen(  # noqa: S603  # nosec B603
                    self._command(),
                    cwd=str(REPO_ROOT),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    shell=False,
                )
            except OSError as exc:
                self._last_error = f"could not start the lab: {exc}"
                raise LabUnavailable(self._last_error) from exc
            self._process = process
            self._started_at = time.time()
            self._reader = threading.Thread(
                target=self._drain, args=(process,), name="lab-log-reader", daemon=True
            )
            self._reader.start()
            log.info("lab_started pid=%s url=%s", process.pid, self.url)
        deadline = time.time() + START_TIMEOUT_SECONDS
        exited_early = False
        while time.time() < deadline:
            if _http_get(self.host, self.port, "/healthz"):
                self._last_error = ""
                return self.status()
            if self._pid() is None:
                exited_early = True
                break
            time.sleep(0.15)
        with self._lock:
            exit_code = process.poll()
            # The child's own words are the only useful diagnosis when it dies at startup,
            # so they go into both `last_error` (the Lab page) and the log line an operator
            # greps. Without this the failure reads as a bare timeout (BUG-22).
            tail = " ⏎ ".join(list(self._log)[-8:]).strip()
            if exited_early:
                self._last_error = f"the lab process exited (code {exit_code}) before it became healthy"
            else:
                self._last_error = "the lab did not become healthy within the start timeout"
            if tail:
                self._last_error = f"{self._last_error}: {tail}"
            else:
                self._last_error = (
                    f"{self._last_error}: the child produced no output "
                    "(it may have died before it could print anything)"
                )
            self._terminate_locked()
        # The Lab page shows `last_error`; the log is where an operator looks first.
        log.error(
            "lab_start_failed reason=%s url=%s exit=%s child_output=%s",
            self._last_error,
            self.url,
            exit_code,
            " | ".join(list(self._log)[-8:]) or "(none)",
        )
        raise LabUnavailable(self._last_error)

    def _terminate_locked(self) -> None:
        process = self._process
        self._process = None
        self._started_at = None
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - stubborn child
                process.kill()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    pass
        log.info("lab_stopped pid=%s", process.pid)

    def stop(self, *, graceful: bool = False) -> Dict[str, object]:
        with self._lock:
            if self._disabled and not graceful:
                raise LabUnavailable("The training lab is disabled on this deployment.")
            self._terminate_locked()
            if not graceful:
                self._log.append("lab stopped by operator")
        return self.status()

    def restart(self) -> Dict[str, object]:
        with self._lock:
            self._assert_enabled()
            self._terminate_locked()
            self._log.append("lab restarted by operator — in-memory demo state was reset")
        return self.start()

    def stop_if_managed(self) -> None:
        """Best-effort shutdown used by the lifespan hook and tests."""
        with self._lock:
            self._terminate_locked()


_supervisor = LabSupervisor()


def get_supervisor() -> LabSupervisor:
    return _supervisor


def scenario_catalogue() -> List[Dict[str, Any]]:
    """Catalogue with a live ``enabled`` flag derived from the deployment config."""
    settings = get_settings()
    rows = load_scenarios()
    for row in rows:
        row["enabled"] = bool(settings.lab_enabled)
    return rows
