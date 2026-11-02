"""The launcher, the PID verifier and the lab supervisor's child environment.

Three defects are pinned here, all from the same class: **a value the shell or the parent
process could not be trusted to carry**.

* `start.cmd` built its start timestamp with a `for /f` whose command began with a quote, which
  `cmd.exe` mangles ("'...python.exe" -c "import' is not recognized"). `START_EPOCH` was then
  empty, and the worker probe died with "--since: expected one argument". The checker now
  rejects that pattern and any unguarded `--since %VAR%`.
* `stop.cmd` killed processes by *window title*, so it also killed a second stack on another
  port and missed a renamed window. Ownership is now a PID written by `run_service.py` and
  verified by `service_pid.py`.
* The lab supervisor handed its child a three-key environment. CPython on Windows cannot
  start without `SYSTEMROOT`, so the child died before binding a port and the API reported
  only "did not become healthy within the start timeout".
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import check_windows_scripts  # noqa: E402
import service_pid  # noqa: E402


# ---------------------------------------------------------------------------
# Windows entry points: the two defects that produced the reported errors
# ---------------------------------------------------------------------------


def test_the_shipped_windows_scripts_pass_every_rule():
    assert check_windows_scripts.check() == []


def test_the_checker_rejects_a_quoted_for_command(tmp_path, monkeypatch):
    """The exact construct that produced "'...python.exe" -c "import' is not recognized"."""
    script = tmp_path / "start.cmd"
    script.write_text(
        "@echo off\n"
        'set "START_EPOCH="\n'
        'for /f "delims=" %%I in (\'"%PY%" -c "import time;print(1)"\') do set "START_EPOCH=%%I"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(check_windows_scripts, "_cmd_files", lambda: [script])
    problems = check_windows_scripts.check()
    assert any("mangled by cmd.exe" in problem for problem in problems), problems


def test_the_checker_rejects_an_unguarded_since(tmp_path, monkeypatch):
    """An empty START_EPOCH turns `--since %X% --timeout 60` into a missing argument."""
    script = tmp_path / "start.cmd"
    script.write_text(
        "@echo off\n"
        '"%PY%" scripts\\wait_healthy.py --worker --since %START_EPOCH% --timeout 60\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(check_windows_scripts, "_cmd_files", lambda: [script])
    problems = check_windows_scripts.check()
    assert any("--since: expected one argument" in problem for problem in problems), problems


def test_the_guard_satisfies_the_since_rule(tmp_path, monkeypatch):
    script = tmp_path / "start.cmd"
    script.write_text(
        "@echo off\n"
        'set "START_EPOCH="\n'
        "if not defined START_EPOCH goto :no_epoch\n"
        '"%PY%" scripts\\wait_healthy.py --since %START_EPOCH%\n'
        ":no_epoch\nexit /b 1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(check_windows_scripts, "_cmd_files", lambda: [script])
    assert check_windows_scripts.check() == []


def test_start_cmd_no_longer_uses_for_f_for_the_timestamp():
    text = (ROOT / "start.cmd").read_text(encoding="utf-8")
    active = [line for line in text.splitlines() if not line.strip().lower().startswith("rem")]
    assert not any("START_EPOCH=%%I" in line for line in active)
    assert "set /p START_EPOCH=" in text
    assert "if not defined START_EPOCH goto :no_epoch" in text


def test_stop_cmd_no_longer_kills_by_window_title():
    text = (ROOT / "stop.cmd").read_text(encoding="utf-8")
    active = [line for line in text.splitlines() if not line.strip().lower().startswith("rem")]
    assert not any("WINDOWTITLE" in line for line in active), "title matching is not ownership"
    assert "service_pid.py" in text


# ---------------------------------------------------------------------------
# The PID verifier: a stale or foreign pidfile must never authorise a kill
# ---------------------------------------------------------------------------


@pytest.fixture()
def fake_data(tmp_path, monkeypatch):
    """Point the verifier at a temporary data directory."""
    monkeypatch.setattr(service_pid, "DATA", tmp_path)
    return tmp_path


def _spawn(*argv: str) -> subprocess.Popen:
    return subprocess.Popen(list(argv), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_no_pidfile_means_the_service_was_not_started_by_us(fake_data):
    code, message = service_pid.check("api")
    assert code == service_pid.EXIT_NO_PIDFILE
    assert "no pidfile" in message


def test_a_stale_pid_is_refused(fake_data):
    (fake_data / "api.pid").write_text("999999\n", encoding="utf-8")
    code, _message = service_pid.check("api")
    assert code == service_pid.EXIT_STALE


def test_a_recycled_pid_that_is_not_our_launcher_is_refused(fake_data):
    """The safety property: PID reuse (or a doctored pidfile) must not authorise a kill."""
    sleeper = _spawn(sys.executable, "-c", "import time; time.sleep(30)")
    try:
        (fake_data / "api.pid").write_text(f"{sleeper.pid}\n", encoding="utf-8")
        code, message = service_pid.check("api")
        assert code == service_pid.EXIT_STALE, message
        assert "not this launcher" in message
        assert sleeper.poll() is None, "the verifier must not have touched the process"
    finally:
        sleeper.kill()
        sleeper.wait(timeout=10)


def test_a_real_launcher_pid_is_accepted(fake_data):
    """A process whose command line *is* run_service.py api verifies, and its PID is printed."""
    launcher = _spawn(
        sys.executable,
        str(SCRIPTS / "run_service.py"),
        "api",
        "--port",
        "8098",
    )
    try:
        (fake_data / "api.pid").write_text(f"{launcher.pid}\n", encoding="utf-8")
        code, message = service_pid.check("api")
        # The child may still be importing uvicorn; the process identity is what is checked.
        assert code == service_pid.EXIT_OK, message
        assert message == str(launcher.pid)
    finally:
        launcher.kill()
        launcher.wait(timeout=10)


def test_the_worker_pidfile_is_not_confused_with_the_api(fake_data):
    launcher = _spawn(sys.executable, str(SCRIPTS / "run_service.py"), "worker")
    try:
        (fake_data / "api.pid").write_text(f"{launcher.pid}\n", encoding="utf-8")
        code, message = service_pid.check("api")
        assert code == service_pid.EXIT_STALE, message  # it is a worker, not the API
    finally:
        launcher.kill()
        launcher.wait(timeout=10)


def test_run_service_refuses_an_unknown_service():
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "run_service.py"), "shell"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "invalid choice" in (result.stderr + result.stdout)


# ---------------------------------------------------------------------------
# The lab supervisor's environment and error reporting
# ---------------------------------------------------------------------------


def _supervisor():
    from app.services.lab import LabSupervisor

    return LabSupervisor()


def test_the_lab_child_gets_the_windows_variables_it_needs(monkeypatch):
    """CPython on Windows will not start without SYSTEMROOT; the child died silently."""
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    monkeypatch.setenv("SYSTEMDRIVE", "C:")
    monkeypatch.setenv("COMSPEC", r"C:\Windows\System32\cmd.exe")
    monkeypatch.setenv("PATHEXT", ".COM;.EXE;.BAT")
    env = _supervisor()._child_env()
    assert env["SYSTEMROOT"] == r"C:\Windows"
    assert env["SYSTEMDRIVE"] == "C:"
    assert env["COMSPEC"].endswith("cmd.exe")
    assert env["PATHEXT"] == ".COM;.EXE;.BAT"
    assert env["PYTHONUNBUFFERED"] == "1"


def test_the_lab_child_never_receives_a_secret(monkeypatch):
    """The lab is intentionally vulnerable, so the API's secrets must not reach it."""
    monkeypatch.setenv("ST_SECRET_KEY", "s" * 48)
    monkeypatch.setenv("ST_BOOTSTRAP_ADMIN_PASSWORD", "Bootstrap-Admin-Pass-9!")
    monkeypatch.setenv("ST_ADMIN_PASSWORD", "x")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "y")
    env = _supervisor()._child_env()
    for name in env:
        assert name.upper() == "PATH" or not any(
            marker in name.upper() for marker in ("SECRET", "PASSWORD", "TOKEN", "KEY", "SUPABASE")
        ), f"{name} would leak a secret into the lab"
    assert "ST_SECRET_KEY" not in env
    assert "Bootstrap-Admin-Pass-9!" not in " ".join(env.values())


def test_a_lab_that_cannot_start_reports_the_childs_own_words(monkeypatch, tmp_path):
    """The old failure was a bare timeout: the child's stderr never reached the operator."""
    import app.services.lab as lab_module

    # A child that fails the way a broken interpreter does: prints, then exits.
    fake_lab = tmp_path / "lab.py"
    fake_lab.write_text(
        "import sys\n"
        "print('Fatal Python error: init_fs_encoding: failed to get the Python codec')\n"
        "print('ModuleNotFoundError: No module named encodings', file=sys.stderr)\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(lab_module, "LAB_ENTRYPOINT", fake_lab)
    monkeypatch.setattr(lab_module, "START_TIMEOUT_SECONDS", 5)
    supervisor = lab_module.LabSupervisor()
    monkeypatch.setattr(type(supervisor), "port", property(lambda self: 8197))
    monkeypatch.setattr(type(supervisor), "host", property(lambda self: "127.0.0.1"))

    with pytest.raises(lab_module.LabUnavailable) as failure:
        supervisor.start()

    message = str(failure.value)
    assert "exited" in message, message
    assert "init_fs_encoding" in message, f"the child's own words must be surfaced: {message}"
    assert supervisor.status()["last_error"] == message


def test_the_supervisor_command_is_still_fixed(monkeypatch):
    """Regression guard: no part of the argv may come from a request."""
    from app.services.lab import LabSupervisor

    supervisor = LabSupervisor()
    command = supervisor._command()
    assert command[0] == sys.executable
    assert command[1] == "-u"
    assert command[2].endswith("lab.py")
    assert command[3:5] == ["--host", supervisor.host]
    assert int(command[-1]) == supervisor.port


def test_the_lab_is_never_started_with_a_secret_in_its_arguments(monkeypatch):
    monkeypatch.setenv("ST_SECRET_KEY", "s" * 48)
    supervisor = _supervisor()
    joined = " ".join(supervisor._command()) + " ".join(supervisor._child_env().values())
    assert "ST_SECRET_KEY" not in joined
    assert "s" * 48 not in joined
    assert os.environ["ST_SECRET_KEY"] not in joined
