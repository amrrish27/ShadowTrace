@echo off
rem ===========================================================================
rem  ShadowTrace -- one-command local start for Windows (CMD).
rem
rem    start.cmd
rem
rem  What it does, in order:
rem    1. finds a Python 3.10+ interpreter (prefers .venv313, then .venv, then py/python)
rem    2. refuses to continue with a readable message if the backend deps are missing
rem    3. builds the frontend bundle once, if it is not there yet
rem    4. applies database migrations to ONE shared SQLite file
rem    5. starts the API (which also starts the isolated training lab) and the worker
rem       in two windows, both logging to logs\*.log
rem    6. waits until the API answers, the lab is healthy and the worker heartbeats in
rem       the same database -- and prints the log tail if any of that fails
rem
rem  Every setting below is exported to both child processes, so the API and the
rem  worker cannot disagree about the database path or the allow-list. That
rem  disagreement is what produced policy_blocked scans in earlier rounds.
rem
rem  DELAYED EXPANSION IS OFF ON PURPOSE. While `setlocal EnableDelayedExpansion` is in
rem  force, cmd.exe consumes an unescaped '!' when it parses a `set "NAME=value"` statement.
rem  The bootstrap password below ends in '!', so that mode silently stored a 22-character
rem  password, hashed it, printed it, and made the documented credential impossible to use.
rem  Nothing here needs delayed expansion: every "did the previous command fail" test is an
rem  immediate `if errorlevel 1`, which reads the live exit code without any variable.
rem
rem  Stop everything with stop.cmd, or Ctrl+C in each of the two windows.
rem ===========================================================================
setlocal EnableExtensions DisableDelayedExpansion
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
cd /d "%ROOT%"

rem --- ports (override before running, e.g. `set API_PORT=8080` then start.cmd) ---
if not defined API_PORT set "API_PORT=8000"
if not defined LAB_PORT set "LAB_PORT=8099"

echo.
echo ShadowTrace local start
echo   project : %ROOT%
echo   api     : http://127.0.0.1:%API_PORT%/
echo   lab     : http://127.0.0.1:%LAB_PORT%/
echo.

rem --- 1. locate Python ------------------------------------------------------
set "PY="
if exist "%ROOT%\.venv313\Scripts\python.exe" set "PY=%ROOT%\.venv313\Scripts\python.exe"
if not defined PY if exist "%ROOT%\.venv\Scripts\python.exe" set "PY=%ROOT%\.venv\Scripts\python.exe"
if not defined PY (
    for /f "usebackq delims=" %%I in (`py -3.13 -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
)
if not defined PY (
    for /f "usebackq delims=" %%I in (`py -3 -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
)
if not defined PY (
    for /f "usebackq delims=" %%I in (`python -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
)
if not defined PY goto :no_python
echo [ok]   python  %PY%

"%PY%" -c "import sys;raise SystemExit(0 if sys.version_info>=(3,10) else 1)" >nul 2>&1
if errorlevel 1 goto :old_python

rem --- 2. backend dependencies ----------------------------------------------
"%PY%" -c "import fastapi,uvicorn,sqlite3" >nul 2>&1
if errorlevel 1 goto :no_deps

rem --- 3. frontend bundle (built once) --------------------------------------
if exist "%ROOT%\frontend\dist\index.html" goto :have_bundle
where npm >nul 2>&1
if errorlevel 1 goto :no_node
if exist "%ROOT%\frontend\node_modules" goto :do_build
echo [info] frontend dependencies missing -- running npm ci once (this needs network)
pushd "%ROOT%\frontend"
call npm ci
if errorlevel 1 (
    popd
    goto :npm_ci_failed
)
popd
echo [ok]   frontend dependencies installed
:do_build
echo [info] frontend bundle missing -- building it once (npm run build)
pushd "%ROOT%\frontend"
call npm run build
if errorlevel 1 (
    popd
    goto :build_failed
)
popd
if not exist "%ROOT%\frontend\dist\index.html" goto :build_failed
echo [ok]   frontend bundle built
:have_bundle

rem --- 4. shared configuration ---------------------------------------------
rem  Local development values only. This file never reads a production key and
rem  ST_ENV=development is refused in a production deployment.
if not exist "%ROOT%\data" mkdir "%ROOT%\data"
if not exist "%ROOT%\logs" mkdir "%ROOT%\logs"

rem  The signing key (lab grants) is generated once per installation and reused, so the
rem  value is not a published constant that any reader of this archive can reuse.
if not exist "%ROOT%\data\secret.key" (
    "%PY%" -c "import secrets,sys;sys.stdout.write(secrets.token_urlsafe(48))" > "%ROOT%\data\secret.key"
    echo [ok]   generated data\secret.key (signing key for this installation)
)
set "ST_SECRET_KEY="
set /p ST_SECRET_KEY=<"%ROOT%\data\secret.key"
if not defined ST_SECRET_KEY goto :no_secret

set "ST_ENV=development"
set "ST_DATABASE_PATH=%ROOT%\data\shadowtrace.db"
set "ST_BASE_URL=http://localhost:%API_PORT%"
set "ST_ALLOWED_HOSTS=localhost,127.0.0.1"
set "ST_CORS_ORIGINS=http://localhost:%API_PORT%,http://127.0.0.1:%API_PORT%"
set "ST_COOKIE_SECURE=false"
set "ST_LOG_LEVEL=INFO"
set "ST_SCANNING_ENABLED=true"
rem  The single approved private destination: the bundled lab, exact host:port.
rem  Nothing else in private address space becomes reachable by starting this script.
set "ST_PRIVATE_ALLOWLIST=127.0.0.1:%LAB_PORT%"
set "ST_LAB_ENABLED=true"
set "ST_LAB_HOST=127.0.0.1"
set "ST_LAB_PORT=%LAB_PORT%"
set "ST_LAB_AUTOSTART=true"
set "ST_DEMO_MODE=false"
rem  First-run administrator. Bootstrap is skipped once any user exists.
set "ST_BOOTSTRAP_ADMIN_EMAIL=admin@example.test"
set "ST_BOOTSTRAP_ADMIN_PASSWORD=Bootstrap-Admin-Pass-9!"
set "ST_BOOTSTRAP_ORG_NAME=ShadowTrace Local"

rem --- 4b. the credential must survive CMD parsing --------------------------
rem  The literal above is exactly 23 characters. If a character was consumed (delayed
rem  expansion, an editor, a copy/paste) refuse to start here -- before migrations and
rem  before the API can hash a different password -- instead of failing later at the
rem  login page with "Email or password is incorrect."
"%PY%" -c "import os,sys;sys.exit(0 if len(os.environ.get('ST_BOOTSTRAP_ADMIN_PASSWORD',''))==23 else 1)"
if errorlevel 1 goto :password_mangled
echo [ok]   database %ST_DATABASE_PATH%

rem --- migrations before either process opens the database ------------------
pushd "%ROOT%\backend"
"%PY%" -m app.cli init
if errorlevel 1 (
    popd
    goto :db_failed
)
popd
echo [ok]   migrations applied

rem  Read the user count NOW, before the API starts: the API bootstraps the administrator
rem  during startup, so probing afterwards would always report "users exist" and the
rem  credential below would never be printed on a genuine first run.
set "ST_USERS=-1"
"%PY%" "%ROOT%\scripts\wait_healthy.py" --user-count --db "%ST_DATABASE_PATH%" > "%ROOT%\data\users.txt" 2>nul
set /p ST_USERS=<"%ROOT%\data\users.txt"
if "%ST_USERS%"=="0" echo [ok]   first run: the bootstrap administrator will be created

rem  Record the launch time: the readiness probes ignore worker heartbeats written
rem  before this instant, so an older worker cannot make a dead new one look healthy.
rem  Written to a file and read back with `set /p`, NOT with `for /f`. A `for /f` whose
rem  command begins with a quote (`'"%PY%" -c "..."'`) is mangled by cmd.exe into
rem  `...python.exe" -c "import`, which is the "'...' is not recognized" error, and the
rem  empty START_EPOCH then made the worker probe die with "--since: expected one argument".
set "START_EPOCH="
if exist "%ROOT%\data\start_epoch.txt" del /q "%ROOT%\data\start_epoch.txt"
"%PY%" -c "import time;print(int(time.time()))" > "%ROOT%\data\start_epoch.txt" 2>nul
if exist "%ROOT%\data\start_epoch.txt" set /p START_EPOCH=<"%ROOT%\data\start_epoch.txt"
if not defined START_EPOCH goto :no_epoch

rem --- 5. start the processes ----------------------------------------------
rem  Two windows, two log files. The lab is a child of the API (ST_LAB_AUTOSTART=1)
rem  so stopping the API stops the lab too, and the Lab page can restart it.
rem  The log is truncated first, so "application_started" in it can only come from this run.
if exist "%ROOT%\logs\api.log" del /q "%ROOT%\logs\api.log"
if exist "%ROOT%\logs\worker.log" del /q "%ROOT%\logs\worker.log"
rem  Launched through scripts\run_service.py, which records its PID in data\<service>.pid
rem  before the service runs. stop.cmd kills *that* PID after checking it is still this
rem  launcher -- not "whatever window is titled ShadowTrace API", which would also kill a
rem  second stack on a different port.
if exist "%ROOT%\data\api.pid" del /q "%ROOT%\data\api.pid"
if exist "%ROOT%\data\worker.pid" del /q "%ROOT%\data\worker.pid"
start "ShadowTrace API" /D "%ROOT%\backend" cmd /c ""%PY%" "%ROOT%\scripts\run_service.py" api --host 127.0.0.1 --port %API_PORT% > "%ROOT%\logs\api.log" 2>&1"
echo [info] API window started  (log: logs\api.log)
start "ShadowTrace Worker" /D "%ROOT%\backend" cmd /c ""%PY%" "%ROOT%\scripts\run_service.py" worker > "%ROOT%\logs\worker.log" 2>&1"
echo [info] worker window started  (log: logs\worker.log)

rem --- 6. wait until it is actually usable ----------------------------------
"%PY%" "%ROOT%\scripts\wait_healthy.py" --url "http://127.0.0.1:%API_PORT%/api/v1/health" ^
  --label "API" --timeout 90 --log-file "%ROOT%\logs\api.log" --require-log-line "application_started" ^
  --tail "%ROOT%\logs\api.log" --tail-lines 30
if errorlevel 1 goto :api_failed

"%PY%" "%ROOT%\scripts\wait_healthy.py" --url "http://127.0.0.1:%LAB_PORT%/healthz" --label "training lab" --timeout 60 --tail "%ROOT%\logs\api.log" --tail-lines 20
if errorlevel 1 (
    echo [warn] the lab is not healthy. The rest of the app still works; open the Lab
    echo        page for the supervisor error, or re-run start.cmd to retry.
)

"%PY%" "%ROOT%\scripts\wait_healthy.py" --worker --db "%ST_DATABASE_PATH%" --since %START_EPOCH% --timeout 60 --tail "%ROOT%\logs\worker.log" --tail-lines 30
if errorlevel 1 goto :worker_failed

rem --- 7. report ------------------------------------------------------------
rem  ST_USERS was read before the API started (above), so it still describes whether
rem  bootstrap ran *this* time. After the first start the password is never re-applied, so
rem  echoing it would advertise a credential that does not exist.
echo.
echo ShadowTrace is ready
echo   UI + API      http://127.0.0.1:%API_PORT%/
echo   training lab  http://127.0.0.1:%LAB_PORT%/
if "%ST_USERS%"=="0" (
    echo   sign in       %ST_BOOTSTRAP_ADMIN_EMAIL% / %ST_BOOTSTRAP_ADMIN_PASSWORD%
    echo                 ^(first run: this credential was created just now^)
) else (
    echo   sign in       the administrator account already in this database
    echo                 bootstrap was skipped ^(users exist^); to reset a password offline:
    echo                   cd backend
    echo                   "%PY%" -m app.cli reset-password --email admin@example.test
)
echo   logs          logs\api.log   logs\worker.log
echo   stop          stop.cmd   (or Ctrl+C in each of the two windows)
echo.
echo Next: Targets ^> New target ^> Run scan, or Lab ^> Run scan against the lab.
exit /b 0

:no_python
echo [fail] No Python interpreter found.
echo        Install Python 3.13 from python.org, or create the documented virtualenv:
echo          py -3.13 -m venv .venv313
echo          .venv313\Scripts\python.exe -m pip install -r requirements.txt
exit /b 1

:old_python
echo [fail] Python 3.10 or newer is required (3.13 is what this project tests against).
echo        Found: %PY%
"%PY%" --version
exit /b 1

:no_deps
echo [fail] Backend dependencies are missing for %PY%
echo        Run:
echo          "%PY%" -m pip install -r requirements.txt
exit /b 1

:no_secret
echo [fail] data\secret.key could not be created or read. Check that data\ is writable.
exit /b 1

:password_mangled
echo [fail] ST_BOOTSTRAP_ADMIN_PASSWORD did not survive CMD parsing (expected 23 characters).
echo        A '!' in the value is the usual cause: cmd.exe consumes it while delayed
echo        expansion is on. Nothing in the database was changed. Re-download start.cmd,
echo        or run `cmd /v:off /c start.cmd`.
exit /b 1

:no_node
echo [warn] Node.js / npm was not found, so the frontend bundle cannot be built.
echo        Install Node 20+, then run:
echo          cd frontend
echo          npm ci
echo          npm run build
echo        The API is starting anyway and will answer on /api/v1/health.
goto :have_bundle

:npm_ci_failed
echo [fail] "npm ci" failed in frontend. Dependencies are not shipped in the archive, so a
echo        fresh copy needs this once. Check the network/proxy settings and re-run start.cmd.
exit /b 1

:build_failed
echo [fail] "npm run build" failed in frontend. Fix the error above and re-run start.cmd.
exit /b 1

:db_failed
echo [fail] Database migrations failed. The error is printed above.
echo        Check that data\ is writable and that ST_DATABASE_PATH is a local file.
exit /b 1

:api_failed
echo.
echo [fail] The API did not start. Stopping the worker window.
call "%ROOT%\stop.cmd" >nul 2>&1
exit /b 1

:worker_failed
echo.
echo [fail] The worker is not heartbeating. Scans would queue and never run, so this
echo        counts as a failed start. Both windows are being stopped; the worker log
echo        tail above has the reason (usually a database path or permission error).
call "%ROOT%\stop.cmd" >nul 2>&1
exit /b 1

:no_epoch
echo.
echo [fail] Could not record the start time (data\start_epoch.txt is empty).
echo        The readiness check uses it to ignore heartbeats written by an older worker,
echo        so starting without it could report a dead worker as healthy.
echo        Re-run start.cmd. If it repeats, check that this prints a number:
echo          "%PY%" -c "import time;print(int(time.time()))"
call "%ROOT%\stop.cmd" >nul 2>&1
exit /b 1
