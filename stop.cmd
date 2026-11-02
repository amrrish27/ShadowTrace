@echo off
rem ===========================================================================
rem  ShadowTrace -- stop what start.cmd started (Windows CMD).
rem
rem    stop.cmd
rem
rem  Asks the API and worker windows to close (graceful: uvicorn runs its
rem  shutdown hook, which stops the lab child and finishes the current scan),
rem  then forces anything that is still alive after five seconds. Closing the
rem  two windows or pressing Ctrl+C in them does the same thing.
rem ===========================================================================
rem  Delayed expansion stays off here too (see the note in start.cmd): it is what
rem  made a password containing "!" silently lose the character.
setlocal EnableExtensions DisableDelayedExpansion
if not defined LAB_PORT set "LAB_PORT=8099"
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
rem  Same interpreter discovery as start.cmd: the venv if it exists, then py -3.13/3, then
rem  python from PATH. stop.cmd needs it only to verify a PID.
if exist "%ROOT%\.venv313\Scripts\python.exe" (
    set "PY=%ROOT%\.venv313\Scripts\python.exe"
) else (
    set "PY="
    for /f "usebackq delims=" %%I in (`py -3.13 -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
    if not defined PY for /f "usebackq delims=" %%I in (`py -3 -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
    if not defined PY for /f "usebackq delims=" %%I in (`python -c "import sys;print(sys.executable)" 2^>nul`) do set "PY=%%I"
)
if not defined PY (
    echo [fail] no Python found; set PY=... or install Python 3.10+
    exit /b 1
)

set "FOUND="
call :stop_service api "%ROOT%\logs\api.log"
call :stop_service worker "%ROOT%\logs\worker.log"

rem  A lab started outside this script (for example `make lab`) is reported so
rem  the port is not left in use with no explanation.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -Command ^
 "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('127.0.0.1', %LAB_PORT%); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    echo [warn] something is still listening on the lab port %LAB_PORT% -- it was started
    echo        outside start.cmd ^(make lab, or the Lab page in another session^).
    echo        Close that window yourself; stop.cmd never kills an unmanaged process.
)

if not defined FOUND (
    echo [info] nothing from start.cmd is running.
    exit /b 0
)
echo [ok]   stopped.
exit /b 0

:stop_service
rem  %1 = service name (api|worker), %2 = its log file
rem  The PID comes from scripts\service_pid.py, which only answers when the process is
rem  alive AND its command line is still run_service.py for this service. A stale pidfile
rem  therefore cannot make this script kill an unrelated process.
set "SVC_PID="
if exist "%ROOT%\data\pid_query.txt" del /q "%ROOT%\data\pid_query.txt" >nul 2>&1
"%PY%" "%ROOT%\scripts\service_pid.py" %~1 --explain > "%ROOT%\data\pid_query.txt" 2>nul
if exist "%ROOT%\data\pid_query.txt" set /p SVC_PID=<"%ROOT%\data\pid_query.txt"
if exist "%ROOT%\data\pid_query.txt" del /q "%ROOT%\data\pid_query.txt" >nul 2>&1
if not defined SVC_PID (
    echo [info] %~1: not started by start.cmd ^(no verified pidfile^) -- not touching it
    exit /b 0
)
echo [stop] %~1 ^(pid %SVC_PID%^): asking it to shut down gracefully ...
taskkill /PID %SVC_PID% /T >nul 2>&1
"%SystemRoot%\System32\timeout.exe" /t 5 /nobreak >nul 2>&1
tasklist /FI "PID eq %SVC_PID%" /FO CSV /NH 2>nul | find "\"%SVC_PID%\"" >nul
if not errorlevel 1 (
    echo [stop] %~1 ignored the request -- forcing it
    taskkill /PID %SVC_PID% /T /F >nul 2>&1
)
if exist "%ROOT%\data\%~1.pid" del /q "%ROOT%\data\%~1.pid" >nul 2>&1
set "FOUND=1"
exit /b 0
