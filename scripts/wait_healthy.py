"""Readiness probes used by ``start.cmd`` (Windows) and ``start.sh`` (POSIX).

Every probe answers one question: *is the thing I just started actually alive* — not
"is something answering". That distinction is the whole point. A previous version of this
script accepted any fresh row in ``worker_heartbeats``, so a worker from an older run made a
dead new worker look healthy, and the operator was told "ready" for a stack that was not
serving the database they had just configured.

Probes
------
``--url URL``             poll an HTTP endpoint until it answers 2xx.
``--require-log-line``    additionally require a line in ``--log-file`` that only the process
                          started by *this* run writes (e.g. ``application_started``). A stale
                          API that already held the port does not write it.
``--worker``              require a heartbeat written by a worker that started at or after
                          ``--since`` (epoch seconds recorded before the windows were opened).
``--user-count``          print the number of user rows and exit (read-only). Used to decide
                          whether bootstrap will run, so the credential is only printed on a
                          first start.

On failure the probe prints the tail of the logs it was given, so a broken startup reports the
real error instead of a bare "did not start". Exit code 0 means healthy, 1 means the probe
timed out or failed, 2 means the probe was misconfigured.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from typing import List, Optional, Sequence, Tuple


def _http_ok(url: str, timeout: float) -> Tuple[bool, str]:
    """Return (healthy, detail). Any HTTP error is a failure with its status code."""
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "shadowtrace-start"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - fixed local URL
            body = response.read(200).decode("utf-8", errors="replace").strip()
            return 200 <= response.status < 300, f"HTTP {response.status} {body[:120]}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code} {exc.reason}"
    except (urllib.error.URLError, OSError) as exc:
        return False, f"not reachable ({exc})"


def _log_contains(path: str, needle: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return needle in handle.read()
    except OSError:
        return False


def wait_for_url(url: str, timeout: float, label: str, log_file: str = "", required_line: str = "") -> bool:
    deadline = time.time() + timeout
    detail = "no attempt made"
    while time.time() < deadline:
        healthy, detail = _http_ok(url, timeout=2.0)
        if healthy:
            if required_line and log_file and not _log_contains(log_file, required_line):
                # Something answers, but it is not the process this run started: the port is
                # held by an older API (typically with a different ST_DATABASE_PATH). Signing
                # in against it would hit the wrong database, so this is a failure, not a pass.
                print(f"[fail] {label} answers at {url}, but {log_file} does not contain "
                      f"{required_line!r} -- the port is held by a process this run did not start")
                return False
            print(f"[ok]   {label} is healthy at {url} ({detail})")
            return True
        time.sleep(0.5)
    print(f"[fail] {label} did not become healthy at {url} within {int(timeout)}s -- last result: {detail}")
    return False


def wait_for_worker(db_path: str, timeout: float, max_age: int = 20, since: float = 0.0) -> bool:
    """A worker counts as alive when *this run's* worker wrote a fresh heartbeat.

    ``since`` is the epoch second recorded before the worker window was opened. Rows written
    by an older worker are ignored, which is what makes the probe mean "the process I started
    is alive" rather than "some worker exists". Reading the same file the API uses is the
    other half: a worker started with a different ``ST_DATABASE_PATH`` never shows up here.
    """
    deadline = time.time() + timeout
    detail = f"{db_path} does not exist yet"
    while time.time() < deadline:
        if os.path.isfile(db_path):
            try:
                connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
                try:
                    row = connection.execute(
                        "SELECT worker_id, MAX(last_seen_at) AS seen, SUM(scans_run) AS runs "
                        "FROM worker_heartbeats WHERE started_at >= ?",
                        (int(since),),
                    ).fetchone()
                finally:
                    connection.close()
                if row and row[1] is not None and int(time.time()) - int(row[1]) <= max_age:
                    print(f"[ok]   worker {row[0]} heartbeating {int(time.time()) - int(row[1])}s ago "
                          f"(scans run: {int(row[2] or 0)})")
                    return True
                detail = ("no fresh heartbeat from a worker started by this run"
                          if since else "no fresh heartbeat yet")
            except sqlite3.Error as exc:
                detail = f"database not ready ({exc})"
        time.sleep(0.5)
    print(f"[fail] no worker heartbeat in {db_path} within {int(timeout)}s -- {detail}")
    if since:
        print("       a heartbeat from an earlier run does not count: the worker you just")
        print("       started either failed or is pointed at another database.")
    return False


def user_count(db_path: str) -> Optional[int]:
    """Number of user rows, read-only. None when the database is not readable yet."""
    if not os.path.isfile(db_path):
        return None
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        try:
            return int(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0])
        finally:
            connection.close()
    except (sqlite3.Error, TypeError):
        return None


def tail(paths: Sequence[str], lines: int) -> None:
    for path in paths:
        print(f"\n--- last {lines} lines of {path} ---")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text: List[str] = handle.readlines()
        except OSError as exc:
            print(f"(could not read the log: {exc})")
            continue
        if not text:
            print("(the log is empty -- the process may have exited before writing anything)")
            continue
        for line in text[-lines:]:
            print(line.rstrip())


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Wait until ShadowTrace is ready.")
    parser.add_argument("--url", help="HTTP endpoint to poll (for example http://127.0.0.1:8000/api/v1/health)")
    parser.add_argument("--worker", action="store_true", help="wait for a fresh worker heartbeat instead")
    parser.add_argument("--user-count", action="store_true", help="print the number of users and exit")
    parser.add_argument("--db", default="", help="database path (defaults to ST_DATABASE_PATH)")
    parser.add_argument("--label", default="service", help="name printed in the result line")
    parser.add_argument("--timeout", type=float, default=60.0, help="seconds to keep trying")
    parser.add_argument("--since", type=float, default=0.0,
                        help="epoch seconds; a worker started before this is ignored")
    parser.add_argument("--log-file", default="", help="log the started process writes to")
    parser.add_argument("--require-log-line", default="",
                        help="fail unless this text appears in --log-file (proves the process started)")
    parser.add_argument("--tail", action="append", default=[], help="log file to print on failure (repeatable)")
    parser.add_argument("--tail-lines", type=int, default=25, help="how many log lines to print on failure")
    args = parser.parse_args(argv)

    if not (args.url or args.worker or args.user_count):
        parser.error("pass --url, --worker or --user-count")

    db_path = args.db or os.environ.get("ST_DATABASE_PATH", "")

    if args.user_count:
        count = user_count(db_path) if db_path else None
        if count is None:
            print("-1")  # unknown: the caller must not claim "first run"
            return 2
        print(count)
        return 0

    if args.worker:
        if not db_path:
            print("[fail] --worker needs --db or ST_DATABASE_PATH")
            healthy = False
        else:
            healthy = wait_for_worker(db_path, args.timeout, since=args.since)
    else:
        healthy = wait_for_url(args.url or "", args.timeout, args.label,
                               log_file=args.log_file, required_line=args.require_log_line)

    if not healthy and args.tail:
        tail(args.tail, args.tail_lines)
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
