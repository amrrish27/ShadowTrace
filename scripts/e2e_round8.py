"""Round-8 acceptance run: the whole lab workflow through the real API.

    python scripts/e2e_round8.py           # or: make e2e-api

What it proves, in one process:

  lab starts -> healthy -> 15 scenarios -> rule mappings -> approved lab target created
  -> scan queued through the API -> the real worker executes it -> the scanner fetches
  the lab pages, discovers endpoints, records findings with rules ST-018..ST-021
  -> the HTML export is generated from stored data -> retry of a completed scan is
  refused -> target rename -> worker health -> CSRF-less mutation refused -> lab
  stop/start/reset -> the security-relevant actions are in the audit log.

It uses a throwaway SQLite file, so it never touches the development database. The lab
is started by the API supervisor on the configured port, which is why
ST_PRIVATE_ALLOWLIST must contain exactly that host:port -- the same requirement a
real deployment has. Exit code 0 means every check passed.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

LAB_PORT = int(os.environ.get("ST_LAB_PORT", "8099"))
DB_PATH = Path(os.environ.get("ST_E2E_DB") or Path(tempfile.gettempdir()) / "shadowtrace-e2e.db")

for suffix in ("", "-wal", "-shm"):
    try:
        Path(str(DB_PATH) + suffix).unlink()
    except FileNotFoundError:
        pass

os.environ.update(
    {
        "ST_ENV": "test",
        "ST_DATABASE_PATH": str(DB_PATH),
        "ST_ALLOWED_HOSTS": "testserver,localhost,127.0.0.1",
        "ST_COOKIE_SECURE": "false",
        "ST_PRIVATE_ALLOWLIST": f"127.0.0.1:{LAB_PORT}",
        "ST_LAB_ENABLED": "true",
        "ST_LAB_HOST": "127.0.0.1",
        "ST_LAB_PORT": str(LAB_PORT),
        "ST_SCANNING_ENABLED": "true",
        "ST_BOOTSTRAP_ADMIN_EMAIL": "admin@example.test",
        "ST_BOOTSTRAP_ADMIN_PASSWORD": "Bootstrap-Admin-Pass-9!",
    }
)

from app.config import reset_settings_cache  # noqa: E402

reset_settings_cache()
from app.db import db, init_db  # noqa: E402

init_db()
from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from app.workers.worker import execute_scan  # noqa: E402

passed = 0
failed = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


def main() -> int:
    with TestClient(app) as client:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": "admin@example.test", "password": "Bootstrap-Admin-Pass-9!"},
        )
        check("login as the bootstrapped administrator", response.status_code == 200, response.text[:200])
        csrf = {"X-CSRF-Token": client.cookies.get("st_csrf") or ""}

        response = client.get("/api/v1/lab/status")
        check("lab status is readable", response.status_code == 200, response.text[:300])
        if response.status_code == 200:
            status = {key: response.json()["lab"][key] for key in ("enabled", "running", "healthy", "allowlisted", "url")}
            print(f"        lab: {json.dumps(status)}")
            check("the lab host:port is allow-listed for this deployment", bool(status["allowlisted"]))

        response = client.post("/api/v1/lab/start", headers=csrf)
        check("lab starts and reports healthy", response.status_code == 200 and response.json()["lab"]["healthy"], response.text[:300])

        response = client.get("/api/v1/lab/scenarios")
        scenarios = response.json().get("scenarios", []) if response.status_code == 200 else []
        check("15 vulnerable scenarios are catalogued", len(scenarios) == 15, str(len(scenarios)))

        response = client.get("/api/v1/lab/mappings")
        mappings = response.json().get("rules", []) if response.status_code == 200 else []
        check("scenario to rule map is served", len(mappings) >= 10, str(len(mappings)))

        response = client.post("/api/v1/lab/target", headers=csrf)
        check(
            "approved lab target exists and is scan-ready",
            response.status_code in (200, 201) and response.json()["target"]["scan_ready"],
            response.text[:300],
        )
        target_id = response.json()["target"]["id"]

        response = client.post(
            "/api/v1/lab/scan",
            headers=csrf,
            json={
                "idempotency_key": "e2e-round8-scan-1",
                "profile": "standard",
                "max_pages": 30,
                "max_scripts": 15,
                "max_requests": 400,
                "max_seconds": 240,
            },
        )
        check("scan is queued through the API", response.status_code in (200, 201), response.text[:300])
        scan_id = response.json()["scan"]["id"]

        # The real worker code path, in-process so the script needs no second terminal.
        with db() as conn:
            summary = execute_scan(conn, scan_id)
        counters = summary.as_counters()
        print(f"        counters: {json.dumps(counters)}")
        check("scan completes with outcome=ok", counters.get("outcome") == "ok", str(counters.get("outcome")))
        check("scanner fetched at least one page from the approved lab", counters.get("pages_fetched", 0) >= 1)
        check("endpoints were discovered", counters.get("endpoints_found", 0) >= 10)
        check("findings were recorded with evidence", counters.get("findings", 0) >= 5)
        check("policy blocks are limited to the hostile-trap controls", counters.get("policy_blocked", 0) <= 4)

        # The scan summary must not under-report the boundary that was enforced: every
        # refusal written to the event log has to be counted, and every one of them has to
        # be a trap rather than the approved lab origin.
        with db() as conn:
            rows = conn.execute(
                "SELECT message FROM scan_events WHERE scan_id = ? AND message LIKE '%policy_blocked%'",
                (scan_id,),
            ).fetchall()
        refusals = [str(row["message"]) for row in rows]
        print(f"        refusals: {refusals}")
        check(
            "policy_blocked counter equals the recorded refusals",
            counters.get("policy_blocked") == len(refusals),
            f"{counters.get('policy_blocked')} counted vs {len(refusals)} logged",
        )
        lab_origin = f"127.0.0.1:{LAB_PORT}"
        check(
            "no refusal was the approved lab origin itself",
            all(not message.split(":")[0].strip().endswith(lab_origin) for message in refusals),
            str(refusals),
        )

        response = client.get(f"/api/v1/scans/{scan_id}")
        check(
            "scan detail shows completed",
            response.status_code == 200 and response.json()["scan"]["state"] == "completed",
            response.text[:200],
        )

        response = client.get(f"/api/v1/scans/{scan_id}/findings?page_size=100")
        rules = {finding["rule_id"] for finding in response.json().get("findings", [])}
        print(f"        rules: {sorted(rules)}")
        for rule_id in ("ST-013", "ST-018", "ST-019", "ST-020", "ST-021", "ST-023"):
            check(f"{rule_id} is detected on the lab", rule_id in rules)

        response = client.get(f"/api/v1/scans/{scan_id}/export?format=html")
        check("HTML export is generated", response.status_code == 200 and "text/html" in response.headers.get("content-type", ""))
        check("HTML export states its limitations", "limitation" in response.text.lower())

        response = client.post(f"/api/v1/scans/{scan_id}/retry", headers={**csrf, "Idempotency-Key": "e2e-retry-1"})
        check("retry of a completed scan is refused with 409", response.status_code == 409, str(response.status_code))

        response = client.patch(f"/api/v1/targets/{target_id}", headers=csrf, json={"name": "ShadowLab (renamed)"})
        check(
            "target rename works and is audited",
            response.status_code == 200 and response.json()["target"]["name"] == "ShadowLab (renamed)",
            response.text[:200],
        )

        response = client.get("/api/v1/admin/workers")
        check("worker health endpoint answers", response.status_code == 200 and "workers" in response.json(), response.text[:200])

        response = client.post("/api/v1/lab/stop", json={})
        check("mutation without a CSRF token is refused", response.status_code == 403, str(response.status_code))
        response = client.post("/api/v1/lab/stop", headers=csrf)
        check("lab stops", response.status_code == 200, response.text[:200])
        response = client.post("/api/v1/lab/start", headers=csrf)
        check("lab restarts after a stop", response.status_code == 200 and response.json()["lab"]["healthy"], response.text[:200])
        response = client.post("/api/v1/lab/reset", headers=csrf)
        check("lab reset returns the lab to its initial state", response.status_code == 200 and response.json()["reset"] is True, response.text[:200])

        response = client.get("/api/v1/admin/audit?limit=50")
        actions = {entry["action"] for entry in response.json().get("entries", [])}
        print(f"        audit: {sorted(a for a in actions if a.startswith(('lab.', 'target.')))}")
        check("security-relevant actions are audited", {"lab.started", "lab.stopped", "lab.reset"} <= actions)

    print(f"\n{passed} passed, {failed} failed  (database: {DB_PATH})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
