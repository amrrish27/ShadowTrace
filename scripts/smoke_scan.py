"""Developer smoke run: create an org, target, baseline, HAR import and scan against ShadowLab.

Usage:
    ST_ENV=test ST_DATABASE_PATH=/tmp/st_smoke.db ST_PRIVATE_ALLOWLIST=127.0.0.1:8099 \
        python scripts/smoke_scan.py [--base-url http://127.0.0.1:8099]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_settings  # noqa: E402
from app.db import db, init_db, new_id, now  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402
from app.security.tokens import verification_token  # noqa: E402
from app.services import scans as scan_service  # noqa: E402
from app.workers.worker import execute_scan  # noqa: E402


def run_lab_scan(
    *,
    base_url: str = "http://127.0.0.1:8099",
    max_pages: int = 40,
    max_requests: int = 400,
    max_seconds: int = 240,
) -> dict:
    """Create (or reuse) an org, target, baseline and HAR, then run one real scan.

    Shared by `scripts/smoke_scan.py` (developer smoke run) and `scripts/seed_demo.py`
    (the Playwright setup step), so the two cannot drift apart.
    """
    settings = get_settings()
    init_db()
    root = Path(__file__).resolve().parent.parent
    baseline_text = (root / "lab/app/baseline.json").read_text()
    har_text = (root / "lab/fixtures/shadowlab.har").read_text()
    with db() as conn:
        org = conn.execute("SELECT id FROM organizations LIMIT 1").fetchone()
        if org is None:
            org_id = new_id()
            conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, 'Smoke Org', ?)", (org_id, now()))
        else:
            org_id = org["id"]
        user = conn.execute("SELECT id FROM users WHERE org_id = ? LIMIT 1", (org_id,)).fetchone()
        if user is None:
            user_id = new_id()
            conn.execute(
                """INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
                   VALUES (?, ?, 'smoke@example.test', 'Smoke', 'admin', ?, 1, ?)""",
                (user_id, org_id, hash_password("smoke-test-password-123"), now()),
            )
        else:
            user_id = user["id"]
        target = conn.execute("SELECT id FROM targets WHERE org_id = ?", (org_id,)).fetchone()
        if target is None:
            target_id = new_id()
            conn.execute(
                """
                INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes,
                                     authorization_mode, authorization_status, attestation, justification,
                                     verification_token, verified_at, verified_by, created_by, created_at, limits)
                VALUES (?, ?, 'ShadowLab', ?, ?, 'http', '[8099]', '[]', 'lab_allowlist', 'approved',
                        'Operator-configured lab target used for the demo scan.', 'Lab allow-list',
                        ?, ?, ?, ?, ?, '{}')
                """,
                (target_id, org_id, base_url, "127.0.0.1", verification_token(), now(), user_id, user_id, now()),
            )
        else:
            target_id = target["id"]
        baseline_id = new_id()
        conn.execute(
            """INSERT INTO baselines (id, org_id, target_id, source, source_ref, spec, endpoint_count, created_by, created_at)
               VALUES (?, ?, ?, 'upload', 'lab/app/baseline.json', ?, 8, ?, ?)""",
            (baseline_id, org_id, target_id, baseline_text, user_id, now()),
        )
        har_id = new_id()
        from app.engine.extractors.har_extract import parse_har

        har = parse_har(har_text, source_name="shadowlab.har", base_url=base_url, policy_hosts=("127.0.0.1",))
        conn.execute(
            """INSERT INTO har_imports (id, org_id, target_id, name, entries, entry_count, created_by, created_at)
               VALUES (?, ?, ?, 'shadowlab.har', ?, ?, ?, ?)""",
            (har_id, org_id, target_id, json.dumps(har.redacted_entries), har.entries_total, user_id, now()),
        )
        target_row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        scan, _created = scan_service.create_scan(
            conn,
            org_id=org_id,
            user_id=user_id,
            target_row=target_row,
            idempotency_key=new_id(),
            config={
                "include_crawler": True,
                "include_source_maps": True,
                "include_specs": True,
                "active_validation": True,
                "max_pages": max(1, min(max_pages, 200)),
                "max_scripts": 20,
                "max_requests": max(10, min(max_requests, 2000)),
                "max_seconds": max(10, min(max_seconds, 900)),
                "seeds": [],
                "har_import_id": har_id,
            },
            baseline_id=baseline_id,
            settings=settings,
        )
        scan_id = scan["id"]
        summary = execute_scan(conn, scan_id)
        state, partial = conn.execute("SELECT state, partial FROM scans WHERE id = ?", (scan_id,)).fetchone()[:]
        counters = json.loads(
            conn.execute("SELECT counters FROM scans WHERE id = ?", (scan_id,)).fetchone()["counters"] or "{}"
        )
        return {
            "scan_id": scan_id,
            "state": state,
            "partial": bool(partial),
            "counters": counters,
            "summary": summary,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8099")
    parser.add_argument("--max-pages", type=int, default=40)
    parser.add_argument("--max-requests", type=int, default=400)
    parser.add_argument("--max-seconds", type=int, default=240)
    parser.add_argument("--json", action="store_true", help="print the counters as JSON only")
    args = parser.parse_args()
    result = run_lab_scan(
        base_url=args.base_url,
        max_pages=args.max_pages,
        max_requests=args.max_requests,
        max_seconds=args.max_seconds,
    )
    scan_id = result["scan_id"]
    print("scan:", scan_id)
    print(json.dumps(result["counters"], indent=2))
    with db() as conn:
        rows = conn.execute(
            """
            SELECT e.method, e.path_template, e.classification, e.validation_status, e.response_status
            FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id
            WHERE se.scan_id = ? ORDER BY e.classification, e.path_template
            """,
            (scan_id,),
        ).fetchall()
        print("\nENDPOINTS:")
        for row in rows:
            print(f"  {row['classification']:10} {row['method']:7} {row['path_template']:45} {row['validation_status']:15} {row['response_status']}")
        findings = conn.execute(
            "SELECT rule_id, severity, confidence, status, risk_score, title FROM findings WHERE scan_id = ? ORDER BY risk_score DESC",
            (scan_id,),
        ).fetchall()
        print("\nFINDINGS:")
        for row in findings:
            print(f"  {row['rule_id']} {row['severity']:8} {row['confidence']:9} {row['status']:9} {row['risk_score']:6} {row['title']}")
    print("\nscan state:", (result["state"], result["partial"]))
    print("scan id for evaluation:", scan_id)
    # machine-readable summary for CI (`tail -1` gives the JSON object)
    print(
        json.dumps(
            {
                "scan_id": scan_id,
                "state": result["state"],
                "partial": result["partial"],
                "counters": result["counters"],
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
