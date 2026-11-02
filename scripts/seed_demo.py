"""Create the least-privilege demo account and the lab target.

The demo user is an **analyst** (never an admin), scoped to one organization, and
the only target is the loopback lab. The password is generated per run, printed
once to stdout and never written to the repository — hand it to the human out of
band, as the spec requires.

Usage:
    ST_ENV=test ST_DATABASE_PATH=/tmp/shadowtrace-demo.db \
        ST_PRIVATE_ALLOWLIST=127.0.0.1:8099 python3 scripts/seed_demo.py

    # with one completed scan, for the Playwright journey (needs the lab on :8099):
    python3 scripts/seed_demo.py --password '...' --with-scan
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.db import db, init_db, new_id, now  # noqa: E402
from app.security.passwords import generate_password, hash_password, validate_password  # noqa: E402
from app.security.tokens import verification_token  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--email", default="demo@shadowtrace.local")
    parser.add_argument("--base-url", default="http://127.0.0.1:8099")
    parser.add_argument("--org", default="ShadowTrace Demo")
    parser.add_argument(
        "--password",
        default=os.environ.get("ST_DEMO_PASSWORD", ""),
        help="use this password instead of generating one (test harnesses only)",
    )
    parser.add_argument(
        "--with-scan",
        action="store_true",
        help="also import the lab baseline/HAR and run one real scan against the lab",
    )
    parser.add_argument(
        "--with-admin",
        action="store_true",
        help="also create an administrator in the same organization (drives the admin-only UI)",
    )
    parser.add_argument("--admin-email", default="admin@shadowtrace.local")
    parser.add_argument(
        "--admin-password",
        default=os.environ.get("ST_DEMO_ADMIN_PASSWORD", ""),
        help="use this password instead of generating one (test harnesses only)",
    )
    args = parser.parse_args()

    port = int(args.base_url.rsplit(":", 1)[-1].split("/")[0]) if ":" in args.base_url else 80
    allowlist = os.environ.get("ST_PRIVATE_ALLOWLIST", "")
    if f"127.0.0.1:{port}" not in allowlist:
        print(
            "refusing to seed: the lab port is not in ST_PRIVATE_ALLOWLIST "
            f"(expected 127.0.0.1:{port}). Export it first.",
            file=sys.stderr,
        )
        return 2

    password = args.password or generate_password(24)
    validate_password(password, email=args.email)
    init_db()
    with db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email = ?", (args.email,)).fetchone()
        if existing is not None:
            print(f"user {args.email} already exists; nothing to do", file=sys.stderr)
            return 1
        org_id = new_id()
        user_id = new_id()
        target_id = new_id()
        timestamp = now()
        conn.execute("INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)", (org_id, args.org, timestamp))
        conn.execute(
            """
            INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
            VALUES (?, ?, ?, 'Demo Analyst', 'analyst', ?, 1, ?)
            """,
            (user_id, org_id, args.email, hash_password(password), timestamp),
        )
        conn.execute(
            """
            INSERT INTO targets (id, org_id, name, base_url, host, scheme, ports, path_prefixes,
                                 authorization_mode, authorization_status, attestation, justification,
                                 verification_token, verified_at, verified_by, created_by, created_at, limits)
            VALUES (?, ?, 'ShadowLab', ?, '127.0.0.1', 'http', ?, '[]', 'lab_allowlist', 'approved',
                    'Operator-owned lab target, synthetic data only.', 'Demo deployment',
                    ?, ?, ?, ?, ?, ?)
            """,
            (
                target_id,
                org_id,
                args.base_url.rstrip("/"),
                json.dumps([port]),
                verification_token(),
                timestamp,
                user_id,
                user_id,
                timestamp,
                json.dumps({"max_requests": 300, "max_pages": 12, "max_seconds": 300}),
            ),
        )
        conn.execute(
            """
            INSERT INTO audit_log (org_id, ts, actor_type, action, object_type, object_id, details)
            VALUES (?, ?, 'system', 'system.demo_seeded', 'target', ?, ?)
            """,
            (org_id, timestamp, target_id, json.dumps({"email": args.email, "role": "analyst"})),
        )
        if args.with_admin:
            admin_password = args.admin_password or generate_password(24)
            admin_id = new_id()
            validate_password(admin_password, email=args.admin_email)
            conn.execute(
                """
                INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at)
                VALUES (?, ?, ?, 'Demo Administrator', 'admin', ?, 1, ?)
                """,
                (admin_id, org_id, args.admin_email, hash_password(admin_password), timestamp),
            )
            conn.execute(
                """
                INSERT INTO audit_log (org_id, ts, actor_type, action, object_type, object_id, details)
                VALUES (?, ?, 'system', 'system.demo_admin_seeded', 'user', ?, ?)
                """,
                (org_id, timestamp, str(admin_id), json.dumps({"email": args.admin_email, "role": "admin"})),
            )
    if args.with_scan:
        from smoke_scan import run_lab_scan

        result = run_lab_scan(base_url=args.base_url)
        print(f"  scan:     {result['scan_id']} ({result['state']})")
    print("ShadowTrace demo account created (password shown once, never stored in the repo):")
    print(f"  email:    {args.email}")
    print(f"  password: {password}" if not args.password else "  password: supplied with --password")
    print("  role:     analyst (member management and target approval are admin-only)")
    if args.with_admin:
        print("  admin:    " + args.admin_email + (" (password supplied with --admin-password)"
              if args.admin_password else f" / {admin_password}"))
    print(f"  target:   {args.base_url} (lab_allowlist, approved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
