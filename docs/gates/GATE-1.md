# GATE-1 — Secure foundation

**Criteria:** `make verify` and CI are green; the authorization matrix is generated from the
routes; cookie and header checks pass; no secrets in history.

**Verification performed**

| Criterion | Command / artefact | Result |
|---|---|---|
| Offline suite green | `make verify` | PASS — egress gate, mypy, bandit, pip-audit and 346 tests |
| Authorization matrix generated from the routes | `test_api_authz.py::test_every_route_has_a_policy_entry` walks `app.routes` and asserts a `ROUTE_POLICY` entry per route | PASS — 41 routes, 39 pattern entries + 2 static, 0 ungoverned |
| Role matrix exercised | `test_role_matrix_enforcement[anonymous/viewer/analyst/admin]` | PASS |
| Cookie hardening | `test_auth_flow.py::test_login_sets_hardened_cookies` (HttpOnly, SameSite=strict, Path=/, Secure in prod) | PASS |
| CSRF | `test_csrf_header_is_required_for_state_changes` | PASS |
| Security headers + request id | `test_security_headers_and_request_id` | PASS |
| Fail-closed production config | `test_config.py` (14 tests) | PASS |
| Audit log append-only | triggers in `migrations/0001_init.sql`; asserted in lifecycle tests | PASS |
| No secrets in history | `git log` — this project was packaged as a source tree; the scan is documented in `docs/known-issues.md` with the command | NOT RUN (no git history in the delivered tree) |
| Docker/compose skeleton | `deploy/docker/Dockerfile`, `deploy/compose.yaml` | WRITTEN, NOT BUILT (no Docker daemon) |
| Pre-commit with secret scanning | not added — `make security` + CI cover SAST and dependency audit | GAP, documented |

**Result: PASS** for everything executable here; two rows are explicitly not executed and
carry exact human commands in `docs/known-issues.md`.
