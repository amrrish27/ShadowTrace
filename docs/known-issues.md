# Known issues, gaps and limits

Everything here is a deliberate, bounded decision — not an oversight. Each item states the
blast radius and, where it can be closed, the exact command a human should run. Items are
ranked by how much they would matter to a reviewer or an operator.

## A. Not executed in this environment (verification gaps)

| # | Gap | Why | Impact | How to close it |
|---|---|---|---|---|
| A1 | **Container images never built** | no Docker daemon in the build sandbox | The `Dockerfile`, compose file and proxy config are unverified; a syntax error would only appear on first build | `docker build -f deploy/docker/Dockerfile -t shadowtrace-runtime .` then `cd deploy && cp ../.env.example .env && docker compose up -d --build` and check `docker compose ps` for `healthy` |
| A2 | **OWASP ZAP baseline + authenticated active scan not run** | ZAP not installed, no network | Dynamic findings (headers, XSS, open redirects) rest on code review and unit tests only | `docker run --rm -t -v "$PWD/deploy/reports:/zap/wrk:rw" --network shadowtrace_backend ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://proxy/ -r zap.html` (add `-z "-config replacer.full_list(0).description=auth"` for an authenticated run) |
| A3 | **Trivy/Grype image scan not run** | needs a built image (A1) and a vulnerability database | Base-image CVEs unknown | `trivy image --severity HIGH,CRITICAL shadowtrace-runtime:latest` |
| A4 | ~~`npm audit` not run~~ **CLOSED 2026-10-26** | — | `npm audit --production` reports **0 vulnerabilities** (runtime dependencies are React + React DOM only) | — |
| A5 | ~~**Playwright journeys not executed**~~ **CLOSED 2026-10-28** | — | A real Chromium was installed here and the suite now **passes: 4 journeys, 30 s** — analyst read-path, target registration (CSRF/origin), admin (audit log → Members → invite → invitee accepts in a separate browser context → password change → sign in with the new password), and an accessibility floor over all 11 pages. Running them found and fixed four real defects (see A6 below and `docs/known-issues.md` §C). Re-run: `cd frontend && npm run build && npx playwright test` |
| A6 | **axe automated a11y scan not run** (a dependency-free floor is now enforced) | axe-core is not part of the delivered dependency set; the browser exists (A5) | The floor catches unlabelled controls, nameless buttons/links, duplicate ids, missing or duplicated H1 and heading-level skips on every page — it caught two real defects and now runs as a journey. Contrast ratios, ARIA misuse and focus order are still unreviewed by a tool | `cd frontend && npm i -D @axe-core/playwright` and assert `violations == []` per page |
| A7 | ~~ESLint not configured~~ **CLOSED 2026-10-26** | — | ESLint 9 flat config with `typescript-eslint` and `eslint-plugin-react-hooks` 5; `npm run lint` runs it after `tsc --noEmit`. 0 errors, 6 advisory `react-refresh` warnings (single-file component organisation) | — |
| A4a | **6 advisories in the dev-only toolchain** (`tinypool`, `esbuild`, `@vitest/mocker` via vitest 2) | They affect the local test runner and dev server, never the shipped bundle or the API; the fix is a vitest 4 major upgrade, which is a separate, deliberate change | `npm audit` after `cd frontend`; the production tree is clean | `npx vitest@4` migration: upgrade `vitest`, re-run `npx vitest run` and `npm run build` |
| A8 | **Hypothesis/fuzzing not installed** | not in the offline wheel set | Parser robustness is proven by explicit adversarial corpora rather than generated cases | `pip install hypothesis` and convert `test_parsers.py`'s fixtures into `@given(st.text())` properties; the size/depth caps make failures deterministic |
| A9 | **Pre-commit hooks / secret scanning absent** | the delivered archive is a source tree, not a git repository with hooks | A developer could commit a secret locally; CI would catch it only if a scanner were added | `pip install pre-commit detect-secrets && pre-commit install` with hooks for `detect-secrets`, `bandit`, `mypy` |
| A10 | **No git history to scan** | the deliverable is a zip of a working tree | "No secrets in history" cannot be asserted for the delivered artefact | `gitleaks detect --no-git --source .` on the unpacked archive (returns nothing) |

| A11 | **Only SQLite has been executed** — a hosted Postgres/Supabase deployment is not supported by this build | the data layer is `sqlite3` (`backend/app/db.py`: `PRAGMA` statements, `sqlite3.Row`, `?` placeholders in ~170 queries). A Postgres port is mechanical but not free, and there is no Postgres server in the build environment, so nothing about it could be verified | Accounts and scans are stored in a real database with a conventional schema, but **not** in Supabase. Do not point this build at one | Porting: replace the connection factory and placeholder style, convert the four migrations to Postgres DDL, then run the full suite against a real server. Treat it as a separate, testable change. **Decided 2026-10-28: keeping local SQLite auth** — [DECISION-007](DECISIONS/DECISION-007-auth-stays-in-sqlite.md) |

### A.1 Closed while preparing this revision

| Item | What changed |
|---|---|
| **26 dependency CVEs across 2 packages** (12 × `python-multipart` ≤ 0.0.20, 14 × `starlette` 0.41.3) | `python-multipart` 0.0.20 → **0.0.31**, `fastapi` 0.115.6 → **0.135.0** with `starlette` pinned to **1.3.1** — the lowest set that clears every advisory. `pip-audit -r requirements.txt` now reports **no known vulnerabilities** (2026-10-26, 27 dependencies, evidence in `docs/evidence/pip-audit.json`). The full suite passes unchanged on the new versions (430 tests). Re-run: `make security` |
| Worker could not reach scan targets | The worker was on the `internal: true` network, which has no default gateway, so no scan could ever complete. It now has its own `egress` bridge with no published ports and no attachment to the proxy; the API stays internal-only (`deploy/HARDENING.md` §6.1) |

### A.2 Closed in the round-7 independent review

| Item | What changed |
|---|---|
| **Private-network egress bypass** (an org admin could scan `127.0.0.1`/RFC1918 by declaring the ports on the target; a canary on an unlisted loopback port received 10 requests) | `validate_destination` now takes the target's declared ports as a *port* permission only; a private/loopback address needs an **operator** `ST_PRIVATE_ALLOWLIST` entry. Target creation refuses non-allow-listed private hosts in every mode (422). `backend/tests/test_egress_guard.py` (34 tests) reproduces the canary exploit and fails if the two permissions are ever merged again. Docs (README, `deploy/HARDENING.md` §5/§6.1, `docs/THREAT_MODEL.md` §3.3, C12) now describe what the code enforces |
| **README quick start omitted the worker** (scans stayed `queued`) | The quick start starts both processes (bash and CMD), says why, and DECISION-005's title/body no longer claim the scan runs in the API process |
| **An unreachable target looked like a success** (`completed`, 0 endpoints, one finding) | `ScanSummary` carries `requests_failed` and `unreachable`; the scan is `partial = 1` and logs `scan.target_unreachable` at **error** level. Verified live against `10.0.0.5`: `partial=true`, `unreachable=true`, `pages_fetched=0`, `requests_failed=1`, and the event text says the target could not be reached |
| **`POST /scans/{id}/start` 404** | Not reproducible with a valid id: while queued/running it returns 200, when finished 409, and 404 only for an id that does not exist in the caller's organization. Pinned by `test_api_scan_objects.py::test_start_accepts_a_scan_a_worker_has_already_claimed` |
| **`database is locked` between the API and the worker** (found while verifying the above) | The worker left `scan_events`/counter writes uncommitted, holding SQLite's write lock for the whole scan; a slow target made the API fail its own writes. Events and progress are now committed per write (`record_event` / `record_progress`), verified live with zero lock errors. `test_worker_loop.py` asserts the connection is never left in a transaction |
| **Login accepted a foreign `Origin`** | `POST /auth/login` now refuses a present-but-disallowed `Origin` with `403 csrf_failed` |
| **`worker.py` 65 % / `ratelimit.py` 73 % coverage** | Now 81.0 % (branch 72.0 %) and **100 %**; see B1 |

### A.3 Closed in the account-management revision (2026-10-28)

Running the UI for the first time (A5) and sweeping every page found these, all fixed here:

| Defect | Why it mattered | Fix | Guard |
|---|---|---|---|
| **Card titles were `<div>`s, not headings** | Screen readers had no section outline on any page; the browser journey could not even find "Severity mix" | `Card` renders `<h2 class="card-title">` | `ui.test.tsx`, e2e accessibility floor |
| **Empty-state titles were `<h3>`** | Pages that opened with an empty state jumped H1 → H3 | the label is a `<p class="empty-title">` | `ui.test.tsx` |
| **Overview and Members had no `<h1>`** | No page-level landmark for assistive tech | a `.page-head` on both; the admin-only refusal keeps the heading | e2e accessibility floor |
| **An administrator could not manage accounts at all** | `/users`, `/users/invite`, `/users/{id}` and `/auth/accept-invite` existed but **nothing in the UI called them** — creating a user required a terminal, and an invitation link had no page to land on | new **Members** page (list, invite, role, deactivate) and **AcceptInvite** screen; invite shows a one-time link | `Members.test.tsx`, e2e journey (invite → accept → sign in) |
| **No way to change your own password in the UI** | `/auth/change-password` was API-only | **Settings → Your account → Change password** dialog | e2e journey (change, sign out, sign in with the new password) |
| **`Dashboard.tsx` / `atoms.tsx` were dead code** | 12 of the 15 Vitest tests exercised a component the app no longer rendered, which inflated the frontend's apparent coverage | deleted; the contract/normaliser tests moved to `contract.test.ts`, new tests cover `ui.tsx` and `Members` | `npx vitest run` (15 tests, all live code) |
| **Journey asserted an admin-only page as an analyst** | The audit-log assertion could never pass — the seeded account is an analyst and the page is admin-only by design | the analyst journey now asserts the *refusal*; a seeded administrator (new `seed_demo.py --with-admin`) asserts the entry | e2e journeys |
| **Positional table indexing in the journey** | `split("\n")[2]` assumed the rule id was the third cell; adding Severity/Confidence broke it | assert the row contains a rule id | e2e journey |

### A.4 Closed in the target-authorization revision (2026-10-28)

A reviewer re-ran a proof against the previous archive and found that `PATCH /api/v1/targets/{id}`
let an **analyst repoint an admin-approved target at any host while keeping the approval**; the
next `POST /api/v1/scans` returned 201 against the new host. `targets.py` had not been changed by
any earlier round, so the hole was present in every build up to and including the one shipped
that morning.

| Defect | Why it mattered | Fix | Guard |
|---|---|---|---|
| **BUG-20: approval survived a scope change** | The product's core rule is "only approved targets are scanned". Re-pointing an approved target defeated it, and the analyst could then scan a third-party host | `PATCH /targets/{id}` compares the new origin (host, scheme, port **set**, normalised path prefixes) with the stored one and revokes the approval — status `pending`, `verified_at`/`verified_by` cleared, `target.approval_revoked` audited with both scopes. Applies to administrators too: the approval describes the origin, not the actor | `test_target_scope_change.py` (14 tests, 4 mutation controls) |
| **BUG-21: `/verify` was an approval authority** | Repointing drops the target to `pending`, but the verification token is visible in the target payload, so the analyst who repointed it could serve it on the new host and re-approve themselves — the reset would have been cosmetic | self-approval is now limited to `ownership` mode, which is the only mode whose contract is "I control this host". Verifying an `admin`/`lab_allowlist` target reports `verified` but leaves approval to an administrator (`self_approved: false`, `requires_admin_approval: true`) | `test_verification_cannot_self_approve_a_pending_admin_target`, `test_verification_still_approves_an_ownership_target` |
| `justification` was accepted by `PATCH` and silently discarded | An edit that looked saved was not | the field is persisted | covered by the update tests |
| The edit dialog reported a bare "Target updated." after dropping an approval | The next scan would fail with `409 target_not_authorized` and nothing explained why | the toast states that the security scope changed and re-approval is required | `npm run build` + manual check |

Deliberate trade-offs, so a reviewer can disagree explicitly:

* **Any** port-set change revokes, including removing a port. Narrowing is not a privilege
  escalation, but "the set of ports you may touch changed" is easier to reason about than a
  superset test, and it fails closed. Re-approval costs one click.
* Path prefixes count as scope. A form that resends the same values — including `"/app/"` for
  `"/app"` — does **not** revoke; the comparison normalises exactly as `ScopePolicy.build` does.

### A.4a Closed in the Windows-start revision (2026-10-28)

Reported from a real Windows 11 machine: `start.cmd` printed
`'...\python.exe" -c "import' is not recognized`, the worker probe failed with
`wait_healthy.py: error: --since: expected one argument`, and the API log said
`lab_start_failed ... did not become healthy within the start timeout` while running the lab by
hand worked. Three separate causes, all reproducible from the code:

| Defect | Why it mattered | Fix | Guard |
|---|---|---|---|
| **BUG-22: quoted command inside `for /f`** | `for /f ... in ('"%PY%" -c "..."')` — `cmd.exe` strips the outer quotes and tries to execute `C:\path\python.exe" -c "import` as a program name, which is the reported error. `START_EPOCH` was therefore empty, and that empty value produced the argparse failure that followed | the epoch is written with `> file` and read back with `set /p`, no `for /f`; `if not defined START_EPOCH goto :no_epoch` fails closed before the probe runs | checker rule 6 (quoted `for /f`) + rule 7 (unguarded `--since`) + 4 tests |
| **BUG-23: the lab child got a three-key environment** | `start()` passed only `PATH`, `PYTHONUNBUFFERED`, `ST_LAB_PORT`. CPython on Windows cannot initialise without `SYSTEMROOT`; the child died before binding, so `_pid()` went `None`, the wait loop broke, and the API reported a **timeout** for a process that had already exited. The same code works on Linux, which is why the lab started by hand and not under the supervisor | `_child_env()` allow-lists the variables a child needs to *start* (`SYSTEMROOT`, `SYSTEMDRIVE`, `WINDIR`, `COMSPEC`, `PATHEXT`, `TEMP`/`TMP`, `USERPROFILE`, plus the POSIX equivalents) and still passes **no** API secret — the lab is the intentionally vulnerable component | `test_the_lab_child_gets_the_windows_variables_it_needs`, `test_the_lab_child_never_receives_a_secret` |
| **BUG-24: a dead child was reported as a slow one, with no evidence** | `lab_start_failed reason=…` never included the child's stdout/stderr, so a crash at import time and a genuinely slow start were indistinguishable — the operator had nothing to act on | the exit code is checked, `last_error` distinguishes "exited (code N)" from "did not become healthy in time", the last 8 log lines go into `last_error` and the log line, and an empty log says so explicitly | `test_a_lab_that_cannot_start_reports_the_childs_own_words` (asserts the child's message reaches both the exception and `status()["last_error"]`) |
| **BUG-25: `stop.cmd` killed by window title** | `tasklist /FI "WINDOWTITLE eq ShadowTrace API*"` is not ownership: it also kills a second stack on another port and misses the process if the window was renamed. Reported symptom (2) had two manual wins and one supervised failure, which is exactly the shape of "I stopped the wrong copy" | `start.cmd` launches both services through `scripts/run_service.py`, which writes `data/<service>.pid` **before** the service runs; `scripts/service_pid.py` returns that PID only when the process is alive *and* its command line is still this launcher for that service, and `stop.cmd` quits gracefully (`taskkill /T`, 5 s) then forces. A stale or recycled PID is refused, never used | 6 tests, including a live process with a doctored pidfile (`test_a_recycled_pid_that_is_not_our_launcher_is_refused`) |

Not a code defect, and not fixed here: **the bootstrap password only exists on a database with an
empty `users` table.** Reported symptom (4) — "bootstrap skipped because users already exist, and
the password may not match" — is the documented behaviour (`README.md`, `docs/known-issues.md` A11),
not a bug. Creating a credential on an existing database is `python -m app.cli create-admin`, which
refuses a duplicate email and never deletes, resets or overwrites a row.

### A.5 Closed in the round-8 audit

| Item | What changed |
|---|---|
| **`policy_blocked` on the approved lab** (the reported failure: 0 pages, 0 endpoints, one misleading "unreachable" finding) | Root cause: `ST_PRIVATE_ALLOWLIST` is per process, so the API approved the target while the worker refused every request. Fixed with an HMAC-SHA256 **lab grant** (`lab-v1\|target\|scheme\|host\|port`) verified by the worker against its own copy of the row and its own allow-list; grants are re-derived at startup and revoked on drift. The boundary itself was not touched: metadata, other loopback ports and RFC1918 stay blocked with a grant in hand. `tests/test_lab_grants.py` (17) includes a real lab scan with an **empty** worker allow-list |
| **A refused scan looked like an assessment** | `outcome` is now `ok` / `unreachable` / `policy_blocked` / `timeout` / `cancelled` / `empty`, and `policy_blocked` equals the number of refusals in the event log (redirect refusals were logged but not counted). A blocked scan records **no** rule findings |
| **No way to run the stack reliably** | `start.cmd` (Windows) and `start.sh` (POSIX): one configuration exported to both processes, migrations first, then three readiness proofs (API health, lab health, worker heartbeat in the same database) before printing URLs; `stop.cmd`/`stop.sh` shut down gracefully. The class of error that caused the reported failure cannot survive this |
| **The UI was a single page** | Twelve real screens (Overview, Targets, Scans, Scan detail, Findings, Finding, Endpoints, Evidence, Reports, Lab, Settings, Audit) on the existing API; no placeholder buttons, no invented metrics |
| **The lab could only be run by hand** | Lab section: supervised loopback-only process with fixed argv and a scrubbed environment, start/stop/restart/reset, health, scenario catalogue, rule mapping and a one-click lab scan, all audited |
| **Coverage fell as the lab grew** | 86.7 % combined (`safe_http` 100 %, `urlguard` 99 % with no partial branches) with 632 tests; the uncovered remainder is process-control and error-mapping glue, listed in §B |

## B. Coverage and structure

| # | Item | Detail |
|---|---|---|
| B1 | `workers/worker.py` at 81.0 % (branch 72.0 %) | Raised from 65.5 % (47.9 %) by `test_worker_loop.py`, which drives the claim, heartbeat, crash recovery, `--recover`/`--scan-id`/`--once` entry points and the shared-database commit contract. What remains uncovered is the process-level infinite loop's timing branches. It holds no authorization or egress logic, so the risk is operational rather than security. |
| B2 | `main.py` at 69 % | Mostly SPA-fallback and static-file branches that only matter when `dist/` is present (it is excluded from the archive). |
| B3 | Combined branch coverage is 82.3 % | The specification asks for ≥ 85 % **line** coverage overall (achieved: 91.8 %) and ≥ 95 % **branch** coverage on security-critical modules (achieved: `safe_http` 100 %, `urlguard` 100 % of branches, `scope` 97.4 %). The lower-scope modules are API glue and worker plumbing; `security/ratelimit.py` is at 100 %. |
| B4 | Isolation vs full-suite delta | `safe_http` alone: 99 % (3 statements and 1 branch reached only by other modules' tests). `urlguard` alone: 98 % (5 statements, 0 branches missed). Full suite: `safe_http` 100 %, `urlguard` 98.6 % with every branch taken. Quoted numbers are always from the full suite. |

## C. Product limits (by design)

| # | Limit | Consequence |
|---|---|---|
| C1 | Only `GET`/`HEAD`/`OPTIONS` are ever sent | Endpoints reachable only via `POST`/`PUT` are discovered from documents but not validated; their findings stay `suspected` |
| C2 | JavaScript is parsed, never executed | URLs assembled at runtime from non-literal values are missed. Recall on the lab is measured against this model, not against a browser |
| C3 | Soft-404 detection is heuristic (size delta > 25 % **and** similarity < 0.9) | A catch-all shell that varies its body wildly over a small size could still be treated as live; it would then appear as a `documented`/`shadow` endpoint with weak evidence rather than a finding |
| C4 | One worker process, one scan at a time | Queueing is per deployment; `scan_concurrency_per_org` and `scans_per_day_per_org` bound abuse. Horizontal scale needs a broker (see ADR-005) |
| C5 | SQLite (single writer) | Fine for a single VM; concurrent writers would need Postgres (ADR-002) |
| C6 | Rate limiting is in-process | Correct for one node; a multi-node deployment needs a shared store |
| C7 | No email delivery | Invitations return a single-use link that an admin copies out of band. This avoids an SMTP dependency and a new phishing surface |
| C8 | Progress is polled, not streamed | The UI polls `/scans/{id}`; there is no SSE/WebSocket channel, so a 30-second scan shows progress at the poll interval |
| C9 | No PDF export | Six formats are supported (`json`, `csv_inventory`, `csv_findings`, `markdown`, `html`, `openapi_stub`); HTML prints to PDF in the browser |
| C10 | No scheduled or recurring scans | Each scan is created explicitly with an idempotency key |
| C11 | Uploads are capped at 8 MiB (`ST_MAX_UPLOAD_BYTES=8388608`, the code default and the documented value) | Larger HAR files or specifications must be split or loaded from a URL |
| C12 | Private and loopback targets require an **operator** allow-list entry | A target on a private/loopback/RFC1918 address is refused at creation (`422 invalid_target`) in every authorization mode unless `ST_PRIVATE_ALLOWLIST` lists that exact `host:port`. The target's own `ports` authorize ports only — they never unlock a private address — and cloud-metadata/link-local destinations can never be allow-listed. This is the intended behaviour, not a bug: it is what stops an organization admin from using the scanner as a proxy into internal services (see `docs/THREAT_MODEL.md` §3.3 and `test_egress_guard.py`) |
| C13 | Findings describe exposure indicators, not exploit proof | The wording lint enforces this; there is no exploitation engine, by design |
| C15 | `ST-022` (open redirect) is not exercised by the lab crawl | A same-origin redirect is followed, so the rule sees the final 200 and never the `Location` header; a cross-origin redirect is refused before a response exists. The rule stays in the registry and is unit-tested (`test_rules_injection.py`), but no lab endpoint claims it. A future probe that requests with redirects disabled would close this |
| C16 | `ST-001` (undocumented endpoint) needs a baseline | It compares the observed endpoint with the documented baseline. The one-click lab target has no baseline, so a lab scan reports the specific vulnerability rules instead; `make smoke` uploads a baseline and does produce `ST-001` findings |
| C14 | An unreachable target can still produce configuration findings | Findings derived from the target record rather than from a response (e.g. "cleartext HTTP") are still true when nothing was fetched. The scan is marked `partial = 1`, `counters.unreachable = true`, `counters.requests_failed > 0`, and a `scan.target_unreachable` **error** event explains that nothing was reached — so the result reads "could not look", not "looked and found it clean" |

## D. Operational notes

| # | Note |
|---|---|
| D1 | `ST_SCANNING_ENABLED=false` is the kill switch: it blocks scan creation **and** every outbound request, including target verification (`SCANNING_ENABLED` is a deprecated fallback that logs a warning). |
| D2 | The database file, WAL and SHM live next to `ST_DATABASE_PATH`; back up with `sqlite3 shadowtrace.db ".backup backup.db"`, never by copying a live file. |
| D3 | Migrations are forward-only. Rolling back a release requires restoring the previous database file. |
| D4 | Audit log and triage history are append-only by trigger; a migration cannot "fix" an audit row, only append a correction. |
| D5 | The demo account created by `make demo-seed` is an **analyst** (cannot approve targets or manage users) and is scoped to one lab target. Its password is printed once and never written to disk. |

## E. Deliberate deviations from the specification

| # | Deviation | Rationale |
|---|---|---|
| E1 | No broker/queue service (Celery/Redis) | ADR-005: the deployment target is one VM; the state machine is isolated in `services/scans.py` so a broker can be swapped in behind it |
| E2 | No headless browser during scanning | ADR-004: executing target JavaScript is a larger risk than the recall it buys |
| E3 | No container-verification in this environment | A1–A3: the sandbox has no Docker daemon; the artefacts are written and documented instead of claimed |
