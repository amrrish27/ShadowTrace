# ShadowTrace

**API shadow-endpoint discovery and security auditing — an authorized, evidence-first scanner.**

ShadowTrace crawls an API you are authorized to test, discovers endpoints from many
sources (HTML, JavaScript, source maps, OpenAPI/Swagger/Postman, robots.txt/sitemaps,
HAR imports and documentation pages), reconciles them against a documented baseline,
validates them with read-only requests, and produces evidence-backed findings with
reproduction commands and exports.

> **Authorized use only.** ShadowTrace refuses targets that are not explicitly approved:
> private address space is unreachable unless an **operator** allow-lists the exact
> `host:port` in `ST_PRIVATE_ALLOWLIST`, and every target carries a written attestation.
> A target's own declared ports authorize *ports*, never private addresses — an
> organization admin cannot widen egress by creating a target. See
> [Responsible use](#responsible-use).

---

## Headline numbers (measured, not claimed)

| Metric | Result | Evidence |
|---|---|---|
| Shadow-endpoint recall vs lab ground truth | **76.9 %** (30/39) | [`docs/evidence/scanner-evaluation.json`](docs/evidence/scanner-evaluation.json) |
| Shadow-endpoint precision | **96.8 %** (30/31) | same file, `discovery.unexpected` |
| Discovery sources contributing endpoints | **10** distinct sources | same file, `sources.breakdown` |
| Planted findings detected | **6/19** (extra rules disabled by default) | same file, `rules.details` |
| Negative controls not flagged | **5/5** | same file, `negative_controls` |
| Hostile traps handled (SSRF, redirect, bombs, loops) | **12/12** | same file, `traps` |
| Backend tests | **699 passed, 0 failed** | [`docs/evidence/junit.xml`](docs/evidence/junit.xml) |
| Coverage | **87.4 %** combined; `safe_http` 100 %, `urlguard` 99 % (0 partial branches), `scope` 97 % | [`docs/evidence/coverage.xml`](docs/evidence/coverage.xml) |
| Frontend | `tsc --noEmit` clean, ESLint **0 errors**, **15/15** Vitest tests, production build 269.6 kB (78.4 kB gzip) | `cd frontend && npm run lint && npx vitest run && npm run build` |
| API end-to-end against the real lab | **32/32** checks (lab → target → scan → worker → crawl → findings → export → audit) | `make e2e-api` |
| Static analysis | bandit: 0 findings | `make security` |
| Dependency CVEs | **0 known** in the pinned set (pip-audit, 2026-10-27) | [`docs/evidence/pip-audit.json`](docs/evidence/pip-audit.json) |
| Browser journeys | **4 Playwright journeys pass** against a real Chromium: analyst read-path, target registration + CSRF, admin (audit log → Members → invite → invitee accepts and signs in → password change), and an accessibility floor over all 11 pages | `cd frontend && npm run build && npx playwright test` |
| Outbound HTTP outside `SafeHttpClient` | **none** (`grep` gate in CI) | `.github/workflows/ci.yml` |

The evaluation is reproducible: `make smoke` then `make evaluate SCAN_ID=...` against the
bundled lab target.

---

## Production & Reliability Improvements (Working Version)

This release includes critical reliability, timeout, and resilience safeguards:
- **Threaded DNS Resolver (`ThreadPoolExecutor`)**: `SystemResolver.resolve` runs DNS lookups in bounded worker threads with a hard timeout, eliminating infinite hangs on dead resolvers and raising `BlockedDestination("dns_timeout")`.
- **External Wall-Clock Watchdog**: Enforces scan `max_seconds` + grace period from outside the scanner thread in the worker process. Stuck scanner calls can never keep a scan `running` indefinitely.
- **Unreachable Target Fast-Fail**: Probing 140+ spec paths is automatically bypassed if target seeds fail due to connection timeouts/errors, returning honest `unreachable` outcomes in seconds instead of timing out after minutes.
- **Worker Recovery Watchdog**: Periodic background recovery automatically transitions abandoned/stalled scans to `timed_out` or `failed` (even with active heartbeats) and force-cancels stuck scans within 5–10 seconds.
- **Live Phase & Progress Sync**: Scanner phase (`discover`, `normalize`, `reconcile`, `validate`, `analyze`, `done`) and request budgets update in real-time in the SQLite database and UI progress card.
- **Cascade Deletion**: Scan deletion cleanly cleans up associated endpoints, findings, and events without foreign key violations.

---

## Requirements

Python **3.13** (3.10+ works; the Dockerfile, CI and the test suite target 3.13), Node **20+**
to build the SPA, and nothing else — SQLite is in the standard library and no external
service is needed.

## Start everything with one command

From the project root.

**Windows (CMD)**

```bat
start.cmd
```

**Linux / macOS / WSL**

```bash
./start.sh
```

Both scripts do the same nine things, in this order:

1. find a Python 3.10+ interpreter (`.venv313`, then `.venv`, then `py -3.13` / `python`)
2. stop with a readable message if the backend dependencies are missing, printing the exact
   `pip install` line to run
3. build the frontend bundle once, if `frontend/dist/index.html` does not exist yet —
   running `npm ci` first when `frontend/node_modules` is absent (the archive ships no
   dependencies, so a fresh copy needs that one download)
4. create `data/` and `logs/`, then apply migrations to **one** SQLite file before either
   process opens it
5. export **one** environment block that both children inherit — same database path, same
   allow-list, same kill switch
6. start the API (which also starts the bundled lab through `ST_LAB_AUTOSTART=true`)
7. start the worker
8. wait until the API answers `/api/v1/health`, the lab answers `/healthz`, *and* the worker
   has written a heartbeat into that same database — three independent proofs, not a sleep
9. print the URLs and credentials, or print the reason plus the tail of the log that
   explains the failure and stop what it already started

| URL | What it is |
|---|---|
| <http://127.0.0.1:8000/> | the UI and the JSON API (one origin, so no CORS in the loop) |
| <http://127.0.0.1:8099/> | the bundled training lab (ShadowLab) |
| <http://127.0.0.1:8000/api/docs> | the OpenAPI UI (development/test only) |

> **Where accounts live:** the local SQLite database, not Supabase or any hosted service.
> Passwords are argon2id hashes (never stored in readable form) and there is no integration to
> point elsewhere — see [DECISION-007](docs/DECISIONS/DECISION-007-auth-stays-in-sqlite.md).

First sign-in on a **fresh** database is `admin@example.test` / `Bootstrap-Admin-Pass-9!`.
Bootstrap only runs while the user table is empty: on a database that already has users the
password above is not applied and does not necessarily work. Change the bootstrap password
after the first login, or set your own `ST_BOOTSTRAP_ADMIN_*` values before the first start
and delete them afterwards. To add an administrator to a database that already has users, use
`create-admin` (see *Commands*).

Logs: `logs\api.log`, `logs\worker.log`. Stop: `stop.cmd` / `./stop.sh`, or Ctrl+C in each
window. Both scripts ask the process to stop first — uvicorn then runs its shutdown hook,
which stops the lab child and lets the worker finish the scan it is on — and only force-kill
after five seconds.

`stop.cmd` stops **the processes this stack started**, and nothing else. `start.cmd` launches
each service through `scripts/run_service.py`, which records its PID in `data\api.pid` /
`data\worker.pid`; `stop.cmd` asks `scripts/service_pid.py` for that PID, which answers only
when the process is alive *and* its command line is still that launcher for that service. A
stale pidfile (after a reboot, a recycled PID, or a process killed outright) is reported and
left alone, and a second stack on another port is never touched. `stop.sh` behaves the same
way on POSIX.

### What the start script exports

| Variable | Value | Why it matters |
|---|---|---|
| `ST_ENV` | `development` | production refuses the development secret; this is a local stack |
| `ST_DATABASE_PATH` | `<root>\data\shadowtrace.db` | the API **and** the worker must open the *same* file |
| `ST_PRIVATE_ALLOWLIST` | `127.0.0.1:8099` | the only private destination that becomes reachable; exact `host:port` |
| `ST_LAB_ENABLED` / `ST_LAB_PORT` / `ST_LAB_AUTOSTART` | `true` / `8099` / `true` | the lab is loopback-only and refused in production |
| `ST_SCANNING_ENABLED` | `true` | the kill switch; `false` blocks scan creation *and* every request |
| `ST_COOKIE_SECURE` | `false` | local http only — production forces `true` |
| `ST_SECRET_KEY` | generated once into `data\secret.key` | signs lab grants; per-installation, not a published constant. Production refuses the old published literal |
| `ST_BOOTSTRAP_ADMIN_*` | local admin | first-run only, skipped once any user exists |

Stop the stack before editing these; a `set` in another window does not reach a running
process.

### First run, in the browser

1. Sign in, open **Targets**, then either register a target or press **Run scan** on the lab
   target the Lab page created.
2. Watch the scan move through `queued → running → completed` on **Scans** (phase, request
   and endpoint counters update while it runs).
3. Open the scan for findings, endpoints, the event timeline, the comparison tab and the six
   exports; **Evidence** shows the same persisted, redacted record the finding page shows.
4. **Lab** starts/stops/restarts/resets ShadowLab, lists the 15 scenarios and the rule each
   one is expected to trigger, and queues a scan that reaches them.
5. **Members** (administrators) is where accounts live: invite a teammate, change a role,
   deactivate an account. The invitee opens the one-time link, chooses their own password and
   is signed in — no terminal, and no password ever travels through an administrator. You can
   change your own password under **Settings → Your account**.

### Manual start (what the script automates)

```bash
# once
python3 -m venv .venv313 && .venv313/bin/pip install -r requirements.txt
cd frontend && npm ci && npm run build && cd ..

# every start: one shared database, one allow-list entry, two processes
export ST_ENV=development ST_DATABASE_PATH="$PWD/data/shadowtrace.db" \
       ST_PRIVATE_ALLOWLIST=127.0.0.1:8099 ST_LAB_ENABLED=true ST_LAB_AUTOSTART=true
(.venv313/bin/python -m uvicorn app.main:app --app-dir backend --port 8000) &
(cd backend && ../.venv313/bin/python -m app.workers.worker) &
```

The Windows equivalent is `start.cmd` itself (one `set` per line); if you prefer typing it
by hand, copy the `set` block out of that file. The classic mistake is starting the worker
with a different `ST_DATABASE_PATH` or without the allow-list entry: the first makes scans
stay `queued`, the second produced the `policy_blocked` scans of round 8 (see the report and
`backend/app/security/labgrant.py`).

## Accounts without a terminal

Every account operation an operator needs is in the UI. The CLI still exists — it is the
recovery path when nobody can sign in — but it is not part of normal use.

| Task | Where | What the server does |
|---|---|---|
| Create the first administrator | automatic on first start (`start.cmd` / `start.sh` print the credential once) | `system.bootstrap_admin`, only while the users table is empty |
| Add a teammate | **Members → Invite member** | creates a single-use invitation (7 days, only the hash is stored) and writes `user.invited` |
| Set their own password | the invite link (`#/accept-invite?token=…`) | creates the account with the invited role, marks the invitation accepted, writes `auth.invitation_accepted`, signs them in |
| Change a role / disable an account | **Members** | `user.role_changed` / `user.updated`; a role change revokes that user's sessions; the last active administrator cannot be removed |
| Change your own password | **Settings → Your account → Change password** | policy-checked, re-hashed, every *other* session revoked, `auth.password_changed` |
| Recover a locked-out account | `python -m app.cli reset-password` (see below) | offline only, `system.admin_password_reset` |

**Passwords are never stored, and cannot be read back — by anyone.** The database holds a
salted hash (see `backend/app/security/passwords.py`); an administrator never sees or sets
another person's password. There is no "show password" feature to add, and a support process
that needs one is a support process that should use `reset-password`.

**Where the data lives.** One SQLite file, `<project>/data/shadowtrace.db` by default
(`ST_DATABASE_PATH`). It is a real database with the same tables a hosted Postgres would have:
`users` (email, role, `password_hash`, `is_active`, `last_login_at`), `sessions`,
`invitations`, `organizations`, the scan tables and an append-only `audit_log`. It is not
Supabase, and this build has only been executed against SQLite — see
`docs/known-issues.md` A11 before you plan to host it elsewhere.

## Administration CLI

Run every command **from `backend/`**. There is no packaging metadata in this project (no
`pyproject.toml`, no `setup.py`), so `app` is only importable from that directory — from the
repository root you get `ModuleNotFoundError: No module named 'app'`. That is expected Python
`-m` behaviour, not a broken archive, and the command fails before it opens the database.

```bat
cd path\to\shadowtrace\backend
.venv313\Scripts\python.exe -m app.cli --help
```

| Command | What it does |
|---|---|
| `init` | apply the SQL migrations (idempotent; `start.cmd` runs it every time) |
| `create-admin --email X [--name N] [--org O]` | create an **additional** administrator on an existing database. Refuses an email that already exists; never deletes, resets or overwrites a row. Takes the password from `--password`, then `ST_ADMIN_PASSWORD`, then an interactive prompt — prefer the environment variable so it stays out of the shell history: `$env:ST_ADMIN_PASSWORD = '…'; py -3.13 -m app.cli create-admin --email you@example.test; Remove-Item Env:ST_ADMIN_PASSWORD` |
| `reset-password --email X [--allow-production]` | **offline recovery**: validates the new password against the policy, revokes every session of that user, and writes a `system.admin_password_reset` audit row. Prompts for the password, or read `ST_ADMIN_PASSWORD` / `--password` |
| `recover` | mark scans whose worker lease expired as failed, then exit |
| `run-scan --scan-id ID` | execute one queued scan in this process |

Every command accepts `--database FILE`. Without it the CLI uses `ST_DATABASE_PATH`
when it is set, otherwise `<project>/data/shadowtrace.db` if that file exists (the
local `start.cmd`/`start.sh` stack), otherwise the `config.py` default. It prints the
database it touched, so a recovery against the wrong file is visible immediately.

`ST_ADMIN_PASSWORD` is a CLI-only variable (never read by the API), which is why it is not in
`.env.example` — that file mirrors `config.py` exactly and is consumed by `deploy/compose.yaml`.

Recovery, step by step, if nobody can sign in:

```bat
cd backend
.venv313\Scripts\python.exe -m app.cli reset-password --email admin@example.test
REM  type the new password twice; every session is revoked; the audit log records it
REM  it uses ..\data\shadowtrace.db automatically; add --database PATH for another file
```

The database is chosen explicitly, because `config.py` defaults to `/data/shadowtrace.db`
(the container path): run from a checkout that is either unwritable or — on Windows — a
*different, empty* file. A reset against the wrong file reports
`no user with that email (database: <path>)`, which names the file it searched.

`reset-password` is deliberately **not** exposed over HTTP: a network-reachable reset is an
account-takeover primitive. It needs filesystem access to the database, which is already total
control of the deployment, and production additionally requires `--allow-production`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[fail] API did not become healthy` + log tail | port 8000 already in use, or a migration error | `set API_PORT=8088` then `start.cmd`, or read `logs\api.log`; the tail is printed for you |
| UI loads but every call fails `403` | opened at a host that is not in `ST_ALLOWED_HOSTS`/`ST_CORS_ORIGINS` | use the printed URL, or add the host to both variables |
| Scan stays `queued` for ever | no worker, or the worker points at another database | `stop.cmd` then `start.cmd`; Settings → Workers shows live heartbeats |
| Scan completes with `outcome=policy_blocked`, 0 pages | target is private/loopback and `ST_PRIVATE_ALLOWLIST` lacks that exact `host:port` in **both** processes | add `host:port` to the allow-list, restart both, or use the lab target |
| Scan `unreachable` | DNS/connection/timeout — the summary says which, and the event log has the URL | check the target is up; a firewall on a lab port is the usual cause |
| `reset-password` says *no user with that email (database: …)* | the command opened the wrong database file — compare the printed path with the one `start.cmd` printed | `--database C:\path\to\data\shadowtrace.db`, or set `ST_DATABASE_PATH` |
| `database is locked` | two stacks pointed at one file, or an editor holding a write transaction | stop one stack; the worker and API commit per write, so this needs a third writer |
| Lab page says *disabled* | `ST_ENV=production` (the lab is refused outright) or `ST_LAB_ENABLED=false` | run the local stack, or set `ST_LAB_ENABLED=true` outside production |
| Login returns `429` | rate limiter: 10 attempts per account / 20 per IP in 5 minutes (`security/ratelimit.py`). A refusal is now audited as `auth.login_rate_limited` | wait five minutes, or restart the API (the limiter is in-memory) |
| **Sign-in with the documented password fails** | four different causes, four different messages — see the table below | — |
| `ModuleNotFoundError: No module named 'app'` | the CLI was run from the repository root | `cd backend` first (see [Administration CLI](#administration-cli)) |
| `start.cmd`: `'…python.exe" -c "import' is not recognized`, then `--since: expected one argument` | a quoted command inside `for /f` is mangled by `cmd.exe`, so the start timestamp came through empty. Fixed in 1.0.0; `scripts/check_windows_scripts.py` now rejects both the construct and any unguarded `--since %VAR%` | update to this build; `python scripts/check_windows_scripts.py` must print *ok* |
| `api.log`: `lab_start_failed … did not become healthy within the start timeout`, but running `lab.py` by hand works | the supervised child was given a three-key environment and CPython on Windows needs `SYSTEMROOT` to start, so it died and the supervisor reported a timeout. The message now names the exit code and quotes the child's own output | read `last_error` on the Lab page or the `child_output=` field in `api.log`; it now says *why* |
| the bootstrap password does not work and `start.cmd` did not print one | `users` is not empty, so bootstrap was skipped — by design on an existing database | `python -m app.cli create-admin --email …` (see *Commands*) |
| `start.cmd` says *ready* but nothing works / the wrong database is served | an older API still holds the port; readiness now requires `application_started` in this run's log, so this fails loudly instead of lying | `stop.cmd`, check `netstat -ano \| findstr :8000`, retry |

### Sign-in failures, by the message the page shows

| Message | HTTP | Real cause |
|---|---|---|
| `Email or password is incorrect.` | 401 | the stored Argon2id hash and the typed password differ. The audit log has `auth.login_failed` for it. Either the password is not the one that was applied (bootstrap ran with a different value) or the account you are typing belongs to another database — check `startup_config database=…` in `logs\api.log` |
| `Too many attempts. Please retry later.` | 429 | the rate limiter, not the password. Wait for the window; `auth.login_rate_limited` rows explain it |
| `The request could not be verified.` | 403 | the page's `Origin` is not this deployment's origin. Open the URL `start.cmd` printed |
| `The submitted data is invalid.` | 422 | the email failed the server-side pattern (`api/schemas.py`) |
| `Sign-in failed. Check the API is running.` | — | `fetch()` itself failed: wrong host/port, or the API is down |

`scripts/diagnose_login.py` (read-only, opens the file with `mode=ro` and prints no secrets)
answers the 401 case definitively: which password the stored hash belongs to, whether
bootstrap ran, and how many `auth.login_failed` rows exist. See the audit report for its usage.

Bootstrap runs **once**, while the users table is empty — re-running `start.cmd` with a
different password does not change an existing account. Use `reset-password` for that.

`start.cmd`/`start.sh` exit non-zero when the **API** or the **worker** check fails, so a
shortcut or a CI step can depend on them. The **lab** check prints a warning and does not fail
the start — the lab is a demo fixture, and the API now keeps serving without it (the same
policy `services/lab.py` and the Lab page implement). Each probe is process-scoped: the API
must have written `application_started` to *this run's* log, and the worker must have
heartbeated since this run began, so a stale process holding a port cannot make a broken
start look healthy.

---

## What it does

1. **Discover** — a bounded, polite crawler (page/script/source-map/spec caps, per-host
   rate limit, cancellation checks) plus extractors for:
   HTML links/forms/scripts · JavaScript (tree-sitter AST + bounded regex fallback) ·
   source maps · OpenAPI/Swagger UI/Postman · robots.txt + sitemaps · documentation pages ·
   HAR imports · CSP `connect-src`, `Link` and `Allow` response headers.
2. **Normalize** — paths and queries collapse to stable templates
   (`/api/v1/users/42` → `/api/v1/users/{param}`) with a fingerprint used everywhere.
3. **Reconcile** — each endpoint is `documented` or `shadow` against the baseline, and
   baseline operations that vanish become `zombie` entries. Legacy version mirrors are
   flagged (ST-015).
4. **Validate safely** — only `GET`, `HEAD` and `OPTIONS` are ever sent; soft-404
   catch-alls are fingerprinted so an SPA shell is never reported as a live API; a circuit
   breaker stops after five consecutive errors.
5. **Analyze** — 17 rules over status, headers and body, each with severity, confidence,
   an explicit *confirmed* vs *suspected* status, limitations, remediation, references and a
   risk score: `ST-001`–`ST-008`, `ST-010`, `ST-011`, `ST-013`–`ST-023` (shadow endpoints,
   bypass, debug routes, exposed specs, GraphQL introspection, CORS, risky methods, verbose
   errors, source maps, secrets in bundles, pagination/versioning drift, cleartext HTTP,
   cookie flags, SQL-error leakage, path traversal, IDOR, missing auth, weak validation).
6. **Report** — JSON, Markdown, HTML, two CSVs and an OpenAPI stub, all generated from
   stored data (nothing is re-fetched from the target at export time).

### Discovery sources measured on the lab

| Source | Endpoints contributed |
|---|---|
| openapi | 11 |
| javascript | 7 |
| html | 5 |
| har | 3 |
| postman | 3 |
| docs | 2 |
| source_map | 2 |
| graphql / redoc / sitemap / swagger_ui | 1 each |

---

## Safety model (why this is not an attack tool)

- **Single egress point.** Every outbound request goes through `SafeHttpClient`
  (`backend/app/engine/safe_http.py`). A CI gate greps the app for `requests`, `httpx`,
  `urllib.request`, `aiohttp`, `urlopen`, raw `socket.create_connection` and fails if any
  appears elsewhere.
- **SSRF defence in depth.** Scheme allow-list, userinfo/backslash/control-character
  rejection, non-canonical IPv4 rejection (decimal, hex, octal, short forms), IDNA
  normalisation, explicit blocklists for loopback/RFC1918/CGNAT/link-local/metadata/
  IPv4-mapped/NAT64/6to4/Teredo, DNS re-validation on every hop, and IP pinning so a
  rebinding answer cannot change the socket destination after validation.
- **CSRF uses the origin the request was addressed to.** Mutations need the session's
  CSRF token *and* an `Origin` that is either configured (`ST_CORS_ORIGINS`/`ST_BASE_URL`)
  or the request's own origin; `null`, malformed and foreign origins are refused. Opening
  the app at any host in `ST_ALLOWED_HOSTS` therefore works, without loosening CORS.
- **The client address cannot be chosen by the client.** nginx overwrites
  `X-Forwarded-For` with `$remote_addr` (never appends), and the API believes the header
  only from a configured proxy *and* walks it from the right, skipping trusted hops, with
  every entry validated as an IP literal — so a spoofed header cannot pick its own
  rate-limit bucket or forge an audit address.
- **Redirects** are followed only same-origin and in-scope; redirects to metadata
  addresses, other origins or an HTTPS→HTTP downgrade are blocked and recorded.
- **Bounded everything**: request/page/script/spec budgets, wall-clock deadline, response
  size cap, header count/size cap, decompression bomb cap, YAML alias cap, JSON/XML depth
  caps, XML DTD/entity refusal.
- **Read-only by construction**: no `POST`/`PUT`/`PATCH`/`DELETE` is ever sent by the
  scanner; declared risky methods are reported as observations, never exercised.
- **No target code is executed.** JavaScript is parsed as data by tree-sitter; the regex
  fallback is linear-time (no nested quantifiers). No headless browser is used.
- **Authorization is a record, not a checkbox**: target + attestation + approval +
  verification token, all audited.
- **An approval is bound to the origin that was reviewed.** Changing a target's host,
  scheme, port set or path prefixes through `PATCH /targets/{id}` revokes the approval,
  clears the verification stamp and writes `target.approval_revoked`; the target drops to
  `pending` and every scan is refused until an administrator approves it again. (A
  `lab_allowlist` target is the only exception — that mode is re-checked against
  `ST_PRIVATE_ALLOWLIST` on every edit, so the operator allow-list is the control.) The
  ownership challenge may only *self*-approve `ownership`-mode targets, so the account that
  repointed a target cannot approve the result. `backend/tests/test_target_scope_change.py`.
- **The lab is authorized explicitly, not by weakening the boundary.** A local lab target is
  the one place a loopback address may be scanned, and that permission is a signed grant
  (`lab-v1|<target>|<scheme>|<host>|<port>`, HMAC-SHA256 with the deployment secret) stored on
  the target row. The worker verifies the grant against *its own* copy of the row and its own
  allow-list, so a grant cannot be replayed for another host or port. Editing the target,
  moving it, or removing the allow-list entry revokes it at the next start (`sync_grants`).
  `169.254.169.254`, other loopback ports and every RFC1918 destination stay blocked
  (`backend/tests/test_lab_grants.py`) — the round-8 `policy_blocked` failure was a
  per-process allow-list mismatch, fixed at that layer, not by opening the guard.

---

## Architecture

```
backend/app
├── api/          FastAPI routers (one module per resource) + ROUTE_POLICY
├── services/     scan lifecycle, quotas, reports, lab supervisor
├── engine/       crawler · extractors/ · normalizer · reconciler · validator
│                 rules · scan_rules · risk · evidence · persistence · scanner
│                 safe_http · urlguard · scope · parsers
├── security/     auth · passwords · tokens · redaction · audit · ratelimit
│                 middleware · labgrant (HMAC lab authorization)
├── workers/      worker loop: claim → heartbeat → execute → recover
└── migrations/   0001_init · 0002_har · 0003_scan_endpoint_status
                  0004_lab_grants_worker_health
frontend/src      React + TypeScript UI: App shell, ui.tsx primitives, lib/router,
                  pages/{Overview,Targets,Scans,ScanDetail,Findings,FindingDetail,
                  Endpoints,Evidence,Reports,Lab,Settings,Audit}
lab/              ShadowLab (15 vulnerable scenarios) + ground truth + HAR fixture
deploy/           Dockerfile, compose, TLS proxy config, HARDENING.md
docs/             ARCHITECTURE · THREAT_MODEL · SECURITY_REQUIREMENTS · TESTING
                  gates/ · DECISIONS/ · evidence/ · known-issues.md · self-evaluation
scripts/          smoke_scan · evaluate · seed_demo · e2e_round8 · wait_healthy
                  run_service (records a service PID) · service_pid (verifies it before use)
                  check_windows_scripts (static rules for start.cmd/stop.cmd)
start.cmd/start.sh, stop.cmd/stop.sh   one-command local stack (Windows / POSIX)
```

Engine modules are pure libraries: they take a client/clock/resolver, return dataclasses,
and are unit-tested without the API. The API and worker only orchestrate them.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the request lifecycle, state machine
and data model, and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the STRIDE analysis.

---

## Running everything

| Command | What it does |
|---|---|
| `make help` | list every target |
| `start.cmd` / `./start.sh` | the whole local stack (API + worker + lab) with readiness checks |
| `stop.cmd` / `./stop.sh` | graceful shutdown of that stack |
| `make test` | backend suite (with coverage) + frontend unit tests |
| `make e2e-api` | the full lab workflow through the real API and worker (32 checks, temp DB) |
| `make coverage` | coverage with `docs/evidence/coverage.xml` |
| `make lint` / `make typecheck` | ruff + `tsc --noEmit` + ESLint (react-hooks) / mypy |
| `make security` | bandit + pip-audit |
| `make verify` | everything that runs offline (CI gate) |
| `make lab` | start ShadowLab on port 8099 |
| `make smoke` / `make evaluate SCAN_ID=…` | real scan + ground-truth scoring |
| `make demo-seed` | least-privilege demo account |
| `make e2e` | build the SPA and run the Playwright journeys (needs `npm run e2e:install` once) |
| `make zip` | build the deliverable archive (source only — no `dist/`, no coverage data) |

Backend tests: `cd backend && ST_ENV=test python3 -m pytest tests -q`
Frontend: `cd frontend && npm ci && npm run build && npx vitest run`

---

## Deployment

`deploy/` contains a production-style composition: an nginx TLS proxy in front of the API,
a separate worker process, a read-only static frontend and a persistent volume for SQLite.
Read [deploy/HARDENING.md](deploy/HARDENING.md) before exposing it — it lists the exact
fail-closed settings, the headers, the CSP and the backup procedure.

Checklist: set every `CHANGE-ME` in `.env.example`, keep `ST_COOKIE_SECURE=true`, leave
`ST_PRIVATE_ALLOWLIST` empty (except for a lab), set `ST_TRUSTED_PROXIES` to the proxy's
address (the compose file pins nginx to `172.30.0.2`), terminate TLS at the proxy, run one
worker, and remove the bootstrap-admin variables after the first sign-in.

Networks: `api` and `proxy` share an `internal: true` network with no route out; the
`worker` alone sits on an `egress` bridge because it is the component that must reach scan
targets. Container networking is not the bound on that egress — `SafeHttpClient` is, so
add host-firewall rules for the destinations you actually scan (`deploy/HARDENING.md` §6.1).

Every setting is documented in `.env.example`, which mirrors `backend/app/config.py`;
`backend/tests/test_env_example.py` fails if the two ever disagree. Note that `.env.example` is
a **template for `deploy/compose.yaml`** (`env_file: ../.env`): the application itself never
reads a `.env` file, and `start.cmd`/`start.sh` set the variables directly in the environment
they hand to both child processes.

---

## Limitations and non-goals

Read [docs/known-issues.md](docs/known-issues.md) for the full list with justification.
The short version:

- **No exploitation.** Findings state exposure; nothing is proven exploitable. Wording lint
  enforces this in code.
- **No authentication testing.** The scanner does not hold or replay credentials.
- **No Browser rendering.** SPAs that build routes only at runtime may be under-discovered;
  the crawler compensates with source maps and bundles but does not execute JavaScript.
- **No distributed queue.** SQLite + one worker; the limiter and queue are single-process.
- **Progress is polled, not streamed.** The scan page polls every few seconds; there is no
  SSE/WebSocket channel, so a fast scan can jump straight from `queued` to `completed`.
- **No PDF export.** Six formats (`json`, `markdown`, `html`, `csv_findings`,
  `csv_inventory`, `openapi_stub`) are generated from persisted data; the HTML report prints
  to PDF in the browser, which is more reliable than a PDF library that would have to embed
  its own fonts.
- **A parameterised endpoint can validate as `not_found`.** `GET /lab/api/idor/account/1001`
  needs a real identifier, so a replay with a synthesised path returns 404; discovery and the
  finding are unaffected because the crawl sample is reconciled against the recorded path.
- **Browser journeys and container images are not executed here** (no browser, no Docker in
  this environment) — the exact commands are in `deploy/HARDENING.md`,
  `frontend/e2e/journey.spec.ts` and [docs/known-issues.md](docs/known-issues.md).

## Responsible use

ShadowTrace is for systems you own or have **written permission** to test. The API requires
an attestation on every target, enforces operator approval, and audits every scan. Private and
loopback destinations are refused at target creation unless an operator has allow-listed that
exact `host:port`; declaring ports on a target never unlocks a private address, so an
organization admin cannot turn the scanner into a proxy for internal services. Do not use it
to scan third-party infrastructure.

## Documentation index

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | layers, data model, scan lifecycle, engine flow |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | assets, actors, STRIDE per component, abuse cases → controls → tests |
| [docs/SECURITY_REQUIREMENTS.md](docs/SECURITY_REQUIREMENTS.md) | numbered requirements (AUTH/SSRF/INP/RED/…) with implementation + test links |
| [docs/TESTING.md](docs/TESTING.md) | test layers, how to run them, what is covered and what is not |
| [docs/evidence/](docs/evidence/) | scanner evaluation, coverage, JUnit, self-evaluation |
| [docs/gates/](docs/gates/) | phase gate records GATE-0 … GATE-9 |
| [docs/DECISIONS/](docs/DECISIONS/) | architecture decision records |
| [docs/known-issues.md](docs/known-issues.md) | every unmet MUST, with justification |
| [SECURITY.md](SECURITY.md) | disclosure process |
