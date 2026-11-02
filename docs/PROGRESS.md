# Progress and build record

Chronological record of what was built, what broke, and what remains. It is the honest
version: every phase lists what was verified, how, and what was **not** verified.

Legend: ✅ done and verified locally · ⚠️ done with a documented limitation · ⛔ not
possible in this environment (human step documented).

## Phase summary

| Phase | Outcome | Evidence |
|---|---|---|
| 0 — environment survey | ✅ Python 3.13, Node 20 available; no Docker, no ZAP, no Trivy, no Playwright browsers, no ESLint *(superseded in revision 4: Chromium and ESLint were installed and both gates now run — see "Revision 4" below)* | this file |
| 1 — skeleton, DB, migrations | ✅ FastAPI app, SQLite schema (0001–0003), RBAC, sessions, audit log | `migrations/`, `test_api_authz.py` |
| 2 — egress engine | ✅ `urlguard` + `safe_http` with pinning, caps, redirects, budget, kill switch | 96 % / 95 % coverage |
| 3 — discovery engine | ✅ crawler + 11 extractor families, scope policy, validator | recall 1.0 / precision 1.0 |
| 4 — reconciliation and rules | ✅ fingerprinting, shadow/documented/zombie, 16 rules, risk scoring, evidence | `rules` 16/16, negatives 5/5 |
| 5 — API surface | ✅ 41 routes, `ROUTE_POLICY` covering every route, 6 export formats | `test_api_authz.py`, `test_api_scan_objects.py` |
| 6 — worker and lifecycle | ⚠️ full state machine, cancel, recovery, quotas; single-process poller | `test_lifecycle_service.py`, `test_scan_integration.py` |
| 7 — frontend | ⚠️ React 18 + TS SPA, built, 3 unit tests; ESLint absent, Playwright not executed *(revision 4: 15 unit tests, ESLint + react-hooks, 3 Playwright journeys passing)* | `frontend/` |
| 8 — lab target and evaluation | ✅ deterministic ShadowLab + ground truth + strict scorer | `docs/evidence/scanner-evaluation.*` |
| 9 — hardening, docs, packaging | ✅ bandit/pip-audit clean, docs pack, deploy assets, zip | this file, `docs/known-issues.md` |

## Phase 0 — environment

* `python3 --version` → 3.13.3; `node --version` → 20.x; `zip` available.
* Not available: Docker daemon, OWASP ZAP, Trivy, Playwright browser bundles, ESLint
  config/package. Each is recorded in `docs/known-issues.md` with the exact human command.
* Consequence: container, DAST and dependency-image scanning are **documented, not run**.
  Everything else is executed.

## Phases 1–2 — the parts that are easy to get wrong

* `db.apply_migrations` creates `schema_migrations` itself; the first migration originally
  re-created it, which failed on a fresh database. Removed the DDL.
* `canonicalize()` intentionally performs **no DNS lookup** (resolution happens in
  `safe_http` under the pinning lock), so an allowlist test cannot depend on it resolving;
  `is_always_blocked()` is the right function for the metadata-range assertion.
* `169.254.169.254` and friends are blocked even when an operator allow-lists the port —
  `target_ports` is unioned with the allowlist for *authorisation*, never for the
  hard-block list.
* Decompression is streamed with a cap: a 10 MB gzip bomb becomes `ResponseTooLarge`, not
  memory pressure.

## Phase 3 — discovery

* 11 source families contribute endpoints on the lab: openapi, swagger_ui, redoc, postman,
  har, graphql, sitemap, source_map, javascript, html, docs.
* JavaScript is parsed as data. There is no JS engine in the scan path; concatenated string
  literals are joined, template placeholders are normalised to `{param}`.
* Source maps are followed only when they are same-origin and in scope.
* Static assets are filtered before they are counted as endpoints (`.js`, `.css`, images,
  fonts, `manifest.json` shapes) — that fix removed several false positives.
* Soft-404 detection: a catch-all shell is probed first; a candidate is only "live" when it
  differs in size by more than 25 % **and** below 0.9 similarity. A 0.7 similarity gate was
  too aggressive and hid real endpoints.

## Phase 4 — reconciliation

* Fingerprint is `METHOD|host|path_template|query_template`; that is what makes a finding
  stable across scans and across renames of ids.
* ST-009 (auth-required shadow) and ST-012 (documented-but-missing) live in `scan_rules.py`
  because they need scan-level context (the baseline and the observed set), not a single
  endpoint.
* Wording lint rejects "proven", "exploitable", "vulnerable" unless a `confirmation_basis`
  is present, so a finding never claims exploitation.

## Phase 5–6 — API and lifecycle

* A route↔policy diff script found 41 routes and 39 policy entries; `policy_guard` and a
  test now make that gap impossible (the test enumerates the app's routes).
* Aborted requests roll back their audit rows, which is correct for data but wrong for
  security events, so security-relevant audit writes pass `durable=True`.
* Crash recovery (`recover_stale`) marks abandoned scans failed with partial results kept.
* Cancellation sets `cancel_requested`; the worker observes it before every request.

## Phase 7 — frontend

* Vite build: 163 kB JS / 5.4 kB CSS, no sourcemaps, no inline script, so the CSP with
  `script-src 'self'` holds.
* `npm run lint` is `tsc --noEmit`; no ESLint configuration was installed
  (no network for the config) — documented as a gap.
* Playwright journeys are written (`frontend/e2e/smoke.spec.ts`) but the browser download
  is unavailable offline — documented as a gap.

## Phase 8 — evaluation

Two runs of the same scan, ten minutes apart, produce identical counters, which is the
point of a deterministic lab. The current scan is `404b416e73554a76bcc15a1bc9dffdbe`
(earlier runs: `ea2cf79beced45848a10e520ffd57c91`, `cf02c0649476476c96a98caf0ba15b26`).

```
endpoints 32 · validated 30 · shadow 24 · zombies 1 · findings 40
pages 13 · scripts 3 · requests 75 · source maps 2 · external refs 2
recall 1.0 · precision 1.0 · rules 16/16 · negatives 5/5 · traps 12/12 · sources 11
```

## Late fixes worth remembering

* **Per-scan response status.** `endpoints` rows are shared across scans, so a status could
  not live there. Migration `0003_scan_endpoint_status.sql` adds
  `scan_endpoints.response_status`; `compare_with_previous` reads
  `COALESCE(se.response_status, e.response_status)`. This is what makes
  "changed status since last scan" correct instead of accidentally global.
* **Crawler scope check before the fetch.** An out-of-scope seed used to reach the HTTP
  client, which then refused it. It is now filtered in `crawl()` and recorded as an
  external reference — defence in depth, and one fewer error event in the scan log.
* **SQL assembly.** Queries with optional filters interpolate only structural fragments
  (fixed clause literals, an allow-listed sort column, a two-value direction) and bind every
  value. The statements are module-level constants so a reviewer can see the whole query on
  one screen; bandit reports 0 findings with 18 justified `# nosec` annotations.
* **Configuration is a test surface.** `test_config.py` asserts that a production process
  with a weak secret, insecure cookie, wildcard host/CORS list or demo mode refuses to
  start.

## What is left for a human

1. Build and push the container images; run `docker compose up` and verify the healthcheck.
2. Run ZAP baseline and an image scan (Trivy/Grype) in a networked CI runner.
3. Load-test the API at the documented rate limits (currently reasoned, not measured).

*(Revision 4 closed items 2 — Playwright, 3 Playwright journeys passing — and 4 — ESLint
with `eslint-plugin-react-hooks`, wired into `make lint`. ZAP/Trivy/Docker remain open.)*

## Fix log

### 2026-10-26 — dashboard blank page after sign-in

**Reported:** `TypeError: Cannot read properties of undefined (reading 'length')` in the
generated bundle; the dashboard rendered blank after a successful sign-in.

**Root cause.** `GET /api/v1/dashboard/overview` never returned `recent_findings`, while
`frontend/src/api.ts` declared it as a required `Overview` field and `Dashboard` called
`data.recent_findings.length`. Two independent defects produced it:

1. *Missing field.* The route returned nine aggregates and simply omitted the recent-findings
   panel the UI expected. Findings were part of the intended dashboard (the README, the
   rubric's "recent findings" panel and the frontend type all assume it), so the backend was
   the side in the wrong: it now returns the five highest-risk findings for the caller's
   organization, with endpoint context and triage status, ordered
   `risk_score DESC, created_at DESC, id`.
2. *No contract.* The two sides had no shared definition, so nothing could catch the drift.
   `frontend/src/__fixtures__/overview.contract.json` is now the single source of truth: a
   backend test asserts the live payload has exactly those keys, a frontend test asserts the
   `Overview` type and both fixtures match them, and `api.overview()` normalises the response
   so a stale or partial payload can never blank the page again.

**Two further mismatches found while checking the related fields (item 6 of the report):**

* `endpoints.shadow` / `endpoints.documented` were counted from `endpoints.classification`,
  which is overwritten by every upsert — a scan without a baseline writes `unknown` for
  everything, so a real 24-shadow scan reported `shadow: 3`. The overview now takes each
  endpoint's most recent non-`unknown` classification from `scan_endpoints` (the authoritative
  per-scan record, see ADR-003), and the live database now reports 32 endpoints / 24 shadow /
  8 documented / 1 zombie, matching the scan counters.
* `ScanCounters` on the frontend declared `endpoints`, `endpoints_shadow`, `validated`,
  `requests`, `pages`, but the scanner writes `endpoints_found`, `shadow_endpoints`,
  `endpoints_validated`, `requests_used`, `pages_fetched`. The scan list and scan header were
  therefore showing zeros. Types and the three call sites were corrected.

**Not changed:** authentication, authorization (`ROUTE_POLICY` role for the route is still
`viewer`), tenant scoping (`WHERE org_id = ?` in every new query), CSRF, audit logging, and the
scanner/egress controls. No dependency was added or upgraded.

**Verification (all run, not claimed):** backend `358 passed`, coverage 90.3 % lines / 79.9 %
branches (`dashboard.py` 95 %/100 %); frontend `vitest` 15 passed; `tsc --noEmit` clean;
`vite build` clean; `ruff`, `mypy`, `bandit` and the egress gate clean; a live server + a real
lab scan returned the contract keys with 5 recent findings and non-zero endpoint counts.

## Fix log — round 3: CLI missing-password error (Windows)

**Reported:** `test_lifecycle_service.py::test_cli_rejects_missing_password_in_non_interactive_mode`
failed only on the reporter's Windows `.venv313`; expected `Provide --password or
ST_ADMIN_PASSWORD`, got `error: password must be at least 12 characters`. The test **passed** in
the Linux CI sandbox as written, so it was environment-dependent.

**Root cause (proven by direct repro, not assumed).** The validator was never at fault.
`app.cli._password()` chose its input source with a truthiness test and treated whatever came
back as a supplied credential. Two paths produced the empty/blank *string* that then failed
policy:

1. `sys.stdin.isatty()` reported `True` while `getpass.getpass()` returned `""` — on Windows
   `getpass` reads the console handle directly, so it does not see `stdin=subprocess.DEVNULL`
   and returns an empty string at EOF instead of raising `EOFError`.
2. `ST_ADMIN_PASSWORD` set to whitespace (`"   "`) is truthy, so it was used as-is.

Both fed `validate_password("")`/`validate_password("   ")` → `WeakPassword("password must be at
least 12 characters")`, hiding the real condition: **no password was supplied at all**.

**Fix (`backend/app/cli.py`, smallest path).** A blank value is now *missing*, never a credential:
`_supplied()` treats `None`/whitespace-only as absent; `_password()` returns `None` when no
source yields a real password, catches `EOFError`/`KeyboardInterrupt` (and a `sys.stdin` that is
`None` or whose `isatty()` raises), and `create_admin()` reports
`Provide --password or ST_ADMIN_PASSWORD (non-interactive)` and exits 2. The returned value is
**never stripped** — a password may legitimately contain leading/trailing spaces.

**Related path (`backend/app/main.py`).** `bootstrap_admin_if_configured()` applied the same
truthiness rule, so `ST_BOOTSTRAP_ADMIN_PASSWORD="   "` aborted startup with a policy error.
A blank value is now "not configured" (consistent with the CLI); a real but weak password still
fails closed.

**Unchanged, deliberately:** `MIN_PASSWORD_LENGTH = 12`, the 256-char cap, `_WEAK_PASSWORD`
denylist, the ≥3-character-class rule, email/name reuse checks, and Argon2id
(`time_cost=3, memory_cost=65536, parallelism=2, hash_len=32`). No credential is hardcoded and
no test was weakened or deleted — the reporter's test is untouched and still asserts the exact
message.

**New coverage — `backend/tests/test_cli.py` (29 tests):** source precedence; blank flag/env and
prompt EOF/Ctrl-C/bare-Enter treated as missing; `isatty()` raising; missing `sys.stdin`;
subprocess runs for the missing-passphrase message, env-var and flag paths, blank env value, and
weak-password rejection (`short`, denylisted, single-class); Argon2id hash at rest,
`verify_password` round-trip and wrong/empty rejection, audit row; bootstrap create / blank-skip /
weak-fail-closed / idempotent.

**Verification (all run, not claimed):** the reported test passes locally in both suites; full
backend suite `387 passed, 0 failed` (125 s); coverage 88.2 % total / 90.8 % lines / 80.4 %
branches (`app/cli.py` 95.1 %/95.9 %); frontend `vitest` 15 passed, `tsc --noEmit` clean,
`vite build` clean; `ruff`, `mypy` (55 files), `bandit` and the egress gate clean.

## Revision 4 — dependencies, deployment topology, config parity, browser journeys

Eight items were requested; each is stated here with the evidence that it is actually done.
Items that could not run in this sandbox are left documented, not claimed.

### 1. Dependency CVEs — closed (`pip-audit` → 0)

`pip-audit -r requirements.txt` (2026-10-26) started at **26 findings in 2 packages**: 12 in
`python-multipart` 0.0.20 and 14 in `starlette` 0.41.3. The lowest set that clears all of
them, verified by re-running the audit against a candidate requirements file before
touching the repo:

| Package | Before | After |
|---|---|---|
| `python-multipart` | 0.0.20 | **0.0.31** |
| `fastapi` | 0.115.6 | **0.135.0** |
| `starlette` | 0.41.3 (transitive) | **1.3.1** (explicit, so the floor is auditable) |

`starlette` 1.x is a major jump; the entire backend suite passes on it unchanged
(`430 passed`), which is the evidence that the upgrade caused no behavioural breakage.
The audit result is stored as `docs/evidence/pip-audit.json` and quoted in the README.

### 2. Kill switch — `ST_SCANNING_ENABLED`

`config.py` now reads `ST_SCANNING_ENABLED` and keeps `SCANNING_ENABLED` only as a
deprecated fallback (logged at WARNING, current name always wins). `.env.example`,
`docs/SECURITY_REQUIREMENTS.md` (OPS-08), `deploy/HARDENING.md`, `docs/known-issues.md`,
`conftest.py`, `test_security_helpers.py`, `test_scan_integration.py` and `test_config.py`
all use the documented name. New `tests/test_kill_switch.py` (11 tests) proves the promise:
`ST_SCANNING_ENABLED=false` returns 503 `scanning_disabled` on scan creation **and**
`SafeHttpClient` refuses before opening a socket (the local counting server records zero
requests), while target verification returns `verified: false` and `/meta/config` reports
the switch.

### 3. Worker egress

The worker was on the `internal: true` network — no default gateway at all, so it could
never reach a scan target. It now sits alone on an `egress` bridge (no published ports, not
attached to the proxy or the API); `api` and `proxy` keep the internal network, and a
regression-style note in `HARDENING.md` §6.1 explains that host/upstream firewall rules —
not Docker — must bound where those requests go, because `SafeHttpClient` is the in-app
control.

### 4. Trusted proxy / client IP

`ST_TRUSTED_PROXIES` is documented in `.env.example` and set in compose to the proxy's
pinned address (`172.30.0.2`); the Dockerfile runs uvicorn with
`--forwarded-allow-ips "${ST_TRUSTED_PROXIES}"` instead of `127.0.0.1`, so the two
allow-lists cannot drift. `client_ip()` now matches literal addresses **and CIDR
networks** (`config.is_trusted_proxy`), failing closed on unparsable entries.
`tests/test_trusted_proxy.py` (15 tests) proves the header is honoured only from a
trusted peer — including that an untrusted client cannot create its own rate-limit bucket
— and `HARDENING.md` §6.2 documents the settings.

### 5. `.env.example` parity

The file was rewritten to mirror `config.py` exactly. The invented
`ST_MAX_REQUESTS_PER_SCAN` / `ST_MAX_PAGES_PER_SCAN` / `ST_MAX_SCAN_SECONDS` names are now
the real `*_HARD_CAP` names; `ST_TRUSTED_PROXIES`, `ST_DEMO_MODE` and `ST_WORKER_POLL_MS`
are documented; upload/concurrency/response caps are identical in code and docs (8 MiB,
2 concurrent scans, 2 MiB — the two former documentation values that were *looser* than
the code were tightened to the code, not the other way round). `tests/test_env_example.py`
(10 tests) fails if an `ST_*` variable exists on one side only, or if a published default
stops matching the code.

### 6. Playwright — closed

New `frontend/playwright.config.ts` (baseURL from `ST_E2E_BASE_URL`, a `webServer` entry
that starts uvicorn against `ST_E2E_DB`), `e2e/global-setup.ts` (starts the lab, then seeds
a demo analyst **and one completed scan** via `scripts/seed_demo.py --with-scan`) and
`e2e/journey.spec.ts`. Chromium 156 was installed with its system libraries, so the
journeys actually ran: **3 passed**. The first run found a real defect — the JSON export
downloaded as `shadowtrace-<id>-json` with no extension — fixed in `EXPORT_FORMATS` with a
parametrised regression test in `test_api_scan_objects.py`. `scripts/seed_demo.py` gained
`--password`/`--with-scan`; `scripts/smoke_scan.py` grew a shared `run_lab_scan()` so the
seeder and the smoke run cannot diverge (its CLI output is unchanged, which the CI scanner
job depends on).

### 7. Consistency and packaging

Python **3.13** everywhere (Dockerfile `python:3.13-slim`, both CI jobs). `backend/.coverage`
is gitignored and excluded from the archive (`make zip` now fails if any coverage file or
`frontend/dist/` slips in). The SPA bundle is a build artefact: it stays gitignored, is not
shipped, and the README quick start always builds it.

### 8. Verification gaps

Closed: **Playwright (A5)** and **ESLint with react-hooks (A7)** — ESLint 9 flat config,
0 errors. `npm audit --production` reports **0 vulnerabilities** (**A4**). Still open and
documented, because the tools do not exist in this sandbox: Docker build/compose (A1),
OWASP ZAP (A2), Trivy (A3), plus axe (A6) and the dev-only vitest advisories (A4a).
`docs/known-issues.md` is updated only for the items actually closed.

## Revision 5 — spoofable client IP (defence in depth)

**Reported:** `deploy/proxy/nginx.conf` used `proxy_set_header X-Forwarded-For
$proxy_add_x_forwarded_for;`, which *appends* the peer to whatever the client sent, while
`client_ip()` took the **first** entry. A client sending `X-Forwarded-For: 1.2.3.4` was
therefore recorded — and rate-limited — as `1.2.3.4`, and could mint a fresh rate-limit
bucket at will.

**Fix 1 — the proxy overwrites.** Every location in `deploy/proxy/nginx.conf` that proxies to
`api:8000` (`/api/`, `/assets/`, `/`) now sets `proxy_set_header X-Forwarded-For
$remote_addr;` and keeps `proxy_set_header X-Real-IP $remote_addr;`. The header the API
receives always carries exactly one value: the peer that reached nginx. The file header
explains why, and warns against re-enabling append if a CDN is added later (use `real_ip`
for that trusted hop instead).

**Fix 2 — the application validates the chain.** `security/auth.py::client_ip()` now:

* reads the header only when the **socket peer** is a trusted proxy (unchanged), and
* parses every hop with `ipaddress.ip_address`, enforcing the 64-character limit per entry
  and a 16-hop bound, and
* walks the chain **from the right**, skipping entries that are themselves trusted proxies,
  returning the first untrusted address — i.e. the address our own infrastructure wrote
  last, not the one the client typed first.

A malformed, oversized, port-suffixed, empty or over-long chain falls back to the socket
peer. This also closes a smaller hole: the previous code returned the header value even
when it was not an IP at all, so `X-Forwarded-For: anything` became the recorded identity.

**Tests — `backend/tests/test_trusted_proxy.py` 15 → 34.**
`"1.2.3.4, 198.51.100.7"` from a trusted peer returns `198.51.100.7` (the spoofed entry is
ignored); an untrusted peer ignores the header entirely; eight malformed/oversized variants
(`not-an-ip`, a 65-character entry, `1.2.3.4:443`, `example.test`, an empty segment, 20 hops)
fall back to the peer; a chain of two trusted proxies resolves to the real client; IPv6 and
`[bracketed]` hops work. Three nginx guards fail if `$proxy_add_x_forwarded_for` reappears,
if any proxying location stops overwriting the header, or if `X-Real-IP` is dropped. Both
guards were mutation-checked: reintroducing append fails
`test_nginx_never_appends_to_x_forwarded_for`, and reverting to leftmost-wins fails
`test_a_spoofed_left_entry_does_not_win_over_the_real_one`.

**Verification (all run, not claimed):** `make verify` exit 0 — egress, ruff, tsc + ESLint
(0 errors), mypy (55 files), bandit, `pip-audit` (0 vulnerabilities), `445 passed` in
133 s, coverage 88.35 % combined / 90.8 % lines / 80.8 % branches (`auth.py` 90.5 %);
frontend `vitest` 15 passed.

## Revision 6 — "The request could not be verified." on Add Target

**Symptom.** Signed in as the administrator, submitting the Add Target form at
`http://127.0.0.1:8000` showed *"The request could not be verified."*; no target was created.

**Where the message comes from.** `security/auth.py::authenticate` raises
`ApiError(403, "csrf_failed", "The request could not be verified.")` from two places: the
CSRF-token comparison and the `Origin` comparison. Everything else in the flow was traced and
cleared with live evidence (a real server plus a real Chromium session):

| Hypothesis | Evidence | Verdict |
|---|---|---|
| Frontend missing the CSRF header | the POST carried `X-CSRF-Token` equal to the token from `/api/v1/auth/me` (`token equal? = true`) | not the cause |
| Cookies not sent | the POST carried `st_session` **and** `st_csrf`; an unauthenticated POST returns 401, not 403 | not the cause |
| Token not generated/persisted | `/me` returns the session's `csrf_token`; it equals the `st_csrf` cookie; `st_csrf` is deliberately not HttpOnly so the SPA can read it | not the cause |
| Session/rotation problem | login creates exactly one session; the token stays valid for the following requests | not the cause |
| **Origin rejected** | the POST carried `Origin: http://127.0.0.1:8000`; `_origin_allowed` compared only against `ST_CORS_ORIGINS` and `ST_BASE_URL`, both defaulting to `http://localhost:8000` → **403** | **root cause** |

**Root cause.** `_origin_allowed()` consulted only the *configured* origins and never the
origin the request was actually addressed to. `ST_ALLOWED_HOSTS` defaults to
`localhost,127.0.0.1`, so the SPA is served on both spellings, but only `localhost` was in the
origin list. The README quick start tells the operator to open `http://127.0.0.1:8000`, so the
very first mutation failed. The same bug hit **every** state-changing endpoint
(`/targets`, `/users/invite`, `/auth/change-password`, `/scans`, triage, approvals), because
they all pass through the same gate — confirmed by probing each route from both origins.

Why the suite never caught it: `conftest.app_env` sets `ST_CORS_ORIGINS=http://testserver`,
which happens to equal `TestClient`'s own origin, so every test was posting an origin that was
already in the configured list.

**Fix (`backend/app/security/auth.py`, ~40 lines).** An origin is now accepted when it is

1. one of `ST_CORS_ORIGINS` / `ST_BASE_URL`, or
2. **the origin the request was addressed to** — derived from the allow-listed `Host` header
   and the connection scheme (`X-Forwarded-Proto` only from a trusted proxy per
   `ST_TRUSTED_PROXIES`).

Origins are normalised to `(scheme, host, port)` with default ports folded and case folded;
`null`, bare host names, userinfo, paths, queries and unparsable ports never match. A
same-origin request is by definition not a cross-site forgery, and a cross-site attacker
cannot produce the pair (the browser sets `Origin`, and `Host` is allow-listed), so this is
not a relaxation: CORS is untouched and foreign origins are still 403.

**Tests — `backend/tests/test_csrf_origin.py` (52 new).** The reported flow end to end
(admin creates a target from `127.0.0.1` while the deployment is configured for `localhost`),
both documented dev origins, analyst creation, all three other mutations accepting the own
origin and rejecting a foreign one, nine hostile origins, missing/empty/wrong CSRF tokens,
safe-method exemption, 401-before-origin for unauthenticated requests, cookie flags,
`/me`↔cookie token equality, logout invalidation, origin parsing and proxy-header trust.
Mutation-checked: with the pre-fix `_origin_allowed` restored, 7 of them fail.

The Playwright journey now creates a target through the form and runs at `127.0.0.1:<port>`
with the API configured for `localhost:8000` — the exact shape that used to 403 — so the
browser layer covers it too (3/3 journeys pass).

**Verification (all run, not claimed):** focused `tests/test_csrf_origin.py` → 52 passed;
full backend suite → **497 passed**, 0 failed (161 s); `make verify` exit 0 (egress, ruff,
tsc + ESLint 0 errors, mypy 55 files, bandit, pip-audit 0 vulnerabilities, coverage
88.4 % combined / 90.9 % lines / 80.9 % branches, `auth.py` 90.9 %); frontend `vitest`
15 passed and `npm run build` clean; Playwright 3/3.

## Revision 7 — the private-network egress bypass, and three smaller findings

An independent reviewer installed the dependencies, ran the gates, the suite, the coverage
report, a smoke scan, `pip-audit`, the frontend checks and a live server, and reported four
findings. All four are addressed below; one extra defect was found while verifying them.

### 1. A target's declared ports unlocked private addresses (the serious one)

**Symptom.** A canary HTTP server on `127.0.0.1:9999` — *not* in `ST_PRIVATE_ALLOWLIST` —
received **10 requests** from a scan. The target was created with `ports: [9999]` and
approved by an organization admin in `admin` mode.

**Root cause.** `engine/safe_http.py::_preflight` built one list,
`private_allowlist = settings.private_allowlist + target_ports`, and `validate_destination`
treated *any* entry in that list as "this address is allowed". So the target record — which
any analyst can create and any org admin can self-approve — doubled as an egress grant. Only
metadata/link-local stayed blocked. `README.md` (lines 12 and 257), `deploy/HARDENING.md` §5
and `known-issues.md` C12 all promised the opposite, and
`test_safe_http.py::test_target_declared_port_is_authorized` encoded the bug as expected
behaviour.

**Fix — two permissions, never merged.**

| Permission | Granted by | Applies to |
|---|---|---|
| non-standard **port** | the target's `ports` **or** an operator allow-list entry | public addresses only |
| private/loopback **address** | an **operator** `ST_PRIVATE_ALLOWLIST` entry only | that exact `host:port` |

* `engine/urlguard.py::validate_destination(url, resolver, *, private_allowlist=(), declared_ports=())`
  keeps the two grants in separate parameters. `is_always_blocked` (metadata, link-local,
  unspecified) is checked for **every** resolved address before either grant is considered,
  so an allow-listed metadata address is still refused.
* `api/targets.py::create_target` refuses a private/loopback/reserved host with
  `422 invalid_target` in every authorization mode unless the operator listed its
  `host:port`; the metadata refusal now names the rule instead of saying "not a canonical URL".
* `tests/test_egress_guard.py` (34 tests) reproduces the exploit with a real counting canary
  and fails if the grants are ever merged again.
* Docs corrected to describe what the code enforces (`README`, `HARDENING` §5/§6.1,
  `THREAT_MODEL` §3.3, C12, `DECISION-005`) — the docs were changed to match the secure
  behaviour, not the other way round.

### 2. The UI quick start left scans `queued` for ever

`README.md` started only the API. The API never scans: it writes a `queued` row and a worker
claims it (`DECISION-005`). The quick start now starts both processes (bash **and** a CMD
variant), says why, and notes that the worker needs the same `ST_DATABASE_PATH` and
`ST_PRIVATE_ALLOWLIST`. `DECISION-005`'s title no longer says "in the API process" while its
body describes a separate process, and `main()` no longer turns `--once` into an infinite
sleep when the kill switch is off (it returned nothing and slept for ever — found while
writing the test).

Reproduced live: with the API only, a created scan sat at `queued` (and `POST /start`
returned 200 without changing anything); starting `python -m app.workers.worker` claimed it
and the scan completed with 29 endpoints and 19 findings.

### 3. An unreachable target looked like a clean result

**Symptom.** A scan of `10.0.0.5` ended `completed` with 0 endpoints and a "cleartext HTTP"
finding, which reads like "we looked and it is clean".

`ScanSummary` now carries `requests_failed` and `unreachable`; when no page could be fetched
and there were errors, the scan is marked `partial = 1` and logs `scan.target_unreachable`
at **error** level. Verified live against `10.0.0.5`:

```
state: completed   partial: True
counters: pages_fetched=0  requests_failed=1  unreachable=true  endpoints_found=0
events:   warning crawl.error              | http://10.0.0.5/: timeout
          error   scan.target_unreachable | No page could be fetched from the target (1 request(s) failed); …
```

The single configuration finding still appears, because it is derived from the target record
rather than from a response; C14 in `known-issues.md` records that, next to the counters that
now say "could not look".

**The `POST /scans/{id}/start` 404 could not be reproduced.** With a valid id the route
returns 200 while the scan is queued or running, 409 once it has finished, and 404 only for
an id that does not exist in the caller's organization — a worker holding the row does not
affect it, because the route only reads. `test_api_scan_objects.py::test_start_accepts_a_scan_a_worker_has_already_claimed`
pins all four cases.

**A real defect found while verifying the above:** the live two-process run logged
`sqlite3.OperationalError: database is locked` in both the API and the worker. The worker
left its `scan_events` and counter writes uncommitted, so it held SQLite's write lock for the
whole scan (a 70-second connect timeout against `10.0.0.5` was enough). Events and progress
are now committed per write (`record_event`, `record_progress`); the same live run shows
**zero** lock errors. `test_worker_loop.py` asserts the worker connection is never left in a
transaction.

### 4. The minor findings

* **Login accepted a foreign `Origin`** — `POST /auth/login` now refuses a present-but-
  disallowed origin with `403 csrf_failed` (the CSRF token itself does not exist before
  login, so the origin check is the only cross-site gate on that route). Covered by
  `test_csrf_origin.py::test_login_rejects_a_foreign_origin` and
  `::test_login_without_an_origin_header_still_works`; with the check removed the first one
  fails with `assert 200 == 403`.
* **Coverage** — `workers/worker.py` 65.5 % → **81.0 %** (branch 47.9 % → 72.0 %) and
  `security/ratelimit.py` 73 % → **100 %**, via `test_worker_loop.py` (20) and
  `test_ratelimit.py` (14). Neither number is load-bearing for security, but both modules are
  now tested for the behaviour they actually have.
* **Six `react-refresh` ESLint warnings and six dev-only npm advisories** — unchanged and
  still documented (A7, A4a). They are dev-toolchain advisories in `vitest`'s dependency tree
  and a single-file component organisation; fixing either is a deliberate change, not a
  patch, and neither ships.

### Verification (all run, not claimed)

Focused `tests/test_egress_guard.py` → **34 passed**; `tests/test_worker_loop.py` →
20 passed; `tests/test_ratelimit.py` → 14 passed; `tests/test_csrf_origin.py` → 54 passed
(the two new login-origin tests fail with the check removed). Mutation-checked: restoring the pre-fix
`_preflight`/`validate_destination` merge fails **8** of the egress tests, and removing either
`conn.commit()` fails the matching worker test.

Full suite → **568 passed**, 0 failed (205 s). `make verify` exit 0: egress gate, ruff, tsc +
ESLint (0 errors, 6 advisory `react-refresh` warnings), mypy 55 files, bandit, `pip-audit`
**0 vulnerabilities**, coverage **89.47 % combined / 91.8 % lines / 82.3 % branches**;
`vitest` 15 passed. `make evaluate --strict` → recall 1.0, precision 1.0, rules 16/16,
negatives 5/5, traps 12/12, sources 11.

Not verified in this round (no tooling in the sandbox): Playwright journeys, Docker/compose,
nginx, CI, production mode. They are listed with commands in `docs/known-issues.md` A1–A3.

---

## Revision 8 — full audit, frontend redesign, lab workflow, `policy_blocked` root cause

### The reported failure, diagnosed first

A scan of the approved local lab (`http://127.0.0.1:8099/`) completed with
`outcome=policy_blocked`, `pages_fetched=0`, one misleading "unreachable" finding and no
endpoints. Root cause: `ST_PRIVATE_ALLOWLIST` is read **per process**. The API had the entry
(so it approved the target at creation time) and the worker did not, so the worker's first
request to the approved host was refused by `validate_destination` before a socket was opened.
The scan then reported the refusal as if it had assessed the target.

Fix, without touching the guard: a target created under `authorization_mode=lab_allowlist`
carries an HMAC-SHA256 **grant** over `lab-v1|target_id|scheme|host|port`, minted with
`ST_SECRET_KEY`. The worker verifies the grant against the target row it reads from the shared
database *and* against its own allow-list, so it can honour an approval the API made while
still refusing everything else. Grants are re-derived on every start (`sync_grants`): removing
the allow-list entry, or editing the target's host/port, revokes it. `169.254.169.254`, other
loopback ports, RFC1918 and metadata destinations remain blocked with a grant in hand —
`backend/tests/test_lab_grants.py` (17 tests) pins both directions, including a real lab scan
with an **empty** worker allow-list.

Honest outcome classification was added at the same time: `ok` / `unreachable` /
`policy_blocked` / `timeout` / `cancelled` / `empty`, with `policy_blocked` now equal to the
number of refusals in the event log (redirect refusals were previously logged but not counted).

### What else changed

* **ShadowLab** grew from a handful of endpoints to 15 catalogued scenarios with inert,
  synthetic data (cleartext transport, headers, cookie flags, verbose errors, CORS, reflected
  XSS, SQLi on an in-memory mock, path traversal over a synthetic filesystem, IDOR, authn/authz,
  upload validation that never executes, a local-only open redirect, debug routes, API access
  control, weak input validation), all under `/lab/api/…`.
* **Six new rules** (`ST-018`–`ST-021`, `ST-023`, plus the `suspected`/`confirmed` split) with
  deterministic fixtures and false-positive controls (`test_rules_injection.py`, 47 tests).
* **Lab section**: a supervised, loopback-only lab process (fixed argv, scrubbed environment),
  start/stop/restart/reset, health, live rule mapping, and a one-click lab scan. No endpoint
  accepts a command, a path or a shell.
* **Frontend**: a complete redesign — sidebar shell, dark/light themes, real charts, tables with
  filters/search/sort/pagination, loading/empty/error states, confirmations, progress, a tabbed
  scan detail, evidence viewer, comparison, six exports, admin-only Settings/Audit — all fed by
  real API calls, with no placeholder control anywhere.
* **One-command start**: `start.cmd` (Windows) and `start.sh` (POSIX) export one configuration
  to both processes, apply migrations first, and prove readiness three ways (API health, lab
  health, worker heartbeat in the same database) before printing the URLs; `stop.cmd`/`stop.sh`
  shut down gracefully. This is the environment lesson from the root cause, encoded.
* **Consistency**: `scripts/e2e_round8.py` (`make e2e-api`) walks lab → target → scan → worker →
  crawl → findings → export → audit and asserts the seeded and persisted counts agree.

### Verification (all run, not claimed)

`make verify` exit 0 — egress gate, ruff clean, `tsc --noEmit` + ESLint (0 errors, 4 advisory
warnings), mypy clean (58 files), bandit 0 findings, `pip-audit` 0 vulnerabilities, coverage
**86.7 % combined** (`safe_http` 100 %, `urlguard` 99 % with no partial branches), backend
**632 passed**, `vitest` **15 passed**.
`make e2e-api` → **32/32** checks. The lab scan it runs produced 44 endpoints, 42 validated,
45 findings (20 high / 10 medium / 4 low), 29 pages and 3 policy refusals — all three the
lab's own redirect traps; the smoke scan produced 47 endpoints, 44 validated, 88 findings and
39 shadow endpoints with 18 distinct rules.
`make evaluate --strict` → recall 1.0, precision 1.0, rules **22/22**, negatives 5/5, traps
12/12, sources 11.

Not verified in this round (no tooling in the sandbox): the rewritten Playwright journeys
(no browser), Docker/compose, nginx, production mode. They are recorded in
`docs/known-issues.md` A1–A3 and A5.
