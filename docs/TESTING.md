# Testing

Four layers, each with a different cost/fidelity trade-off. Everything in layers 1–3 is
offline and deterministic; layer 4 needs the bundled lab process.

```
make verify          # layer 1 + 2 + 3 (what CI runs before anything else)
make test            # backend suite with coverage + frontend unit tests
make smoke evaluate  # layer 4: a real scan and a ground-truth score
make e2e-api         # layer 4b: the whole workflow through the API + worker (32 checks)
```

## Layer 1 — unit tests (fast, no I/O)

| File | What it pins down |
|---|---|
| `test_urlguard.py` (80) | the SSRF corpus: schemes, userinfo, backslashes, control chars, encoded IP literals, IPv4/IPv6 blocklists, metadata names, port policy, canonicalisation |
| `test_safe_http.py` (46) | header/size/decompression caps, pinning, redirect policy, kill switch, cancellation, budget accounting, `HEAD`/custom headers, charset fallbacks |
| `test_parsers.py` | XML/JSON/YAML hardening: DTD, entities, external refs, alias bombs, depth bombs, size caps |
| `test_extractors.py` | OpenAPI 2/3, Swagger UI, Redoc, Postman, HAR, GraphQL, source maps, HTML forms, JS patterns — plus source-map and asset filtering |
| `test_reconciler_rules.py` | fingerprinting, classification (shadow/documented/zombie), every rule, risk scoring, wording lint |
| `test_scope_validator.py` | scope host/port matching, prefix rules, validator method allow-list, circuit breaker, backoff, soft-404, authorisation-probe interpretation |
| `test_security_helpers.py` | password policy, token hashing, redaction (headers, keys, JWTs, private keys), audit redaction, request-id rules, host allow-list |
| `test_config.py` (14) | fail-closed production configuration (weak secret, insecure cookie, wildcard CORS/hosts, demo mode, bad quotas) |
| `test_crawler.py` (11) | crawl scope, page/script caps, cancellation, error recording, CSP/`Link`/`Allow` hints, inline-script parsing without execution, JSON spec parsing, source-map following, out-of-scope seed refusal |
| `test_egress_guard.py` (34) | the round-7 egress regression suite: a real counting canary on an unlisted loopback port that must receive **zero** requests, the same for RFC1918 and IPv6 ULA addresses, seven private base URLs refused at target creation in all three authorization modes, declared ports that must **not** unlock a private address, an allow-listed pair that must not open another port on the same host, metadata/link-local still blocked even when allow-listed, and the positive controls (an allow-listed lab target is still created, a public target is unaffected) |
| `test_lab_grants.py` (17) | the round-8 `policy_blocked` regression: a worker with an **empty** `ST_PRIVATE_ALLOWLIST` still scans a lab target that carries a valid HMAC grant; the same target without a grant stays blocked; a grant for another host/port, a tampered signature and a grant minted with a different secret are all refused; `169.254.169.254` and a second loopback port stay blocked even with a grant; removing the allow-list entry revokes the grant (`sync_grants`); a blocked scan reports `outcome=policy_blocked` with **no** findings, and a fetched scan reports `outcome=ok` |
| `test_rules_injection.py` (47) | one deterministic fixture per rule (positive *and* false-positive/false-negative case), the hedging lint for `suspected` findings, and the injection-safety rule: a hostile body cannot inject evidence, break the HTML export or change a rule's verdict |
| `test_ratelimit.py` (14) | the sliding window with an injected clock: window edges, `Retry-After` sizing and shrink, `limit <= 0` bypass, per-key independence, `peek` without consuming, `reset`, drained-bucket eviction, the `MAX_KEYS` pruning path, category namespacing, and 200 threads against one key where exactly the limit may pass |

## Layer 2 — API and authorization tests

| File | What it pins down |
|---|---|
| `test_api_authz.py` | the role × route matrix. A separate test walks the FastAPI route table and fails if any route has no entry in `ROUTE_POLICY`, so the matrix cannot silently fall behind the code |
| `test_auth_flow.py` | login, hardened cookies, CSRF, logout revocation, session rotation, password change, invitations, rate limits, audit rows |
| `test_api_scan_objects.py` | scan list/detail, endpoint and finding filters, comparison, six export formats, CSV formula handling, HTML escaping, audit of exports |
| `test_api_targets_inventory.py` (15) | target creation/approval/verification (against a local stub), duplicate-host conflict, delete guarded by active scans, baseline upload validation, HAR import counts and limits, inventory filters/sort fallbacks, triage history |

`tests/conftest.py` gives each test a fresh SQLite database in `tmp_path` and seeded
organizations, users (admin/analyst/viewer in two orgs) and one approved lab target.
Organizations are separate; cross-organization access is asserted to return 404.

## Layer 3 — service and integration tests

| File | What it pins down |
|---|---|
| `test_api_dashboard.py` (12) | the overview contract: exact key set (asserted against `frontend/src/__fixtures__/overview.contract.json`), empty-organization payload, `recent_findings` shape/order/cap, per-scan endpoint classification, tenant isolation, role access, triage counts |
| `test_cli.py` (29) | the admin CLI and bootstrap password path: source precedence (`--password` → `ST_ADMIN_PASSWORD` → prompt), blank/whitespace values and prompt EOF/Ctrl-C treated as *missing* rather than weak, a real but weak password still rejected by `validate_password`, Argon2id at rest and `verify_password` round-trip, blank bootstrap variables skipped while a weak one fails closed |
| `test_csrf_origin.py` (54) | the CSRF origin gate: a target creation (and every other mutation) from the app's own origin succeeds while `ST_CORS_ORIGINS`/`ST_BASE_URL` name a *different* documented dev origin; both `localhost:8000` and `127.0.0.1:8000` work; foreign, `null`, path-bearing, wrong-port, scheme-downgraded and userinfo origins are refused; missing/empty/wrong tokens are refused; safe methods are exempt; unauthenticated is 401 before any origin check; cookie flags (`st_session` HttpOnly, `st_csrf` readable, both `SameSite=Strict`); `X-Forwarded-Proto` honoured only from a trusted proxy; origin parsing folds case and default ports; and `POST /auth/login` — which has no CSRF token to compare — refuses a foreign `Origin` while still accepting a client that sends none |
| `test_kill_switch.py` (11) | `ST_SCANNING_ENABLED` under its documented name: precedence over the deprecated `SCANNING_ENABLED`, the warning it logs, boolean parsing, and the promise itself — no scan is queued, no socket is opened, target verification returns unverified, and the API metadata reports the switch |
| `test_trusted_proxy.py` (34) | `X-Forwarded-For` is honoured only from a configured proxy (literal addresses, CIDR networks); the chain is walked from the right so `"spoofed, real"` returns `real`; a two-proxy chain resolves to the client; malformed, oversized, port-suffixed, empty and >16-hop headers fall back to the socket peer; an untrusted peer ignores the header entirely and cannot create its own rate-limit bucket; and `nginx.conf` is guarded against reintroducing `$proxy_add_x_forwarded_for` (every proxied location must overwrite with `$remote_addr` and keep `X-Real-IP`) |
| `test_env_example.py` (10) | `.env.example` and `config.py` describe the same configuration in both directions, the kill switch is documented under its real name, and the published numeric/boolean defaults match the code |
| `test_lifecycle_service.py` (15) | state machine, idempotency, quotas, cancel semantics, crash recovery, comparison against the previous scan (per-scan `response_status`) |
| `test_worker_loop.py` (20) | the worker process itself: the kill switch stops `claim_next` **and** `main()` (so `--once` cannot spin), a claim takes the lease and records `worker.claimed`, two pollers cannot claim the same row, FIFO order, heartbeat renewal and cancellation propagation, `recover_stale` on an expired lease (partial results kept, audit row written) and not on a live one, `--recover`/`--scan-id` entry points, an unreachable target ends `completed` with `partial = 1` and a `scan.target_unreachable` event, and the shared-database contract — an event or counter write must be committed, because leaving it open locks the API out of SQLite |
| `test_scan_integration.py` (5) | the real engine against an in-process lab on a free port: a full scan produces endpoints, sources, evidence and findings; cancellation stops mid-scan; a scope-violating target is refused |

## Layer 4 — the real lab and the evaluation harness

```bash
make lab                     # terminal 1: ShadowLab on 127.0.0.1:8099
make smoke                   # terminal 2: one real scan (40-page budget), prints the scan id
make evaluate SCAN_ID=<id>   # scores it against lab/ground_truth.json (strict gate)

make e2e-api                 # layer 4b: lab → target → scan → worker → findings → export
```

`scripts/evaluate.py --strict` exits non-zero unless **all** of these hold: recall 1.0,
precision 1.0, every planted rule detected, every negative control silent, every hostile
trap handled, ≥ 5 discovery sources, and the scan completed without being partial. That is
the same gate CI runs, so the numbers in `docs/evidence/` cannot drift from the code
without CI failing.

Current result (scan `0c93c64e361e4d368bdea04ccef8c2f0`):

```
recall 1.0  precision 1.0  rules 22/22  negatives 5/5  traps 12/12  sources 11
```

## Frontend

```bash
cd frontend
npm run lint      # tsc --noEmit && eslint (flat config, react-hooks rules)
npx vitest run    # 15 unit tests: API client, error mapping, formatting, and the dashboard
                  # (empty + populated + legacy payload + counter keys + XSS escaping)
npm run build     # production bundle, no sourcemaps, no inline script
```

**Layer 5 — browser journeys (`frontend/e2e/journey.spec.ts`, 2 tests).** Rewritten for the
round-8 UI (sidebar, tabbed scan detail, modal target form) and **not executed in this
delivery environment** — there is no browser here. The previous UI's journeys were executed
and passed (Chromium 156, `3 passed`) before the redesign; the rewrite is a best-effort
translation of the same assertions onto the new DOM, so treat a first local run as part of
acceptance. Playwright builds nothing itself — run `npm run build` first — and
`global-setup.ts` starts the bundled lab, seeds a demo analyst plus one **completed real
scan** through `scripts/seed_demo.py --with-scan`, while `webServer` starts uvicorn against
that same database.

| Journey | What it proves |
|---|---|
| analyst signs in, follows a scan, reads evidence and exports it | login → overview charts → scan list → tabbed scan detail → finding with remediation → endpoint classification filter → event timeline → Report download with a real filename → sign out. Runs at `127.0.0.1:<port>` while the API is configured for `localhost:8000`, exactly the deployment that used to fail |
| target registration works from the browser | the modal form creates a target and the audit log shows `target.created` (the "request could not be verified" CSRF/origin regression) |

```bash
cd frontend && npm run e2e:install     # once: Chromium + system libraries
cd frontend && npm run build && npm run e2e
```

The first execution found a real defect — the JSON export downloaded as
`shadowtrace-<id>-json`, with no extension — now fixed and covered by
`test_api_scan_objects.py::test_export_filename_carries_an_extension`.

## Coverage

`make test-backend` writes `docs/evidence/coverage.xml`, `coverage.json` and `junit.xml`
and fails below 80 % combined coverage. Current position:

| Scope | Statements | Branches | Combined |
|---|---|---|---|
| All backend code | 86.7 % combined (5665 statements, 1844 branches) | | **86.7 %** |
| `engine/safe_http.py` | 100 % | 100 % | **100 %** |
| `engine/urlguard.py` | 99 % | 100 % (0 partial) | 99 % |
| `engine/scope.py` | 97 % | 96 % | 97 % |
| `security/ratelimit.py` | 100 % | 100 % | **100 %** |
| `workers/worker.py` | 80 % | 72 % | 80 % |
| `engine/crawler.py` | 83 % | 77 % | 83 % |
| `services/lab.py`, `api/targets.py` | 70 % | — | 70 % (the lab supervisor's process-control and error branches) |

The lowest module is `workers/worker.py` — the poll loop, heartbeat and recovery paths are
covered by `test_worker_loop.py`; what remains is the timing of the process-level infinite
loop. `api/deps.py` (72 %) and `api/scans.py` (78 %) are thin glue whose uncovered lines are
error-mapping branches.

## Determinism and hygiene

* No test touches the network: `ST_PRIVATE_ALLOWLIST` is empty except where a test
  deliberately starts a loopback stub, and the scanner is only pointed at loopback.
* Every test gets its own database file; `limiter.reset()` runs per test so rate-limit
  state cannot leak between tests.
* Time is monotonic and injected where it matters (`now()`), and backoff sleeps are
  injected, so the suite has no `sleep`-based flakiness.
* The suite is order-independent: `pytest-randomly` reshuffles it and the run above was a
  randomised one.
