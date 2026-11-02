# Architecture

ShadowTrace is a scanner, not a framework: one FastAPI application, one worker process, one
SQLite database, one egress client.

## 1. Layers

| Layer | Modules | Rule |
|---|---|---|
| Transport / API | `app/api/*`, `app/main.py`, `app/security/middleware.py` | Validate, authorize, delegate. No engine logic, no SQL outside the service helpers. |
| Services | `app/services/scans.py`, `app/services/reports.py` | Lifecycle transitions, quotas, report rendering. The only place that mutates scan state. |
| Engine | `app/engine/*` | Pure functions and small classes. Take a client/clock/resolver, return dataclasses. Never import `app.api`. |
| Security | `app/security/*` | Auth, sessions, CSRF, RBAC, redaction, audit, rate limiting. No knowledge of the engine. |
| Worker | `app/workers/worker.py` | Claim → heartbeat → execute → recover. Owns the scan lease. |
| Persistence | `app/db.py`, `app/engine/persistence.py`, `migrations/` | The only writers of SQL that is not a read query. |

Dependency direction is strictly downward. `app/engine` never imports `app.api` or
`app.workers`; the dependency-injection seam is `SafeHttpClient(settings, resolver=…,
scope=…, budget=…, clock=…, sleep=…)`, which is why the whole engine runs offline in tests.

## 2. Data model

```
organizations ─┬─ users ── sessions
               ├─ invitations
               ├─ targets ─┬─ baselines
               │           ├─ har_imports
               │           └─ scans ─┬─ scan_events
               │                     ├─ scan_endpoints ── endpoints ─┬─ endpoint_sources
               │                     │                               └─ observations
               │                     ├─ findings ── triage_records ── triage_history
               │                     └─ report_exports
               └─ audit_log (append-only, enforced by triggers)
```

Key invariants enforced by the database, not by convention:

- `endpoints` is unique on `(org_id, target_id, method, host, path_template, query_template)`
  — one identity per endpoint per target, so fingerprints are stable across scans.
- `scan_endpoints` carries the **per-scan** `validation_status`, `classification` and
  `response_status`, so scan-to-scan comparison does not read the mutable `endpoints` row.
- `findings` is unique on `(scan_id, fingerprint)`; a rule can fire once per scan.
- `audit_log` rejects `UPDATE`/`DELETE` with `RAISE(ABORT)`.
- `targets` is unique on `(org_id, host)`.
- `scans.state` and `findings.severity` are `CHECK` constrained to the documented enums.

Migration `0004_lab_grants_worker_health.sql` adds the lab grant columns, the grant table and
`worker_heartbeats` (worker liveness is a row, not a guess); `0003_scan_endpoint_status.sql`
exists because comparison between two scans needs
the observation of *that* scan; the retrofitted column is the fix for a real defect found by
`tests/test_lifecycle_service.py`.

## 3. Scan lifecycle

```
queued ──start──▶ running ──┬─▶ completed
   │                        ├─▶ failed
   │                        ├─▶ timed_out
   └─cancel─▶ cancelled     └─cancel─▶ cancelling ─▶ cancelled
```

`app/services/scans.py::transition` is the only writer of `scans.state`, and it checks both
the `from_states` set and the transition map. Illegal transitions raise
`InvalidTransition` (HTTP 409), which is covered by
`tests/test_lifecycle_service.py::test_quotas_and_state_machine`.

Cancellation is cooperative: `request_cancel` sets `cancel_requested`, the worker's
`cancel_check` is consulted before every fetch through
`SafeHttpClient._preflight`, and the scanner converts the resulting `ScanCancelled` into a
`cancelled` state with partial results preserved.

Crash recovery: the worker renews a lease in `scans.lease_expires_at` from a heartbeat
thread. `recover_stale()` fails scans whose lease expired, keeps `partial = 1`, emits a
`worker.lost` event and writes an audit record — never silently deletes work.

## 4. Engine flow

```
crawl()                       ── pages, scripts, source maps, well-known probes
  extractors/*                ── HTML, JS(AST+regex), specs, robots/sitemap, HAR, source maps
normalize()                   ── path/query templates, fingerprints, static-asset filter
reconcile()                   ── documented vs shadow vs zombie, legacy version hints
validate()                    ── GET/HEAD/OPTIONS only, soft-404 probe, circuit breaker
analyze()                     ── rules over (endpoint, observation) pairs
persist()                     ── endpoints, provenance, observations, findings
```

Each stage is idempotent with respect to its inputs and independently testable:

| Stage | Module | Test file |
|---|---|---|
| crawl | `engine/crawler.py` | `tests/test_crawler.py` |
| extract | `engine/extractors/*` | `tests/test_extractors.py` |
| normalize | `engine/normalizer.py` | `tests/test_normalizer.py` |
| reconcile | `engine/reconciler.py` | `tests/test_reconciler_rules.py` |
| validate | `engine/validator.py` | `tests/test_scope_validator.py` |
| analyze | `engine/rules.py`, `scan_rules.py` | `tests/test_reconciler_rules.py` |
| egress | `engine/safe_http.py`, `urlguard.py`, `scope.py` | `tests/test_safe_http.py`, `test_urlguard.py` |
| orchestrate | `engine/scanner.py`, `workers/worker.py` | `tests/test_scan_integration.py` (real lab) |

## 5. Discovery sources and confidence

| Extractor | Source type | Confidence | Cap |
|---|---|---|---|
| `html_extract` links/forms/scripts | `html` | 0.6 | 12 pages |
| `js_extract` (tree-sitter + regex) | `javascript` | 0.5–1.0 by pattern | 20 scripts, 3 MiB each |
| `sourcemap` | `source_map` | inherits | 6 maps |
| `specs` OpenAPI/Postman/Swagger UI | `openapi`/`postman`/`swagger_ui`/`redoc` | 0.9–1.0 | 12 probes |
| `robotssitemap` | `robots`/`sitemap` | 0.35–0.55 | 500 URLs, 20 index files |
| `har_extract` | `har` | 0.95 | 5000 entries in scope |
| `docs` method/path pairs | `docs` | 0.35 | prose only, never comments |
| crawler headers (CSP/Link/Allow) | `crawler` | 0.4–0.5 | per response |

Decoys are handled deliberately: HTML comments and prose are not endpoint sources (the lab
plants `/api/v1/decoy-only-in-comment` and `/api/v1/decoy-in-prose` as negative controls), and
sitemap entries must look API-like before they enter the inventory.

## 6. Scoring

```
risk_score = clamp(severity_base + 12 × confidence_weight + 4 × exposure, 0, 100)
severity_base   = critical 80 · high 60 · medium 40 · low 20 · info 2
confidence_wt   = confirmed 1.0 · high 0.8 · medium 0.5 · low 0.2
exposure        = 0.2 base + 0.5 unauthenticated + 0.2 sensitive path − 0.2 out of scope
```

Bands do not overlap, so a lower severity can never outrank a higher one
(`tests/test_reconciler_rules.py::test_risk_score_is_bounded_and_monotonic`).

## 7. API surface

- One version prefix (`/api/v1`), one error envelope
  (`{"error": {"code", "message", "request_id"}}`), request IDs on every response.
- Pagination (`page`, `page_size`) and sorting on every collection, with sort keys mapped
  through an allow-list dictionary (never interpolated from user input).
- OpenAPI generated from code; `/api/docs` and `/api/openapi.json` are disabled in
  production.
- `ROUTE_POLICY` in `app/api/deps.py` is the single source of truth for the minimum role per
  `METHOD path`. `policy_guard` enforces it before any body is parsed, and
  `tests/test_api_authz.py` fails when a route is missing from the map — the matrix cannot
  drift from the code.

## 8. Frontend

React 18 + TypeScript + Vite, no inline scripts, served by FastAPI from `frontend/dist`
with an SPA fallback for non-`/api` paths. `frontend/src/api.ts` is the only place that
talks to the API: it attaches the CSRF header from the readable `st_csrf` cookie, normalises
errors into `ApiError`, and keeps the in-memory CSRF token in sync after login. The UI never
renders target data as HTML — values go through React's text nodes, so a payload like
`<script>alert(1)</script>` renders inert (asserted by
`tests/test_api_scan_objects.py::test_html_export_escapes_untrusted_values` on the report and
by the React data flow in the UI).
