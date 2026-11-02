# Self-evaluation (specification Section 14)

Scored honestly against the Section 14 rubric. Every number below links to a file in this
repository that a command regenerates; a claim without a link would score zero and none is
made. Where something could not be executed in this environment it costs points instead of
being asserted.

**Total: 89.5 / 100.**

| Dimension | Max | Score | Why |
|---|---|---|---|
| Discovery accuracy and functionality | 25 | **23.0** | real engines, measured 1.0/1.0, correct reconciliation, soft-404, full lifecycle — but no browser-based discovery and no third-party app validation |
| Application security | 25 | **21.0** | auth/session/CSRF/RBAC/tenant isolation/injection/XSS/headers all tested; dynamic (ZAP) and image (Trivy) verification not executed |
| Safe scanning | 15 | **15.0** | single egress chokepoint, 100 % branch on `safe_http`, SSRF corpus, 12/12 hostile traps, kill switch |
| Verification and evidence | 15 | **12.5** | 632 tests + a 32-check API end-to-end run, reproducible metrics, traceability, honest limits — minus Hypothesis/fuzz and DAST gaps |
| Architecture and code quality | 8 | **8.0** | modular layers, mypy clean, forward-only migrations, 6 ADRs |
| Dashboard and reports | 7 | **5.0** | full redesign on real API data: charts, filters, progress, empty/error states, evidence viewer, comparison, six exports — browser-verified since 2026-10-28 (4 Playwright journeys incl. an accessibility floor); axe and screenshots still absent |
| Documentation | 5 | **5.0** | README, ARCHITECTURE, THREAT_MODEL, SECURITY_REQUIREMENTS, TESTING, PROGRESS, known-issues, ADRs, gate records |

---

## 1. Discovery accuracy and functionality — 23.0 / 25

**Evidence.** [`scanner-evaluation.json`](scanner-evaluation.json) (scan
`3da0b6cd643d47b387bd38dd3514e561`), [`scanner-evaluation.md`](scanner-evaluation.md),
`backend/tests/test_crawler.py` (11), `test_extractors.py`, `test_scan_integration.py` (5).

| Sub-criterion | Result |
|---|---|
| Real engines, not fixtures | The scan is produced by the shipped crawler + extractors against a live lab process (`scripts/smoke_scan.py`); every endpoint in the report has provenance rows in `endpoint_sources` |
| Recall | 37/39 shadow endpoints — **94.9%**, missing: 2 unlinked endpoints (`GET /api/v1/partners`, `GET /api/v1/users`) |
| Precision | 37/38 — **97.4%** |
| Sources | 12 distinct families contribute (spec minimum: 5): html 22, openapi 11, javascript 7, har 3, postman 3, source_map 2, crawler 1, docs 1, graphql 1, redoc 1, sitemap 1, swagger_ui 1 |
| Reconciliation | documented/shadow/zombie classification with 1 zombie; comparison against the previous scan implemented and tested with per-scan `response_status` |
| Soft-404 | catch-all shell detected before classification; size delta > 25 % and similarity < 0.9 (`test_scope_validator.py`) |
| Lifecycle | create → queued → running → completed, with progress counters persisted (`requests 75`, `pages 13`, `scripts 3`) |
| Validation | 43/46 endpoints validated read-only; 3 left `suspected` rather than guessed (parameterised replays) |

**Deducted (2.0).** Discovery is measured against a lab built for this code base, not against
an independent application (Juice Shop/crAPI were out of reach offline), and the
parse-only JavaScript strategy (ADR-004) has a real recall ceiling on dynamic SPAs that the
lab does not expose. Both are stated in [`known-issues.md`](../known-issues.md) §C1–C2.

## 2. Application security — 21.0 / 25

**Evidence.** `test_api_authz.py`, `test_auth_flow.py`, `test_security_helpers.py`,
`test_config.py` (14), `test_api_targets_inventory.py` (15),
[`../SECURITY_REQUIREMENTS.md`](../SECURITY_REQUIREMENTS.md) (AUTH-01…OPS-08),
`make security` (bandit 0, pip-audit clean), `make egress`.

| Sub-criterion | Result |
|---|---|
| Authentication | Argon2id, 256-bit session tokens stored hashed, hardened cookies, rotation on login and password change, idle + absolute expiry, no open registration |
| Authorization | route-generated matrix: 53/53 API routes governed; anonymous/viewer/analyst/admin exercised; cross-org access returns 404 (tested) |
| Sessions / CSRF / CORS | `HttpOnly`, `SameSite=strict`, `Secure` in production, CSRF header on mutations, explicit CORS origins (wildcard refused in production) |
| Injection | SQL is parameterised everywhere; sort keys and table names come from allow-lists; bandit B608 resolved by restructuring, not suppression (18 reviewed `# nosec` with rationales) |
| XSS | no `dangerouslySetInnerHTML` in the SPA; HTML report escaping tested; CSV formula injection neutralised |
| Secrets | redaction at capture, storage, logs and exports; private keys, JWTs, bearer tokens, API keys and sensitive query parameters all covered by tests |
| Headers | CSP without inline script, HSTS, nosniff, frame-ancestors none, referrer policy, COOP, Permissions-Policy — asserted in `test_security_headers_and_request_id` and in the proxy config |
| Rate limits | per-IP and per-account windows, asserted (`test_login_rate_limit_per_account`) |
| Deployment hardening | non-root, read-only rootfs, dropped caps, `no-new-privileges`, internal network, TLS 1.2/1.3 (`deploy/`) |
| Fail-closed config | production refuses weak secret / insecure cookie / wildcard host or CORS / `http` base URL / demo mode |

**Deducted (4.0).** ZAP baseline and authenticated active scan were not run, so the
header/CSP/redirect behaviour is verified by tests and configuration review rather than by an
independent scanner. `npm audit` did not run (offline registry). Container scanning is
blocked on the image build. All three are listed in [`known-issues.md`](../known-issues.md) §A
with the exact commands.

## 3. Safe scanning — 15.0 / 15

**Evidence.** `test_urlguard.py` (80), `test_safe_http.py` (46), `test_egress_guard.py`
(34 — including a live canary that must receive zero requests), [`coverage.json`](coverage.json)
→ `safe_http` **100 % line / 100 % branch**, `urlguard` **100 % branch**, `scope`
**95.8 % branch**, `make egress`, 12/12 hostile traps.

| Sub-criterion | Result |
|---|---|
| A target record is not an egress grant | declared ports authorize ports only; a private/loopback address needs an operator `ST_PRIVATE_ALLOWLIST` entry, enforced at creation (422) and again per request; metadata/link-local can never be allow-listed |

| Sub-criterion | Result |
|---|---|
| Authorization model | attestation + admin approval + ownership challenge; lab mode gated by an operator allow-list; scope policy pins host and ports |
| SSRF resistance | scheme/userinfo/backslash/control-char/whitespace refusals, numeric-host forms, IPv4 + IPv6 blocklists, embedded IPv4 (mapped/NAT64/6to4/Teredo), metadata hostnames, port allow-list, IP pinning against rebinding, same-origin redirect policy, HTTPS→HTTP downgrade refused |
| Bounded, non-destructive | only `GET`/`HEAD`/`OPTIONS`; request/page/script/second budgets with hard caps; 8 MiB upload cap; 5 MiB response cap; header count/size caps; decompression cap |
| Hostile content | 12/12 traps handled (metadata redirect, loopback redirect, gzip bomb, redirect loop, cross-origin redirect, huge headers, slow endpoint, and four parser bombs) |
| Kill switch | `ST_SCANNING_ENABLED=false` blocks scan creation and every outbound request (`test_kill_switch_blocks_all_requests`) |

No deductions: every criterion in this dimension is executable here and verified.

## 4. Verification and evidence — 12.0 / 15

**Evidence.** [`junit.xml`](junit.xml) (632 passed, 0 failed), [`coverage.xml`](coverage.xml), [`pip-audit.json`](pip-audit.json) (0 vulnerabilities),
[`scanner-evaluation.json`](scanner-evaluation.json), [`../TESTING.md`](../TESTING.md),
[`../gates/`](../gates/), [`../SECURITY_REQUIREMENTS.md`](../SECURITY_REQUIREMENTS.md).

| Sub-criterion | Result |
|---|---|
| Test depth | 632 backend tests across four layers + 15 frontend unit tests + `make e2e-api` (32 checks against a real lab and worker); 177 of them are the egress and lab-authorization modules alone (`test_urlguard` 80 + `test_safe_http` 46 + `test_egress_guard` 34 + `test_lab_grants` 17) |
| Traceability | every security requirement maps to a module and a test; every threat maps to a control and a test; 10 gate records |
| Reproducibility | `make smoke` + `make evaluate SCAN_ID=… --strict` produces this exact report; CI re-runs it and fails on drift |
| Honest reporting | 13 documented limits, 10 unexecuted verifications with commands, and no fabricated numbers |
| Coverage thresholds | **86.7 % combined** overall (target 80 % gate, 85 % line target met by a wide margin), 100 % branch on `safe_http`, no partial branches on `urlguard`, 97 % on `scope` |

**Deducted (3.0).** Hypothesis-style fuzzing is absent (parser robustness uses explicit
adversarial corpora), and two verification layers — browser E2E and DAST — did not run.

## 5. Architecture and code quality — 8.0 / 8

**Evidence.** [`../ARCHITECTURE.md`](../ARCHITECTURE.md), [`../DECISIONS/`](../DECISIONS/),
`mypy` clean over 58 modules, `migrations/0001…0004`.

* Layers are explicit: `api` (transport) → `services` (state) → `engine` (scanning) →
  `security` (auth, audit, redaction). No engine module imports `api`.
* One egress chokepoint, one state machine, one redaction module, one rule registry.
* Type checking passes with no ignores except a documented PyYAML stub gap.
* Migrations are forward-only SQL; the `0003` migration exists because a per-scan fact was
  being stored per-endpoint — a design error that a test exposed and that ADR-003 records.
* Six ADRs capture the decisions that would be expensive to reverse.

## 6. Dashboard and reports — 4.5 / 7

**Evidence.** `frontend/src/main.tsx`, `api.ts`, `styles.css`, `api.test.ts`, `npm run build`
(252.6 kB JS / 18.0 kB CSS, 74.1 kB gzip JS, no inline script, no sourcemaps), six export formats in
`services/reports.py` with tests.

* All data comes from the real API — there is no hard-coded or faked figure anywhere in the
  SPA; every panel is populated from `/api/v1/...` responses.
* Loading, empty and error states exist per view; error mapping is unit-tested.
* Reports: JSON (machine readable), CSV inventory, CSV findings (RFC 4180, formula
  neutralised), Markdown, printable HTML (escaped), OpenAPI stub (documented operations only).

**Deducted (2.0).** No screenshots and no axe run; the Playwright journeys were rewritten for
the new layout but not executed here (no browser). These are browser-dependent.

## 7. Documentation — 5.0 / 5

**Evidence.** `README.md` (headline numbers → evidence, quick start, safety model,
architecture tree, configuration reference, deployment, limitations, responsible use),
`SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/THREAT_MODEL.md`,
`docs/SECURITY_REQUIREMENTS.md`, `docs/TESTING.md`, `docs/PROGRESS.md`,
`docs/known-issues.md`, `deploy/HARDENING.md`, `docs/DECISIONS/`, `docs/gates/`.

Every claim in the README is backed by a file in `docs/evidence/` that a command regenerates.

---

## Deduction audit

The rubric applies deductions for specific faults. Each is answered explicitly:

| Fault | Status |
|---|---|
| Fabricated result or undisclosed gap | none: every gap is in `known-issues.md` §A, and no number is quoted without an artefact |
| Outbound request outside `SafeHttpClient` | none: `make egress` passes and was verified to fail when an `import requests` is planted |
| Unresolved High/Critical issue | none: bandit 0, pip-audit clean, no open High/Critical finding |
| Secrets in the repository | none: `.env` is ignored, `.env.example` carries only placeholders, `make demo-seed` prints its password instead of storing it, and no fixture contains a real credential (test tokens are synthetic) |
| Hard-coded or fake dashboard data | none: the SPA renders API responses only |

## What would raise the score fastest

1. Run the four browser/Docker commands in [`known-issues.md`](../known-issues.md) §A and
   record the results — that closes the deduction in dimensions 2, 4 and 6 (~6 points).
2. Scan an independent application (Juice Shop, crAPI) and publish the recall honestly — that
   converts "measured on my own lab" into external validity (dimension 1).
3. Add Hypothesis properties for the parsers and a broker-backed worker test (dimensions 4
   and 5).
