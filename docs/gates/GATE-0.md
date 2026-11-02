# GATE-0 — Plan, architecture and threat model

**Criteria:** the phase-0 documents are complete and consistent, cover Sections 3–5 of the
specification, and every threat has a mitigation *and* a planned test.

**Deliverables and where they live**

| Deliverable | Location |
|---|---|
| Architecture, data flow, trust boundaries, state machine, data model | `docs/ARCHITECTURE.md` (150 lines, includes a Mermaid container diagram and the scan state machine) |
| Architecture decisions | `docs/DECISIONS/DECISION-001…006` (+ index) |
| Threat model: assets, actors, STRIDE per component, abuse cases | `docs/THREAT_MODEL.md` (109 lines) |
| Security requirements with IDs | `docs/SECURITY_REQUIREMENTS.md` (AUTH/AUTHZ/SSRF/SCAN/DATA/INP/OPS) |
| Risk-ranked backlog | `docs/known-issues.md` (ranked) + `docs/PROGRESS.md` |
| Test strategy | `docs/TESTING.md` |

**Verification**

```bash
grep -c "^|" docs/THREAT_MODEL.md       # threat rows
grep -c "^| SSRF-" docs/SECURITY_REQUIREMENTS.md
```

Every abuse case in the threat model names a control and a test file. The four abuse cases
the specification calls out explicitly are all present with a test:

| Abuse case | Control | Test |
|---|---|---|
| SSRF through target URLs | `urlguard.canonicalize` + blocklists | `test_urlguard.py` (80 tests) |
| Redirect / DNS rebinding | pinned socket + same-origin redirect policy | `test_safe_http.py` (46 tests) |
| `$ref` / XML / YAML bombs | `parsers.safe_*` with DTD/entity/alias/depth caps | `test_parsers.py` |
| Resource exhaustion | budgets, size caps, circuit breaker | `test_safe_http.py`, `test_scope_validator.py` |
| XSS through scanned content | escaping in exports, CSP, React text rendering | `test_api_scan_objects.py::test_html_export_escapes_untrusted_values` |
| Scanner used as an attack tool | attestation, approval, scope policy, kill switch, read-only methods | `test_api_targets_inventory.py`, `test_api_authz.py` |

**Result: PASS.** Assumptions recorded rather than asked: single-tenant-per-deployment
styling of the demo, no email delivery (invitations are link-based), SQLite storage.
