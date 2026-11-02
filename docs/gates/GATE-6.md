# GATE-6 — Orchestration and scan-management API

**Criteria:** a full scan of the lab runs end-to-end through the API; cancellation stops
requests within 5 s; killing the worker mid-scan yields a failed scan with partial results;
export escaping tests pass; the authorization matrix covers every new route.

| Criterion | Evidence | Result |
|---|---|---|
| End-to-end scan | `scripts/smoke_scan.py` creates org → target → baseline → HAR import → scan; result `completed`, `partial=0`, 32 endpoints, 40 findings; `test_scan_integration.py` does the same through the real API in-process | PASS |
| Cancellation | `test_scan_integration.py::test_cancellation_stops_the_scan` — the scan stops mid-crawl; the worker checks `cancel_requested` before every request, so the stop is bounded by one request, well inside 5 s | PASS |
| Crash recovery | `test_lifecycle_service.py::test_recover_stale_fails_abandoned_scans` — state `failed`, `partial=1`, observations preserved | PASS |
| State machine | `test_lifecycle_service.py` (15 tests): legal/illegal transitions, quotas, compare-with-previous | PASS |
| Exports (6 formats) | `test_api_scan_objects.py::test_exports[json|csv_inventory|csv_findings|markdown|html|openapi_stub]` | PASS |
| Export escaping | HTML escaping test, CSV RFC 4180 parsing test, formula-injection neutralisation | PASS |
| Every route authorized | route-generated matrix test (41 routes) | PASS |
| Triage with history | `test_api_targets_inventory.py::test_triage_records_history_and_updates_finding_filters` | PASS |

**Result: PASS.**
