# GATE-2 — Safe-scanning core

**Criteria:** the SSRF corpus passes with ≥ 95 % branch coverage on the client, URL normaliser
and scope policy; a code search finds no outbound HTTP outside `SafeHttpClient`; rate-limit
and budget tests pass against a counting test server.

| Criterion | Evidence | Result |
|---|---|---|
| SSRF corpus | `backend/tests/test_urlguard.py` — 80 tests: schemes, userinfo, backslash, control chars, whitespace, numeric-host forms (decimal/octal/hex), IPv4 & IPv6 blocklists, embedded IPv4 (mapped/NAT64/6to4/Teredo), metadata names, port policy, canonicalisation, redirect targets | PASS |
| Branch coverage, `safe_http.py` | **100 %** line / **100 %** branch | PASS (≥95 %) |
| Branch coverage, `urlguard.py` | 98.0 % line / **100 %** branch | PASS (≥95 %) |
| Branch coverage, `scope.py` | 98.1 % line / **95.8 %** branch | PASS (≥95 %) |
| No outbound HTTP outside the client | `make egress` → "egress policy: only SafeHttpClient performs network I/O"; the gate was verified to fail when `import requests` is planted | PASS |
| Budget and rate limits against a counting server | `test_budget_is_enforced`, `test_client_without_scope_or_budget_still_validates_the_destination`, `_throttle` tests | PASS |
| Ownership verification, admin approval, attestation | `test_api_targets_inventory.py::test_ownership_target_stays_pending_until_an_admin_approves`, `test_target_verification_succeeds_only_with_the_issued_token` | PASS |
| Kill switch | `test_kill_switch_blocks_all_requests`, `test_scanning_kill_switch_blocks_scan_creation` | PASS |

**Result: PASS.** Counts: 126 tests across the three egress modules alone.
