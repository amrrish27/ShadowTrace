# GATE-5 — Validation and analysis engine

**Criteria:** every rule has positive and negative tests; ground-truth findings are detected
and negative controls are not flagged; no finding can exist without evidence; redaction tests
prove secrets never reach the database, logs or exports.

| Criterion | Evidence | Result |
|---|---|---|
| Rule registry (16 rules) with positive tests | `test_reconciler_rules.py` (per-rule cases) + `rules` 16/16 in the evaluation | PASS |
| Negative controls not flagged | 5/5 (`negative_controls` in `scanner-evaluation.json`) | PASS |
| No finding without evidence | `rules.finalize_hit` requires `evidence`; `test_scan_integration.py::test_real_scan_completes_with_evidence` asserts every finding has non-empty evidence + reproduction | PASS |
| Wording lint | `CERTAINTY_PHRASES` rejects "proven"/"exploitable"/"vulnerable" without `confirmation_basis`; asserted in `test_reconciler_rules.py` | PASS |
| Redaction before storage | `test_security_helpers.py::test_redaction_masks_well_known_secret_shapes`, `test_secret_rule_redacts_the_value`; HAR import redacts request headers (`test_har_import_filters_scope_and_redacts`) | PASS |
| Secrets never in logs | `audit_redact` + structured logger tests (`test_audit_redaction_never_leaks_values`) | PASS |
| Secrets never in exports | `test_api_scan_objects.py` export assertions (JSON/CSV/Markdown/HTML) | PASS |
| Safe validator | method allow-list, budgets, backoff, circuit breaker, soft-404 (`test_scope_validator.py`) | PASS |
| Risk scoring | `clamp(base + 12·confidence + 4·exposure)` with three pinned examples | PASS |

**Result: PASS.**
