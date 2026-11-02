# GATE-4 — Discovery engine

**Criteria:** unit tests on realistic fixtures; robustness tests on every parser (malformed,
huge, deeply nested, hostile) with time limits; discovery on the lab meets the recall target;
no target JavaScript is ever executed; ReDoS tests pass.

| Criterion | Evidence | Result |
|---|---|---|
| Realistic fixtures | `lab/fixtures/shadowlab.har`, live lab pages, spec fixtures in `test_extractors.py` | PASS |
| Parser robustness | `test_parsers.py`: DTD, external entities, billion laughs, YAML alias bombs, JSON/XML depth, size caps, invalid UTF-8 | PASS |
| **Hypothesis / fuzzing** | Hypothesis is not installed in this offline environment; the property tests are replaced by explicit adversarial corpora with time caps | **PARTIAL** — documented in `docs/known-issues.md` with the command to add it |
| Recall on the lab | recall 1.0, precision 1.0, 24/24 shadow endpoints, `missing: []`, `unexpected: []` | PASS |
| No JavaScript execution | `test_crawler.py::test_inline_script_is_parsed_without_execution`; there is no JS engine or browser in the dependency tree (`grep -r playwright backend` is empty) | PASS |
| ReDoS safety | every regex in `engine/extractors/` is a literal-prefix or character-class pattern; `test_extractors.py` feeds 200 kB adversarial strings and asserts completion under the fixture timeout | PASS |
| 11 discovery sources on one scan | `docs/evidence/scanner-evaluation.json → sources.breakdown` | PASS (spec minimum: 5) |
| Soft-404 handling | `test_scan_validator.py::test_soft_404_detects_and_matches_catch_all_shell` | PASS |

**Result: PASS**, with the Hypothesis substitution recorded as the one deviation.
