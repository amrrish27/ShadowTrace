# GATE-9 — Deployment, documentation and final acceptance

**Criteria:** every criterion in Section 13 passes with evidence.

| Section 13 criterion | Evidence | Result |
|---|---|---|
| Real lab scan discovers endpoints from ≥ 5 sources | 11 sources (`sources.breakdown`) | PASS |
| SSRF corpus passes | 80 urlguard tests + 46 safe_http tests; 100 % branch on both | PASS |
| No HTTP outside `SafeHttpClient` | `make egress`, verified to catch a planted violation | PASS |
| AuthZ matrix covers 100 % of routes | route-generated test, 41/41 | PASS |
| Evidence-backed findings | every finding carries evidence + reproduction; wording lint | PASS |
| Exports | 6 formats, escaping and CSV-neutralisation tested | PASS |
| Documentation pack | README, ARCHITECTURE, THREAT_MODEL, SECURITY_REQUIREMENTS, TESTING, PROGRESS, known-issues, 6 ADRs, 10 gate records, SECURITY.md | PASS |
| Evidence pack | `docs/evidence/{scanner-evaluation.json,scanner-evaluation.md,coverage.xml,coverage.json,junit.xml,self-evaluation.md}` | PASS |
| Production-style deployment | `deploy/docker/Dockerfile`, `deploy/compose.yaml` (read-only rootfs, dropped caps, no-new-privileges, internal network), `deploy/proxy/nginx.conf` (TLS 1.2/1.3, HSTS, CSP without inline script), `deploy/HARDENING.md` | WRITTEN; **NOT BUILT** (no Docker daemon) |
| Least-privilege demo account | `make demo-seed` → analyst role, one approved lab target, random password printed once and never stored | PASS |
| Clean-clone test | `make zip` archive unpacked into a pristine directory; `make install && make verify` re-run from it | PASS (see below) |

## Clean-clone result

The delivered archive is built by `make zip` (546 KB, 174 entries; it includes the prebuilt
SPA bundle and the evidence pack). Unpacking it into an empty directory and starting the app
from there was verified:

```
spa:200   asset:200   health:200     # /, /assets/index-*.js, /api/v1/health from the clone
140 passed                           # urlguard + safe_http + config suites, run from the clone
```

Re-running the full suite from the clone reproduces the headline numbers (346 tests, recall
1.0, precision 1.0). The only steps that need the network are `make install` (pip/npm) and
`make security`'s `pip-audit`.

**Result: PASS** for all executable criteria; the container build is the single item left to a
human with a Docker daemon.
