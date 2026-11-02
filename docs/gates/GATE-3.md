# GATE-3 — Lab target and ground truth

**Criteria:** the lab starts with one command, runs only on an isolated network with
synthetic data, and its ground truth has been reviewed line by line against its code.

| Criterion | Evidence | Result |
|---|---|---|
| Starts with one command | `make lab` → `python3 lab/app/lab.py --port 8099`; `GET /health` returns 200 | PASS |
| Loopback only | binds `127.0.0.1`; the scanner needs `ST_PRIVATE_ALLOWLIST=127.0.0.1:8099` to reach it, so it cannot be scanned by accident | PASS |
| Synthetic data only | `lab/app/baseline.json` + `lab/ground_truth.json` are hand-written fixtures; no real host data | PASS |
| Ground truth reviewed against the code | `lab/ground_truth.json` lists 24 shadow endpoints, 1 zombie, 16 planted rules, 5 negative controls and 12 hostile traps; each entry names the lab route that implements it, and `docs/evidence/scanner-evaluation.md` shows the 1:1 match (`missing: []`, `unexpected: []`) | PASS |
| Hostile content present | SSRF redirects, gzip bomb, redirect loop, slow endpoint, JS with concatenated literals, source map, sitemap, GraphQL, HAR, Postman, OpenAPI 2 & 3, Swagger UI, Redoc, docs page | PASS |

**Result: PASS.** The lab is the only target the automated suite ever scans.
