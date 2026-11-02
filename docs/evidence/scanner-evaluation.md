# Scanner evaluation against ShadowLab ground truth

- Scan: `c48b947ab79745be85a92bf87ba5abf9` (completed, partial=False)
- Shadow endpoints: recall **76.9%** (30/39), precision **96.8%** (30/31)
- Planted findings detected: **6/19** (31.6%)
- Negative controls passed: **5/5**
- Hostile traps handled: **12/12**
- Discovery sources used: **10** (meets the five-source minimum)

## Discovery sources

| Source | Endpoints contributed |
|---|---|
| html | 27 |
| crawler | 18 |
| openapi | 10 |
| javascript | 7 |
| har | 3 |
| docs | 2 |
| graphql | 2 |
| postman | 2 |
| source_map | 2 |
| sitemap | 1 |

## Reconciliation

- Baseline operations: 8 documented, observed 7
- Shadow: 31 observed of 39 planted
- Zombies: 0 reported of 1 planted

## Per-rule detection

| Rule | Planted endpoint | Detected | Findings |
|---|---|---|---|
| ST-001 | `GET /api/internal/export` | yes | 1 |
| ST-001 | `GET /api/admin/backup` | yes | 1 |
| ST-001 | `GET /api/internal/tokens` | yes | 1 |
| ST-002 | `GET /api/v1/orders` | NO | 0 |
| ST-004 | `GET /openapi.json` | yes | 1 |
| ST-005 | `GET /graphql` | NO | 0 |
| ST-006 | `GET /api/v2/profile` | NO | 0 |
| ST-007 | `GET /api/admin/backup` | NO | 0 |
| ST-008 | `GET /api/v2/orders` | NO | 0 |
| ST-009 | `GET /api/v1/orders` | NO | 0 |
| ST-012 | `GET /api/v1/orders` | NO | 0 |
| ST-014 | `GET /static/app.js.map` | yes | 2 |
| ST-016 | `GET /api/v2/reports` | NO | 0 |
| ST-017 | `GET /st-nonexistent` | yes | 1 |
| ST-018 | `GET /lab/api/cookies/session` | NO | 0 |
| ST-020 | `GET /lab/api/sqli/product` | NO | 0 |
| ST-021 | `GET /lab/api/files/download` | NO | 0 |
| ST-023 | `GET /lab/api/idor/account/{param}` | NO | 0 |
| ST-013 | `GET /lab/api/headers/ping` | NO | 0 |

## Missing shadow endpoints

- `GET /lab/api/errors/checkout`
- `GET /lab/api/input/quantity`
- `GET /lab/api/redirect`
- `GET /lab/transport/checkout`
- `GET /redoc`
- `GET /swagger-ui.html`
- `POST /api/v1/wishlist`
- `POST /graphql`
- `POST /lab/upload`

## Unexpected (not in ground truth)

- `GET /healthz`

## Negative controls

| Control | Expected | Findings | Pass |
|---|---|---|---|
| `/api/v2/secure` | no finding | 0 | yes |
| `/api/v1/health` | no finding | 0 | yes |
| `/api/v1/decoy-only-in-comment` | not discovered | 0 | yes |
| `/api/v1/decoy-in-prose` | no finding | 0 | yes |
| `/does-not-exist-*` | not reported as live | 0 | yes |

## Hostile traps

| Trap | Expected | Handled |
|---|---|---|
| `/redirect-metadata` | blocked, not followed | yes |
| `/redirect-loopback` | blocked, not followed | yes |
| `/redirect-loop` | blocked after hop limit | yes |
| `/redirect-cross-origin` | blocked | yes |
| `/bomb.gz` | response size aborted | yes |
| `/endless` | response size aborted | yes |
| `/huge-headers` | header limits enforced | yes |
| `/big.js` | response size aborted | yes |
| `/nested.json` | nesting rejected | yes |
| `/spec-remote-ref.json` | remote $ref refused | yes |
| `/sitemap-bomb.xml` | entity expansion refused | yes |
| `/slow` | timeout enforced | yes |

## Validation status vs ground truth

| Endpoint | Expected | Observed |
|---|---|---|
| `GET /api/v1/legacy/users` | live | live |
| `GET /api/internal/export` | live | live |
| `GET /api/v1/secret-report` | live | live |
| `GET /api/legacy/checkout` | live | live |
| `GET /api/internal/shipments` | live | live |
| `GET /api/v1/invoices/{param}` | live | live |
| `GET /api/v1/partners` | live | live |
| `GET /api/v1/partners/{param}/invoices` | live | live |
| `GET /api/v1/legacy/orders` | live | live |
| `GET /api/v1/customers/{param}` | live | live |
| `GET /api/internal/audit-log` | live | live |
| `POST /api/v1/wishlist` | unvalidated | unvalidated |
| `GET /api/v1/users` | live | live |
| `GET /api/v1/reports/summary` | live | live |
| `GET /api/admin/backup` | live | live |
| `GET /api/internal/tokens` | live | live |
| `GET /api/v1/debug/config` | live | live |
| `GET /graphql` | live | live |
| `GET /openapi.json` | live | live |
| `GET /swagger-ui.html` | live | live |
| `GET /api-docs.json` | live | live |
| `GET /redoc` | live | missing |
| `GET /api/v1/remote` | live | live |
| `POST /graphql` | unvalidated | unvalidated |
| `GET /lab/api/cookies/session` | live | live |
| `GET /lab/api/errors/checkout` | error | error |
| `GET /lab/api/cors/profile` | live | live |
| `GET /lab/api/xss/echo` | live | live |
| `GET /lab/api/sqli/product` | live | live |
| `GET /lab/api/files/download` | live | not_found |
| `GET /lab/api/idor/account/{param}` | live | not_found |
| `GET /lab/api/auth/admin-panel` | live | live |
| `GET /lab/api/redirect` | live | not_found |
| `GET /lab/api/api-keys/export` | live | live |
| `GET /lab/api/input/quantity` | live | missing |
| `GET /lab/api/diagnostics/env` | live | live |
| `GET /lab/transport/checkout` | live | live |
| `POST /lab/upload` | unvalidated | unvalidated |
| `GET /lab/api/headers/ping` | live | live |

Full structured data: `scanner-evaluation.json`.
