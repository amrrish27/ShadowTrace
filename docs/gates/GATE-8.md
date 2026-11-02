# GATE-8 — Hardening and adversarial verification

**Criteria:** zero unresolved High/Critical issues; triage log complete; no unmapped threat in
the traceability matrix; the self-audit finds no undocumented routes.

| Activity | Tool | Result |
|---|---|---|
| SAST | `bandit -r backend/app` | **0 findings** (18 justified `# nosec` annotations, each with a rationale comment) |
| Dependency audit | `pip-audit -r requirements.txt` | no known vulnerabilities in the pinned set |
| Frontend dependency audit | `npm audit` — not run (offline registry) | **NOT RUN** |
| Container scan | Trivy/Grype | **NOT RUN** — no Docker daemon; command in `docs/known-issues.md` |
| DAST baseline | OWASP ZAP | **NOT RUN** — ZAP not installed; command in `docs/known-issues.md` |
| Manual trust-boundary review | `docs/THREAT_MODEL.md` mapped to controls + tests | complete: every abuse case has a control and a test |
| Self-audit | ShadowTrace scanning its own lab with the same rules, plus a route diff (`routes` vs `ROUTE_POLICY`) | 41 routes, 0 undocumented; scanner finds only the deliberately planted lab issues |
| Triage log | every finding of the self-scan reviewed; no High or Critical | complete |
| Training-app scan (Juice Shop / crAPI) | optional in the specification | not performed — no network |

**Result: PARTIAL.** Every offline check is clean and zero High/Critical issues remain
unresolved; three dynamic scanners could not run here and are documented rather than claimed.
