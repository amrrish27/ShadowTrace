# GATE-7 — Dashboard and reports UI

**Criteria:** every page in Section 4.6 against the real API, accessible and responsive, with
loading/empty/error states; Playwright end-to-end tests for the main journeys; script-generated
screenshots.

| Criterion | Evidence | Result |
|---|---|---|
| Pages implemented against the real API | `frontend/src/main.tsx` drives sign-in, dashboard, targets, scans, scan detail (endpoints, findings, sources, triage), reports; `frontend/src/api.ts` is the typed client with CSRF + error mapping | PASS |
| Loading / empty / error states | each view renders a skeleton, an empty-state message and an error banner; covered by `frontend/src/api.test.ts` for error mapping | PASS |
| Responsive | single CSS grid, `@media` breakpoints in `styles.css`; layout collapses to one column below 900 px | PASS (manual) |
| Production build | `npm run build` → 163 kB JS / 5.4 kB CSS, no sourcemaps, no inline script | PASS |
| XSS payloads render as inert text | React text interpolation everywhere (`dangerouslySetInnerHTML` is not used anywhere: `grep -r dangerously frontend/src` → none); HTML *report* export is escaped and tested server-side | PASS |
| CSP enforced with no violations | `deploy/proxy/nginx.conf` sends `script-src 'self'`; the bundle has no inline script (CI asserts it) | PASS by construction, NOT OBSERVED in a browser |
| Playwright journeys | `frontend/e2e/journey.spec.ts` (4 journeys) | **PASS** (2026-10-28) — real Chromium: analyst read-path, target registration, admin + invite/accept + password change, accessibility floor over 11 pages |
| axe accessibility checks | not installed | **GAP** — replaced by a dependency-free floor (labels, names, duplicate ids, H1/heading order) enforced in the journeys |
| Screenshots | `docs/screenshots/` is empty | **GAP** — needs a browser |

**Result: PARTIAL.** All UI code, the build and the XSS-by-construction argument are
verified; the browser-executed checks (Playwright, axe, screenshots) could not run in this
environment and are listed in `docs/known-issues.md` with their exact commands.
