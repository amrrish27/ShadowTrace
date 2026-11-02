# DECISION-006 — Every claim in the documentation links to a generated artefact

**Status:** accepted · **Date:** 2026-10 · **Supersedes:** none

## Context

Security tooling is full of unfalsifiable claims: "high coverage", "no SSRF", "production
ready". A reviewer cannot check any of them, and the claims rot the moment the code changes.

## Decision

Numbers in `README.md`, `docs/TESTING.md` and `docs/gates/` are quoted from files that a
command regenerates:

* scanner metrics → `docs/evidence/scanner-evaluation.json`, produced by `scripts/evaluate.py`
  with a `--strict` gate that fails the build unless recall/precision are 1.0, all rules fire,
  all negative controls stay silent, all traps are handled, and ≥ 5 sources contribute;
* test and coverage numbers → `docs/evidence/junit.xml` and `coverage.xml`, written by
  `make test-backend` with a coverage floor;
* static analysis → `make security` (bandit + pip-audit), which CI runs on every push.

Where something was not executed (Docker, ZAP, Trivy, Playwright), the documentation says so
in `docs/known-issues.md` and gives the exact command a human should run.

## Consequences

* CI can fail on a *documentation* drift, which is the point.
* The scanner job in CI re-runs the lab scan, so the headline numbers cannot be from an
  older code state.
* Every limitation is written down with its blast radius instead of being omitted — the
  gate records deliberately contain "not verified" rows.

## Revisit if

Never, in spirit. The mechanics may change (a report generator writing the Markdown table),
but a claim without an artefact stays unacceptable.
