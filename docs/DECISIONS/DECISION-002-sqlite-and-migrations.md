# DECISION-002 — SQLite with forward-only SQL migrations

**Status:** accepted · **Date:** 2026-10 · **Supersedes:** none

## Context

The product needs durable multi-tenant storage for targets, scans, endpoints, sources,
observations, findings, triage and audit events. The deployment target is a single VM behind
nginx (see `deploy/`). A Postgres dependency would add an operational component that the
acceptance criteria do not require, and would make the "clone and run" story worse.

## Decision

SQLite in WAL mode, with plain `.sql` files in `backend/app/migrations/` applied in filename
order by `db.apply_migrations`, tracked in `schema_migrations`. Migrations are forward-only
and never edited after being applied; corrections arrive as new files (see `0003`, which
added `scan_endpoints.response_status`).

Tenant isolation is enforced in queries (`WHERE org_id = ?`) plus a `scoped()` helper that
refuses to read a table that is not on its allow-list, so a missing `org_id` clause surfaces
as a `ValueError` in tests rather than a data leak.

## Consequences

* Single-writer concurrency. With one worker process and short transactions this is fine;
  long scans do not hold a transaction open.
* `GROUP_CONCAT` is used for source-type roll-ups — SQLite-specific, so a Postgres port
  needs a rewrite of a handful of queries.
* Tests are superb: a fresh database per test in `tmp_path` costs milliseconds, which is why
  the suite can afford 333 tests.
* Audit tables use triggers to reject `UPDATE`/`DELETE`, so tampering fails at the storage
  layer rather than relying on application code.

## Revisit if

We need concurrent writers beyond one node, or scans larger than memory. Then move to
Postgres, keep the SQL-migration style, and port the SQLite-specific queries.
