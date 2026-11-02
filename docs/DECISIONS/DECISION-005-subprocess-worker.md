# DECISION-005 — The scanner runs in a separate worker process behind a database queue

**Status:** accepted, with known limits · **Date:** 2026-10 · **Supersedes:** none

## Context

A scan can take minutes. It must not block a request, must survive a restart, and must be
cancellable. The textbook answer is a broker (Redis/Celery) plus a worker fleet. The
deployment target is one small VM (or one compose stack), not a fleet.

## Decision

`backend/app/workers/worker.py` polls the `scans` table for `queued` rows (and for stale
leases), promotes them to `running`, and executes `Scanner` synchronously. It is started as
a separate process in compose (`python -m app.workers.worker`), sharing the SQLite file with
the API. Cancellation is cooperative: the API sets `cancel_requested`, the worker checks it
before every request.

Resilience: `worker_lease_seconds` bounds how long a `running` scan may hold a claim;
`recover_stale()` fails abandoned scans with `partial = 1` and preserves every observation
collected so far.

The API process **never** runs a scan itself: it validates the request and inserts a
`queued` row. A scan created through the UI therefore stays `queued` until a worker is
running (`python -m app.workers.worker`, or `docker compose up -d worker`). This is the
one piece of operational knowledge that is easy to miss, so the README quick start starts
both processes and `known-issues.md` C12 records the failure mode.

The worker writes scan events and progress counters as their own short transactions
(`workers/worker.py: record_event` / `record_progress`). Leaving them uncommitted would hold SQLite's
write lock for the whole scan, and the API — which shares the file — would then fail with
`database is locked` on its own writes (reproduced against a slow target in round 7).

## Consequences

* No broker to operate; the demo is two commands (API + worker) or one
  `docker compose up -d`.
* Throughput is one scan at a time per worker process; `scan_concurrency_per_org` and
  `scans_per_day_per_org` quotas keep the queue honest.
* A crashed worker delays recovery until the lease expires.
* `services/scans.py` contains the entire state machine, so a future move to a real queue
  only needs the poller replaced — the transitions, audit events and quotas stay.

## Revisit if

Queue depth regularly exceeds a few minutes, or we need horizontal scale. Then swap the
poller for a broker-backed consumer and keep `transition()` as the single writer of state.
