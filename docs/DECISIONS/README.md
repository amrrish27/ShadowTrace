# Architecture decision records

One file per decision that would be expensive to reverse. Each record states the context,
the decision, the consequences, and what would make us revisit it.

| ID | Decision | Status |
|---|---|---|
| [001](DECISION-001-egress-single-choke-point.md) | All outbound traffic goes through one `SafeHttpClient` | accepted |
| [002](DECISION-002-sqlite-and-migrations.md) | SQLite with forward-only SQL migrations | accepted |
| [003](DECISION-003-fingerprint-identity.md) | Endpoint identity is a method+path-template fingerprint | accepted |
| [004](DECISION-004-static-extraction-not-execution.md) | JavaScript is parsed, never executed | accepted |
| [005](DECISION-005-subprocess-worker.md) | The scanner runs in the API process behind an in-process queue | accepted (with limits) |
| [006](DECISION-006-evidence-linked-claims.md) | Every claim in the docs links to a generated artefact | accepted |
| [007](DECISION-007-auth-stays-in-sqlite.md) | Authentication stays in local SQLite; no Supabase | accepted (owner, 2026-10-28) |
