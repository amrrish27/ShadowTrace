# DECISION-007 — Authentication stays in the local SQLite database; no Supabase

**Status:** accepted by the project owner, 2026-10-28 · **Supersedes:** none

## Context

The owner expected credentials to be stored "in a database such as Supabase" and asked whether
accounts should be created there. The build has no Supabase (or any hosted Postgres) integration:
`grep -rniE "supabase|postgrest|service_role|anon_key"` returns two prose mentions only
(`README.md`, `docs/known-issues.md` A11). Authentication is the SQLite `users` table, passwords
are argon2id (`backend/app/security/passwords.py`), and the session is an httpOnly cookie plus a
CSRF token.

The alternatives were put to the owner as an explicit choice — keep SQLite, or port as a separate
tested change, or explain the trade-offs first. The owner chose **keep local SQLite auth**.

## Decision

Authentication remains in the local SQLite database. No migration is planned, and no Supabase key,
client or schema is added to this tree. Accounts are created by `python -m app.cli create-admin`
(on a fresh database, bootstrap does it) and recovered by `python -m app.cli reset-password`,
both offline operations with no HTTP equivalent.

## Consequences

* The stack stays a single self-contained VM/compose deployment: no network dependency on the
  authentication path, no hosted credential to leak from the API environment, no service-role key
  that could ever reach the frontend bundle.
* Passwords cannot be read back by anyone, an administrator must not be able to set another
  person's password, and the recovery path is an offline CLI on the host. That remains true.
* **Cost:** accounts do not follow the user across machines, there is no central user directory,
  and an administrator who loses host access loses the accounts with it. A multi-tenant or
  multi-host deployment would need this decision revisited.
* The earlier expectation of Supabase is now closed rather than pending; `docs/known-issues.md` A11
  already states that this build must not be pointed at one.

## What would make us revisit it

A second host serving the same accounts, an operator requirement for SSO, or an audit finding that
requires independent credential custody. Any of those turns this into DECISION-008 with the full
port: replace the connection factory and `?` placeholders, convert the four migrations to Postgres
DDL, move password verification behind the same `passwords.py` interface, and run the entire suite
against a real server before anything ships.
