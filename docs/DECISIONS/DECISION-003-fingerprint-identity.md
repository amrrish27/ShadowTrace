# DECISION-003 — Endpoint identity is a method+path-template fingerprint

**Status:** accepted · **Date:** 2026-10 · **Supersedes:** none

## Context

The same endpoint is seen many times: in an OpenAPI document, in a JS bundle, in a HAR, in a
sitemap, by a live probe. It also appears in every scan of the same target. We need one
identity that (a) collapses those observations, (b) survives a re-scan, and (c) stays stable
when ids change.

## Decision

`fingerprint = METHOD|host|path_template|query_template`, where path segments that look like
ids or uuids are normalised to `{id}` and query values to `{param}`. Rules that need scan
level context (ST-009 auth-required shadow, ST-012 documented-but-missing) are evaluated in
`scan_rules.py` against the baseline and the observed set, not per endpoint.

Per-scan facts (was this endpoint live *in this scan*?) live on `scan_endpoints`, never on
`endpoints`. `compare_with_previous` reads
`COALESCE(scan_endpoints.response_status, endpoints.response_status)`.

## Consequences

* Findings and triage are keyed on the fingerprint, so triage survives renames and re-scans.
  That is the behaviour an analyst expects: "I marked this a false positive last month".
* Two genuinely different endpoints that differ only by id (`/users/1` vs `/users/2`) collapse
  into one row, which is intended: they are the same route.
* The early version of the lifecycle test failed with a UNIQUE violation because a second
  scan tried to insert a duplicate `endpoints` row. The fix was not a schema workaround but
  the realisation that status is per scan — recorded here because the failure mode is easy to
  reintroduce.

## Revisit if

We support API versioning in the path (`/v2/users` today already produces a distinct
fingerprint, which is correct) or want to distinguish hosts that serve the same path on
different ports — currently host+port are part of the scope, not the fingerprint.
