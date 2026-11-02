# DECISION-004 — JavaScript is parsed, never executed

**Status:** accepted · **Date:** 2026-10 · **Supersedes:** none

## Context

SPA route tables and API clients live in JavaScript. The obvious way to enumerate them is a
headless browser: load the page, let it run, watch the network. That is also the riskiest
option: we would be executing attacker-controlled code on our own host, and a browser
sandbox is a large attack surface we do not control.

## Decision

Scripts are fetched as bytes and parsed as data with a linear-time tokenizer that:

* extracts string literals, `fetch(`/`axios.`/`XMLHttpRequest.open`/`$.ajax` call shapes, and
  route-table literals;
* joins adjacent concatenated literals and normalises `${...}` template placeholders to
  `{param}`;
* never evaluates anything, never runs a JS engine, and never follows a computed URL.

Source maps are followed only when same-origin and in scope, and only to recover source
paths (a source map that points off-host is recorded as an external reference).

## Consequences

* Lower recall than a browser on heavily dynamic code (URLs assembled at runtime from
  variables are invisible). The lab reflects this: `requests_used` 75 for a scan that
  discovers 32 endpoints, which is roughly what steady-state production looks like.
* No browser dependency, no sandbox to escape, and scan cost is bounded by bytes rather than
  by render time.
* `test_crawler.py` asserts that an inline script containing `fetch('/api/x')` yields the
  endpoint **and** that the script body is not executed — the test would fail if someone
  introduced an evaluator.

## Revisit if

Recall on real SPAs proves insufficient. Then add a browser worker as an *optional,
separately sandboxed* discovery source that feeds the same `ExtractionResult` pipeline —
never in-process, and its findings tagged so the difference stays visible.
