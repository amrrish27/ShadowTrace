# DECISION-001 — All outbound traffic goes through one `SafeHttpClient`

**Status:** accepted · **Date:** 2026-10 · **Supersedes:** none

## Context

The scanner makes requests to customer-controlled hosts. That makes SSRF the single largest
risk in the product: one careless `requests.get(user_url)` anywhere in the codebase is a
metadata-service read or a pivot into the internal network. Review discipline alone does not
scale, because the risky call will be added by someone who is in a hurry.

## Decision

Exactly one class performs network I/O: `backend/app/engine/safe_http.py::SafeHttpClient`.
It owns scheme/port/host validation, DNS resolution, IP pinning, redirect policy, header and
body size caps, decompression caps, timeouts, the kill switch, cancellation checks and the
request budget. Every other module receives a client instance.

The rule is enforced two ways:

1. `make egress` (and the CI gate) greps `backend/app` for `requests`, `httpx`, `urllib.request`,
   `http.client`, `aiohttp` and `urllib3`, excluding only `safe_http.py`. A violation fails
   the build. The gate itself is verified to fail when an `import requests` is planted.
2. The same class is the only place that resolves DNS, so a rebinding attack has a single
   place to defend (the socket is connected to the *validated* IP, and `Host`/SNI are set
   explicitly).

## Consequences

* Every new fetcher must be written as a call on a passed-in client — a deliberate speed
  bump in exchange for one auditable egress point.
* The client is stateful (budget, circuit-breaker counters), so tests inject a stub client
  rather than monkeypatching sockets. That is why `test_crawler.py` uses a fake client with
  exact-then-longest-prefix routing: it exercises the real call sites without touching a
  socket.
* A future async engine would need an async variant. The fake-client tests would keep
  working because they depend on the protocol, not the implementation.

## Revisit if

We add a second network egress (for example SMTP for notifications). Then the gate must be
narrowed to "scanner egress" rather than "all egress", and the new path needs its own
validated allow-list.
