# Deployment and hardening

Two supported shapes: a single VM with Docker Compose behind nginx (below), or the same
image run directly under systemd with nginx in front. Both assume TLS terminates at the proxy.

## 1. Files

```
deploy/
  docker/Dockerfile      multi-stage: node builds the SPA, python runs the API
  compose.yaml           api + worker + proxy, read-only rootfs, dropped caps
  proxy/nginx.conf       TLS 1.2/1.3, HSTS, CSP (script-src 'self'), rate limiting
  HARDENING.md           this file
```

## 2. Configure

```bash
cd deploy
cp ../.env.example .env
```

Edit every value marked `CHANGE-ME`:

| Variable | Why it matters |
|---|---|
| `ST_SECRET_KEY` | signs sessions; ≥ 32 chars, generated with `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
| `ST_BASE_URL` | must be `https://…` in production; used in invitation links and CSP reports |
| `ST_ALLOWED_HOSTS` | comma-separated, explicit. `*` is refused in production |
| `ST_CORS_ORIGINS` | the exact SPA origin; `*` is refused in production |
| `ST_COOKIE_SECURE` | must stay `true` in production |
| `ST_PRIVATE_ALLOWLIST` | **empty in production** unless you intentionally scan a lab. Every entry widens egress |
| `ST_MAX_REQUESTS_HARD_CAP` / `ST_MAX_PAGES_HARD_CAP` / `ST_MAX_SCAN_SECONDS_HARD_CAP` | hard ceilings; the per-scan values in the API cannot exceed them |
| `ST_SCANNING_ENABLED` | kill switch; `false` blocks scan creation and all outbound requests. The unprefixed `SCANNING_ENABLED` is accepted as a deprecated fallback and logs a warning |
| `ST_TRUSTED_PROXIES` | who may set `X-Forwarded-For`: the proxy's address (`172.30.0.2` in the bundled compose file) or its subnet. Never a value a client can reach |
| `ST_BOOTSTRAP_ADMIN_EMAIL` / `..._PASSWORD` | first-run admin only; delete these variables after the first login |

The process **refuses to start** in production with a weak or default secret, an insecure
cookie, a wildcard host/CORS list, an `http://` base URL or demo mode enabled (see
`app/config.py::_validate`, covered by `tests/test_config.py`).

## 3. Certificates

Put `fullchain.pem` and `privkey.pem` in `deploy/proxy/certs/` (owned `root:root`, mode `600`),
or point nginx at your ACME path. `ssl_stapling` is on; if your CA does not support OCSP the
directive is ignored harmlessly.

## 4. Start

```bash
docker compose up -d --build
docker compose ps                     # api and worker must report (healthy)
curl -fsS https://shadowtrace.example.com/api/v1/health
```

The healthcheck hits `/api/v1/health` from inside the container, so it also proves the SPA
files and the database are reachable.

## 5. First-run checklist

1. Sign in with the bootstrap admin, then **delete** `ST_BOOTSTRAP_ADMIN_*` from `.env` and
   restart: `docker compose up -d api`.
2. Change the admin password (the UI requires the current password; sessions rotate).
3. Invite analysts (`analyst`) and viewers (`viewer`). Viewers are read-only by policy.
4. Register a target: base URL, authorized ports, attestation text. `ownership` targets stay
   `pending` until an admin approves them or the `.well-known/shadowtrace-verification.txt`
   challenge succeeds. `lab_allowlist` targets require `(host, port)` in
   `ST_PRIVATE_ALLOWLIST` and are approved immediately — use them only on isolated networks.
   A private or loopback host is refused at creation (`422 invalid_target`) **for every
   authorization mode** unless `ST_PRIVATE_ALLOWLIST` lists its `host:port`; an admin
   self-approving a target does not make it reachable. Declaring ports on the target
   authorizes those ports only, never a private address. Cloud-metadata and link-local
   names/addresses cannot be allow-listed at all.
5. Create a scan with an `Idempotency-Key` header; the API returns the same scan for a
   repeated key inside the window.

## 6. Hardening already applied

| Layer | Control |
|---|---|
| Container | non-root user (uid 1001), `read_only` rootfs with a `tmpfs` for `/tmp`, `cap_drop: ALL`, `no-new-privileges`, no published ports except the proxy |
| Network | app tier on an `internal: true` network (no route to the internet); only the proxy is on the edge network; the worker alone has an egress network (§6.1) |
| Proxy | TLS 1.2/1.3, HSTS 2 years, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP, Permissions-Policy, CSP with `script-src 'self'` and `frame-ancestors 'none'`, `server_tokens off`, 30 r/s per-IP burst limit |
| Application | security headers on every response, request-id propagation, host allow-list, 8 MiB body cap, CSRF on every mutation, per-account and per-IP rate limits, append-only audit log |
| Scanning | one egress chokepoint (`SafeHttpClient`), read-only methods only, budgeted requests, IP pinning, redirect policy, kill switch |

## 7. Operations

* **Kill switch:** set `ST_SCANNING_ENABLED=false` and restart the worker. In-flight scans stop
  at the next request boundary and finish as `cancelled`.
* **Backup:** `docker compose exec api python -c "import sqlite3;sqlite3.connect('/var/lib/shadowtrace/shadowtrace.db').backup(sqlite3.connect('/tmp/b.db'))"` then copy `/tmp/b.db` out. Do not copy a live database file.
* **Retention:** `ST_RETENTION_DAYS` drives the cleanup job; audit rows are never deleted by it.
* **Upgrade:** pull the new image, run migrations by starting the API (they are applied at
  startup and are forward-only), then restart the worker.
* **Logs:** JSON on stdout, one object per line, with secrets redacted. Ship them with your
  usual collector; do not add request bodies to log output.

## 6.1 Network egress (why the worker has its own network)

```
backend (internal: true)   api, proxy            no route out, no inbound from outside
edge                       proxy                 the only published ports (80/443)
egress (bridge)            worker                reaches scan targets; no published ports
```

*The API never needs the internet*: it serves the SPA, the JSON API and exports, all from
SQLite. Keeping it on an `internal: true` network is what makes an SSRF-from-the-API class
of bug uninteresting.

*The worker must reach scan targets*, so it cannot live on an internal network — an
`internal` network has no default gateway at all, which is why an earlier revision could
never complete a scan. It therefore gets its own bridge network (`egress`) that:

- publishes **no ports**, so nothing can connect *to* the worker;
- is **not** attached to the proxy or the API, so a compromised worker cannot reach the
  admin API, and a compromised proxy cannot talk to the worker;
- carries **no `extra_hosts` or DNS override**, so it resolves exactly what the target
  scope allows.

**Container networking is not the control that bounds egress — `SafeHttpClient` is.** The
`egress` network still routes anywhere the host routes, so an operator must add host or
upstream firewall rules for the destinations they actually scan. Two workable shapes:

```bash
# (a) host firewall: drop new outbound connections from the egress subnet except to the
#     scan targets you have approved.
sudo iptables -A DOCKER-USER -s 172.31.0.0/24 -m conntrack --ctstate NEW \
     -d 203.0.113.0/24 -j ACCEPT
sudo iptables -A DOCKER-USER -s 172.31.0.0/24 -m conntrack --ctstate NEW -j REJECT

# (b) route the worker through an egress proxy that enforces a destination allow-list.
```

In-application, the controls are the operator allow-list (`ST_PRIVATE_ALLOWLIST`, empty in
production), the per-target scope policy (host + port + path prefix), the read-only method
set, the request budget and `ST_SCANNING_ENABLED`. Those still apply on the `egress`
network; the firewall is the layer that stops a bug in them from reaching the internet.

The two permissions are deliberately separate and are enforced in
`engine/urlguard.validate_destination`:

| Permission | Granted by | Unlocks |
|---|---|---|
| Non-standard port | the target record's `ports` **or** an operator allow-list entry | that `host:port` only when the resolved address is public |
| Private/loopback address | an **operator** allow-list entry only | that exact `host:port`, after the metadata/link-local check |

So a target record is not an egress grant: an organization admin who creates a target on
`127.0.0.1:9999` cannot scan it unless the operator listed `127.0.0.1:9999` in
`ST_PRIVATE_ALLOWLIST`. `test_egress_guard.py` holds the regression suite for this
(including a live canary that must receive zero requests).

If you do not scan anything, set `ST_SCANNING_ENABLED=false`: the worker then idles
without opening a socket.

## 6.2 Trusted proxy and the client address

Behind nginx every request arrives from the proxy container, so the address used for rate
limiting and the audit trail has to come from `X-Forwarded-For`. Two settings must agree,
and the Dockerfile deliberately derives one from the other:

| Where | Setting |
|---|---|
| uvicorn | `--forwarded-allow-ips "${ST_TRUSTED_PROXIES}"` (never `127.0.0.1`, which is the API itself inside a container) |
| application | `ST_TRUSTED_PROXIES` — checked in `security/auth.py::client_ip` before the header is believed |
| nginx | sets `X-Real-IP` and **overwrites** `X-Forwarded-For` with `$remote_addr` (never `$proxy_add_x_forwarded_for`) |

`ST_TRUSTED_PROXIES` accepts literal addresses (`172.30.0.2`) or CIDR networks
(`172.30.0.0/24`). The compose file pins the proxy to `172.30.0.2` on the `backend`
network and defaults the variable to that address, so the least-privileged value is the
default. A value that cannot be parsed never matches, so a typo degrades to *ignoring* the
header — the safe direction, covered by `backend/tests/test_trusted_proxy.py`.

Never set this to `0.0.0.0/0` or to a range a client can reach: the header would then be
attacker-controlled, giving anyone their own rate-limit bucket and a forgeable audit
address.

### Why the proxy must overwrite, not append

`$proxy_add_x_forwarded_for` **appends** the peer to whatever the client sent, so a request
carrying `X-Forwarded-For: 1.2.3.4` arrives at the API as `1.2.3.4, <real client>`. Any code
that reads the leftmost entry — as the first implementation here did — then records an
address the client chose, for both the rate-limit bucket and the audit log.

Both sides were fixed, so either one alone would be enough:

* **nginx** (`deploy/proxy/nginx.conf`, every proxied location) sets
  `proxy_set_header X-Forwarded-For $remote_addr;` — the header is replaced, so it always
  carries exactly one value: the peer that reached nginx. `X-Real-IP` is set the same way.
* **The application** (`security/auth.py::client_ip`) walks the header from the **right**
  — the hop nearest to us — skipping entries that are themselves trusted proxies, and
  returns the first untrusted address. Every hop must be a valid IP literal no longer than
  64 characters; a malformed, oversized or too-long chain falls back to the socket peer.

`backend/tests/test_trusted_proxy.py` covers both layers: the spoofed-value cases, a chain
of two trusted proxies, malformed/oversized headers, and a guard that fails if
`$proxy_add_x_forwarded_for` is ever reintroduced into `nginx.conf`.

This mirrors what uvicorn's own `ProxyHeadersMiddleware` does with
`--forwarded-allow-ips` (same right-to-left walk, same all-trusted fallback), so the three
layers — nginx, uvicorn and the application — agree on the same address instead of
disagreeing about which end of the chain to read. The application check still matters
because it is the one that holds when the API is started without `--proxy-headers`, and
because it is what the rate limiter and the audit log actually call.

**CSRF origin check.** Every state-changing request must carry the session's CSRF token and
pass an `Origin` check. An origin is accepted if it is in `ST_CORS_ORIGINS` or `ST_BASE_URL`,
**or** if it is the origin the request was addressed to (same-origin) — the case a
first-party SPA always produces. `null`, malformed values and foreign origins are rejected,
and an absent `Origin` (curl, the CLI) is still required to send the token. The scheme used
for the same-origin comparison comes from the connection, or from `X-Forwarded-Proto` when
the peer is a trusted proxy — which is why `ST_TRUSTED_PROXIES` and a correct `ST_BASE_URL`
matter behind TLS termination.

**If you put a CDN or a second proxy in front of nginx**, do not re-enable append to "keep"
the client address. Configure nginx's `real_ip` module for that specific trusted hop —
`set_real_ip_from <cdn-range>; real_ip_header X-Forwarded-For;` — so nginx computes
`$remote_addr` itself; the API then still receives one overwritten value.

## 8. What a deployer must still verify

Run these once against your own instance (they need a Docker daemon and network):

```bash
docker build -f deploy/docker/Dockerfile -t shadowtrace-runtime .
trivy image --severity HIGH,CRITICAL shadowtrace-runtime:latest
docker run --rm -t --network shadowtrace_backend ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://proxy/ -r zap.html
cd frontend && npx playwright install --with-deps chromium && npx playwright test
cd frontend && npm audit --production
```

Their results are not claimed anywhere in this repository; see `docs/known-issues.md` §A.
