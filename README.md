# ShadowTrace

**API shadow-endpoint discovery and security scanner.**

ShadowTrace crawls APIs you are authorized to test, discovers hidden and undocumented endpoints from multiple sources, validates them with read-only requests, and produces evidence-backed security findings — all from a single local stack with no external services required.

> **Authorized use only.** Every target requires explicit approval and a written attestation before scanning. Private address space is fully blocked unless an operator explicitly allow-lists the exact `host:port`.

---

## What It Does

ShadowTrace combines several discovery techniques into one pipeline:

- **Crawls** the target's pages, follows links up to depth 2, and collects inline and external JavaScript
- **Extracts** API endpoints from HTML attributes, JS string literals, source maps, OpenAPI/Swagger specs, Postman collections, robots.txt, sitemaps, and HAR imports
- **Reconciles** discovered endpoints against a documented baseline to surface shadow (undocumented) APIs
- **Validates** each candidate with a read-only HTTP replay, classifying live vs. unreachable and detecting soft-404s
- **Analyses** responses for security findings — leaked secrets, missing headers, CORS misconfigurations, reflected parameters, and more
- **Exports** results as JSON, HTML report, CSV inventory, CSV findings, Markdown, or OpenAPI stub

---

## Requirements

- **Python 3.13+** (3.10+ also works)
- **Node 20+** — only needed to build the frontend SPA once
- **Nothing else** — SQLite is built into Python; no databases, message queues, or cloud accounts needed

---

## Quick Start

**Windows**
```bat
start.cmd
```

**Linux / macOS / WSL**
```bash
./start.sh
```

The start script handles everything automatically:
1. Installs Python dependencies (if missing, it prints the exact `pip install` line)
2. Builds the frontend bundle on first run (`npm ci && npm run build`)
3. Creates the SQLite database and applies migrations
4. Starts the API server, the scan worker, and the bundled ShadowLab training target
5. Waits until all three are healthy before printing the URLs

| URL | What it is |
|---|---|
| http://127.0.0.1:8000/ | Main UI and JSON API |
| http://127.0.0.1:8099/ | ShadowLab — the bundled training target |
| http://127.0.0.1:8000/api/docs | Interactive API docs (dev only) |

**Default credentials on a fresh database:**

| Field | Value |
|---|---|
| Email | `admin@example.test` |
| Password | `Bootstrap-Admin-Pass-9!` |

Logs are written to `logs/api.log` and `logs/worker.log`. Stop everything with `stop.cmd` / `./stop.sh` or Ctrl+C.

---

## Architecture

```
Browser  →  React SPA (served by API)
                ↓
         FastAPI  ←→  SQLite (single file)
                ↓
          Scan Worker  (separate process)
                ↓
        SafeHttpClient  (SSRF-safe HTTP)
                ↓
          Target  /  ShadowLab
```

| Layer | Technology |
|---|---|
| Backend | Python 3.13, FastAPI, SQLite |
| Frontend | React, TypeScript, Vite |
| Worker | Separate Python process with heartbeat + watchdog |
| HTTP client | Custom `SafeHttpClient` — IP-pinned, scope-checked, rate-limited |
| Lab | Bundled Flask app with 15 planted vulnerability scenarios |

---

## Safety & Reliability

- **SSRF protection** — all outbound requests go through a single choke point with strict scope, IP pinning, private-range blocking, and redirect validation
- **Threaded DNS timeouts** — resolver runs in a bounded thread pool; DNS hangs are killed after a hard deadline
- **External watchdog** — worker enforces `max_seconds` from outside the scanner thread; no stuck scan can run forever
- **Unreachable-target fast-fail** — if the seed request fails, spec probing is skipped immediately rather than timing out across 140+ paths
- **Recovery** — background recovery marks abandoned or stalled scans `timed_out` / `failed` automatically, even with a live heartbeat

---

## ShadowLab

ShadowLab is a purpose-built vulnerable API included with ShadowTrace. It runs locally on port `8099` and contains 15 scenarios, each designed to trigger a specific detection rule:

- Unauthenticated shadow endpoints
- IDOR and broken object-level authorization
- Leaked API keys and secrets in JavaScript
- Exposed internal admin routes
- CORS misconfiguration
- Missing rate limiting on sensitive paths
- And more

Open the **Lab** page in the UI to start/stop the lab, view scenarios, and queue a scan that covers all of them.

---

## Running Tests

```bash
# Backend — all tests
cd backend
py -3.13 -m pytest -q

# Frontend — unit tests + production build
cd frontend
npm test
npm run build
```

---

## Stopping

```bat
stop.cmd          # Windows
./stop.sh         # Linux / macOS
```

Both scripts ask the processes to stop gracefully first, then force-kill after five seconds if they haven't exited.

---

## License

For authorized security assessment use only. See [SECURITY.md](SECURITY.md) for the responsible use policy.
