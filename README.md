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

### Step 1 — Install dependencies

```bash
pip install -r requirements.txt
```

Then install the frontend dependencies (only needed once):

```bash
cd frontend
npm install
cd ..
```

### Step 2 — Start the app

**Windows** — double-click `start.cmd` in the project folder, or run it from a terminal:
```bat
start.cmd
```

**Linux / macOS / WSL** — open a terminal in the project folder and run:
```bash
./start.sh
```

The script will print something like this when everything is ready:
```
ShadowTrace UI + API : http://127.0.0.1:8000/
ShadowLab training   : http://127.0.0.1:8099/
Sign in              : admin@example.test / Bootstrap-Admin-Pass-9!
```

### Step 3 — Open the browser

Go to **http://127.0.0.1:8000/** and sign in with:

| Field | Value |
|---|---|
| Email | `admin@example.test` |
| Password | `Bootstrap-Admin-Pass-9!` |

### Step 4 — Run your first scan

1. Click **Lab** in the left sidebar → click **Start Lab** to launch the training target
2. Click **Targets** in the left sidebar → you'll see the lab target already registered
3. Click **Run Scan** on the lab target → choose a profile and click **Start Scan**
4. Click **Scans** to watch progress in real time — phase, requests, and endpoints update live
5. Open the scan when complete to browse **Findings**, **Endpoints**, **Events**, and **Exports**

| URL | What it is |
|---|---|
| http://127.0.0.1:8000/ | Main UI and JSON API |
| http://127.0.0.1:8099/ | ShadowLab — the bundled training target |
| http://127.0.0.1:8000/api/docs | Interactive API docs (dev only) |

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
