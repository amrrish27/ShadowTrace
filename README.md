# ShadowTrace

**API shadow-endpoint discovery and security scanner.**

ShadowTrace crawls APIs you are authorized to test, discovers hidden/shadow endpoints from HTML, JavaScript, source maps, OpenAPI specs, HAR imports, and more — then validates them and produces evidence-backed findings with full exports.

> **Authorized use only.** Every target requires explicit approval and a written attestation. Private address space is blocked unless an operator explicitly allows it.

---

## Quick Start

**Requirements:** Python 3.13+, Node 20+

**Windows**
```bat
start.cmd
```

**Linux / macOS**
```bash
./start.sh
```

Then open **http://127.0.0.1:8000/** and sign in:

| Field | Value |
|---|---|
| Email | `admin@example.test` |
| Password | `Bootstrap-Admin-Pass-9!` |

> Default credentials apply only on a fresh database. Change your password after first login.

| URL | Description |
|---|---|
| http://127.0.0.1:8000/ | Main UI + API |
| http://127.0.0.1:8099/ | ShadowLab training target |

---

## Features

- **Multi-source Discovery** — HTML links, inline JS, external scripts, source maps, OpenAPI/Swagger, robots.txt, sitemaps, HAR imports
- **Shadow Endpoint Detection** — reconciles discovered endpoints against a documented baseline to surface undocumented APIs
- **Active Validation** — read-only replay confirms each endpoint is live and classifies HTTP behavior
- **Security Findings** — rules engine checks for misconfigurations, leaked secrets, and policy violations
- **SSRF Protection** — all outbound requests go through `SafeHttpClient` with strict scope, IP pinning, and private-range blocking
- **Evidence Exports** — JSON, HTML, CSV, Markdown, OpenAPI stub per scan
- **Reliability** — threaded DNS timeouts, external wall-clock watchdog, unreachable-target fast-fail, live progress tracking

---

## Architecture

```
frontend (React SPA)  ←→  backend API (FastAPI)  ←→  SQLite DB
                                  ↓
                            scan worker
                                  ↓
                         SafeHttpClient (SSRF-safe)
                                  ↓
                            target / ShadowLab
```

- **Backend:** Python 3.13, FastAPI, SQLite (no external services needed)
- **Frontend:** React + TypeScript, Vite, served by the API
- **Worker:** separate process, heartbeat + lease system, watchdog-enforced time limits
- **Lab:** bundled Flask training target with 15 vulnerability scenarios

---

## Running Tests

```bash
# Backend
cd backend
py -3.13 -m pytest -q

# Frontend
cd frontend
npm test
npm run build
```

---

## Stopping

```bat
stop.cmd        # Windows
./stop.sh       # Linux / macOS
```

---

## License

For authorized security assessment use only. See [SECURITY.md](SECURITY.md) for responsible use policy.
