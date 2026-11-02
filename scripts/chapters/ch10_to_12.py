# -*- coding: utf-8 -*-
"""
Chapters 10, 11, and 12 for ShadowTrace engineering documentation.
"""

def get_ch10_to_12():
    return """
<!-- CHAPTER 10: SHADOWLAB: BUNDLED VULNERABLE TRAINING APPLICATION -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 10</div>
  <h1 class="chapter-title">ShadowLab: Bundled Vulnerable Training Application</h1>
</div>

<h2>10.1 Architectural Isolation & Purpose</h2>
<p>
To facilitate rigorous automated verification, unit testing, and safe educational training for junior security engineers, ShadowTrace includes <strong>ShadowLab</strong>—a fully self-contained, vulnerable-by-design training application bundled directly within the platform.
</p>
<p>
ShadowLab is architecturally isolated as a distinct FastAPI sub-application mounted under the <code>/shadowlab</code> path prefix. It maintains independent route controllers, in-memory mock datasets, and synthetic frontend script bundles, ensuring that testing against ShadowLab cannot inadvertently pollute or affect production scanner state.
</p>

<h2>10.2 The 7 Deliberate Vulnerability Scenarios</h2>
<p>
ShadowLab implements seven realistic, high-fidelity vulnerability scenarios specifically designed to exercise every detection rule in the ShadowTrace auditing engine:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 15%;">Scenario ID</th>
      <th style="width: 25%;">Vulnerability Scenario</th>
      <th style="width: 30%;">Vulnerable Route & Behavior</th>
      <th style="width: 30%;">Targeted Detection Rule</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Scenario 1</strong></td>
      <td>Unauthenticated Admin Console</td>
      <td><code>/shadowlab/api/internal/debug-console</code><br/>Returns server memory stats and internal queue status without requiring authentication.</td>
      <td><span class="badge badge-critical">Rule ST-001</span><br/>Unauthenticated Admin Endpoint</td>
    </tr>
    <tr>
      <td><strong>Scenario 2</strong></td>
      <td>Zombie API Version Route</td>
      <td><code>/shadowlab/api/v1/users/auth</code><br/>Active legacy auth endpoint accepting deprecated MD5 password hashes while v2 uses Argon2.</td>
      <td><span class="badge badge-medium">Rule ST-015</span><br/>Legacy Zombie Route Reachable</td>
    </tr>
    <tr>
      <td><strong>Scenario 3</strong></td>
      <td>Hardcoded Secrets in Client Bundle</td>
      <td><code>/shadowlab/assets/bundle-vulnerable.js</code><br/>Contains hardcoded AWS access key (<code>AKIAIOSFODNN7EXAMPLE</code>) and Stripe live key.</td>
      <td><span class="badge badge-high">Rule ST-010</span><br/>Secret Disclosed in Client Scripts</td>
    </tr>
    <tr>
      <td><strong>Scenario 4</strong></td>
      <td>Single-Page Catch-All Router</td>
      <td><code>/shadowlab/catch-all/*</code><br/>Returns HTTP 200 with SPA root HTML for all undefined paths, simulating client-side routing.</td>
      <td><span class="badge badge-info">Rule ST-017</span><br/>Soft-404 Fallback Observation</td>
    </tr>
    <tr>
      <td><strong>Scenario 5</strong></td>
      <td>Excessive PII Data Exposure</td>
      <td><code>/shadowlab/api/users/profile</code><br/>Returns user records containing unmasked social security numbers (SSN) and internal password salts.</td>
      <td><span class="badge badge-high">Rule ST-003</span><br/>Sensitive Data Leakage</td>
    </tr>
    <tr>
      <td><strong>Scenario 6</strong></td>
      <td>Permissive Wildcard CORS</td>
      <td><code>/shadowlab/api/data/export</code><br/>Emits <code>Access-Control-Allow-Origin: *</code> and allows credentialed cross-origin requests.</td>
      <td><span class="badge badge-medium">Rule ST-007</span><br/>Permissive CORS Wildcard</td>
    </tr>
    <tr>
      <td><strong>Scenario 7</strong></td>
      <td>Exposed Public GraphQL Schema</td>
      <td><code>/shadowlab/graphql</code><br/>Publicly responds to <code>__schema</code> introspection queries, revealing private database mutations.</td>
      <td><span class="badge badge-medium">Rule ST-011</span><br/>GraphQL Introspection Enabled</td>
    </tr>
  </tbody>
</table>

<h2>10.3 Automated CI Dogfooding Pipeline & Verification</h2>
<p>
In modern software engineering, "dogfooding" refers to using one's own product to validate its functionality. ShadowLab serves as the primary ground-truth benchmark for ShadowTrace's Continuous Integration (CI) pipeline.
</p>
<p>
During automated test runs (<code>pytest -q</code>), the verification suite spins up the internal test server, targets the ShadowLab endpoint, and executes a full scan. The test suite asserts that:
</p>
<ol>
  <li><strong>100% True-Positive Detection:</strong> All seven planted vulnerabilities are discovered and mapped to their correct rule IDs (ST-001, ST-003, ST-007, ST-010, ST-011, ST-015, ST-017).</li>
  <li><strong>Zero False-Positive Soft-404 Flags:</strong> The catch-all route (Scenario 4) is correctly identified as an SPA fallback and suppressed from active vulnerability alerts.</li>
  <li><strong>Mathematical Monotonicity Verified:</strong> The unauthenticated admin console (ST-001) is mathematically computed as the highest-ranking finding, outranking medium and low findings.</li>
</ol>

<h2>10.4 Educational Lab Walkthrough: Analyst Verification Procedure</h2>
<p>
For security interns and junior penetration testers joining HackHalt Cyber Security, ShadowLab provides an interactive hands-on training curriculum. Analysts follow a structured verification runbook to validate findings discovered by ShadowTrace:
</p>

<h3>Step 1: Admin Endpoint Manual Validation (Scenario 1)</h3>
<p>
The analyst issues a direct cURL command to verify that administrative functionality is exposed without session cookies or authorization tokens:
</p>
<pre>
curl -i -s -X GET "https://shadowtrace-1ff5.onrender.com/shadowlab/api/internal/debug-console" \
     -H "Accept: application/json"
</pre>
<p>
<strong>Expected Forensic Evidence:</strong> HTTP/1.1 200 OK with internal server diagnostics. The analyst documents the lack of <code>401 Unauthorized</code> challenge and confirms Rule ST-001 violation.
</p>

<h3>Step 2: Legacy Version Authentication Probe (Scenario 2)</h3>
<p>
To demonstrate why Zombie APIs present severe risks, the analyst examines the legacy v1 endpoint versus the hardened v2 endpoint:
</p>
<pre>
# Probe hardened v2 endpoint (Enforces Argon2, Rate Limiting & TLS)
curl -i -s -X POST "https://shadowtrace-1ff5.onrender.com/shadowlab/api/v2/auth" \
     -H "Content-Type: application/json" -d '{"user":"test"}'

# Probe unmanaged legacy v1 endpoint (Accepts plain MD5 hash)
curl -i -s -X GET "https://shadowtrace-1ff5.onrender.com/shadowlab/api/v1/users/auth"
</pre>
<p>
The analyst records that while <code>v2</code> rejects non-credentialed payloads, <code>v1</code> remains reachable and returns legacy configuration objects, verifying Rule ST-015.
</p>

<h3>Step 3: Client Script Bundle Lexical Inspection (Scenario 3)</h3>
<p>
The analyst downloads <code>/shadowlab/assets/bundle-vulnerable.js</code> and confirms the presence of hardcoded test AWS credentials using standard terminal tools:
</p>
<pre>
curl -s "https://shadowtrace-1ff5.onrender.com/shadowlab/assets/bundle-vulnerable.js" | \
grep -E "AKIA[0-9A-Z]{{16}}"
</pre>
<p>
This hands-on walkthrough bridges theoretical vulnerability definitions with offensive exploitation and defensive remediation skills.
</p>

<!-- CHAPTER 11: FRONTEND UI/UX ARCHITECTURE & REAL-TIME VISUALIZATION -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 11</div>
  <h1 class="chapter-title">Frontend UI/UX Architecture & Real-Time Visualization</h1>
</div>

<h2>11.1 Component Hierarchy & Vue 3 Composition API Stack</h2>
<p>
The user interface of ShadowTrace is constructed using <strong>Vue 3</strong> and the <strong>Composition API</strong>, bundled with <strong>Vite 6</strong> and styled using <strong>Tailwind CSS</strong>. The frontend architecture is organized into modular components adhering to strict separation of concerns:
</p>
<ul>
  <li><code>App.vue</code>: Root application shell providing responsive layout framing, navigation header, and theme switching context.</li>
  <li><code>ScanManager.vue</code>: Target URL submission form, pre-flight configuration controls (crawl depth, concurrency rate, baseline specification upload), and scan execution buttons.</li>
  <li><code>ScanStreamMonitor.vue</code>: Real-time progress bar, animated phase step indicators, live status feed, and elapsed scan timer.</li>
  <li><code>EndpointInventoryTable.vue</code>: High-performance searchable, sortable, and filterable catalog of all discovered endpoints, complete with status pills, HTTP verbs, and normalization badges.</li>
  <li><code>FindingsView.vue</code>: Grouped vulnerability accordion with risk score badges, CVSS indicators, evidence tabs, and copyable remediation code blocks.</li>
  <li><code>ExportModal.vue</code>: Report generation dialog allowing one-click export of comprehensive findings in Markdown, JSON, and PDF formats.</li>
</ul>

<h2>11.2 Real-Time SSE Event Streaming Pipeline</h2>
<p>
Traditional web scanners force operators to wait minutes or hours with no feedback while a scan executes, or require aggressive polling of backend REST endpoints. ShadowTrace implements a modern real-time streaming pipeline utilizing <strong>Server-Sent Events (SSE)</strong> via the native HTML5 <code>EventSource</code> API.
</p>
<p>
When an operator launches a scan, the backend returns a unique <code>scan_id</code>, and the frontend establishes an SSE stream to <code>/api/scans/{scan_id}/stream</code>. The backend streams structured JSON events as they occur:
</p>

<div class="diagram-box">
+---------------------------------------------------------------------------------------------------------+
|                                    REAL-TIME SSE EVENT STREAMING PIPELINE                               |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|   Frontend Client (Vue 3 EventSource)                           Backend Scanner Engine (FastAPI)       |
|          |                                                                     |                        |
|          | ------------ 1. GET /api/scans/{id}/stream -----------------------> |                        |
|          |                                                                     |                        |
|          | <----------- 2. event: phase_change {phase: "PASSIVE_CRAWL"} ------ |                        |
|          |    [UI Updates: Progress 20%, Step 2 Active]                        |                        |
|          |                                                                     |                        |
|          | <----------- 3. event: endpoint_discovered {path: "/api/v2/users"} -|                        |
|          |    [UI Updates: Appends row to Live Inventory Table]                |                        |
|          |                                                                     |                        |
|          | <----------- 4. event: finding_logged {rule: "ST-001", risk: 92} ---|                        |
|          |    [UI Updates: Increments Critical Badge counter]                  |                        |
|          |                                                                     |                        |
|          | <----------- 5. event: scan_completed {total_endpoints: 47} --------|                        |
|          |    [UI Updates: Renders Executive Summary & Export Button]          |                        |
+---------------------------------------------------------------------------------------------------------+
</div>

<h2>11.3 Accessibility, Contrast Compliance & Theming Engine</h2>
<p>
In accordance with professional design guidelines and HackHalt standards, ShadowTrace features an advanced, accessible theming system:
</p>
<ul>
  <li><strong>Default Light (White) Theme:</strong> Built around a clean white (<code>#FFFFFF</code>) and subtle slate (<code>#F8FAFC</code>) background, high-contrast dark slate body text (<code>#111827</code>), and vibrant royal navy primary branding (<code>#1E3A8A</code>), achieving WCAG 2.1 AA compliant contrast ratios (&gt; 4.5:1 for body text, &gt; 7:1 for headings).</li>
  <li><strong>Dark Theme Toggle:</strong> A secondary dark mode palette engineered with slate-900 backgrounds (<code>#0F172A</code>), high-contrast text (<code>#F8FAFC</code>), and luminous accents, switchable via a single-click header toggle that persists preferences in <code>localStorage</code>.</li>
  <li><strong>Responsive Grid & Mobile Compatibility:</strong> Built with CSS Flexbox and Tailwind responsive grid breakpoints, ensuring full operational usability across standard desktop monitors, tablets, and field-testing laptops.</li>
</ul>

<!-- CHAPTER 12: BACKEND ARCHITECTURE, DATABASE DESIGN & API REFERENCE -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 12</div>
  <h1 class="chapter-title">Backend Architecture, Database Design & API Reference</h1>
</div>

<h2>12.1 FastAPI Modular Router Architecture</h2>
<p>
The backend service of ShadowTrace is implemented in Python 3.13 utilizing the <strong>FastAPI</strong> framework. The application code is strictly modularized across dedicated packages to promote maintainability, loose coupling, and testability:
</p>
<ul>
  <li><code>backend/main.py</code>: Application entry point, CORS middleware configuration, exception handlers, and router mounting.</li>
  <li><code>backend/routers/scans.py</code>: Scan orchestration, background task submission, and SSE event streaming controllers.</li>
  <li><code>backend/routers/targets.py</code>: Target domain management, asset tagging, and target history endpoints.</li>
  <li><code>backend/routers/findings.py</code>: Vulnerability query filters, severity sorting, and remediation guidance endpoints.</li>
  <li><code>backend/routers/baseline.py</code>: OpenAPI and Swagger specification upload, validation, and baseline diff controllers.</li>
  <li><code>backend/routers/auth.py</code>: Operator authentication, cryptographic password hashing (Argon2), and session cookie validation.</li>
</ul>

<h2>12.2 Relational Entity Schema & WAL Concurrency Tuning</h2>
<p>
Data persistence is handled by an optimized SQLite relational database. The schema is organized into five primary normalized entities with enforced foreign key constraints:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 20%;">Entity / Table</th>
      <th style="width: 35%;">Key Attributes & Types</th>
      <th style="width: 45%;">Relational Role & Indexing Strategy</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>targets</code></td>
      <td><code>id</code> (TEXT PK), <code>domain</code> (TEXT UNIQUE), <code>created_at</code> (DATETIME)</td>
      <td>Stores monitored domains and base URLs. Indexed on <code>domain</code> for rapid lookup.</td>
    </tr>
    <tr>
      <td><code>scans</code></td>
      <td><code>id</code> (TEXT PK), <code>target_id</code> (FK), <code>status</code> (TEXT), <code>risk_score</code> (REAL), <code>started_at</code></td>
      <td>Represents an execution instance. Foreign key cascade deletion on <code>target_id</code>.</td>
    </tr>
    <tr>
      <td><code>endpoints</code></td>
      <td><code>id</code> (TEXT PK), <code>scan_id</code> (FK), <code>path</code> (TEXT), <code>method</code> (TEXT), <code>category</code> (TEXT)</td>
      <td>Stores discovered routes. Categorized as <code>documented</code>, <code>shadow</code>, <code>zombie</code>, or <code>orphaned</code>.</td>
    </tr>
    <tr>
      <td><code>findings</code></td>
      <td><code>id</code> (TEXT PK), <code>scan_id</code> (FK), <code>rule_id</code> (TEXT), <code>severity</code> (TEXT), <code>score</code> (REAL)</td>
      <td>Records vulnerability findings. Contains proof-of-concept evidence, request headers, and remediation text.</td>
    </tr>
    <tr>
      <td><code>audit_logs</code></td>
      <td><code>id</code> (INTEGER PK AUTO), <code>user_id</code> (TEXT), <code>action</code> (TEXT), <code>ip_address</code>, <code>timestamp</code></td>
      <td>Append-only compliance audit trail recording operator attestations and scan dispatches.</td>
    </tr>
  </tbody>
</table>

<h2>12.3 Complete RESTful API Reference Specification</h2>
<p>
The backend exposes a fully documented, RESTful HTTP interface allowing programmatic integration into CI/CD pipelines, SIEM platforms, and custom security scripts:
</p>

<h3>1. POST /api/scans/start — Initiate Autonomous Discovery Scan</h3>
<p>Dispatches an asynchronous discovery and auditing job against an authorized domain.</p>
<pre>
REQUEST:
POST /api/scans/start HTTP/1.1
Content-Type: application/json

{
  "target_url": "https://api.example.com",
  "crawl_depth": 3,
  "max_concurrency": 10,
  "baseline_spec_id": "spec_9b1deb4d",
  "attestation_confirmed": true
}

RESPONSE:
HTTP/1.1 202 Accepted
Content-Type: application/json

{
  "scan_id": "scan_4a8f9c1e-7b2d",
  "target_url": "https://api.example.com",
  "status": "QUEUED",
  "stream_url": "/api/scans/scan_4a8f9c1e-7b2d/stream",
  "created_at": "2026-11-02T22:30:00Z"
}
</pre>

<h3>2. GET /api/scans/{scan_id}/findings — Query Scan Vulnerability Findings</h3>
<p>Retrieves paginated, filtered vulnerability findings with risk scores and remediation guidance.</p>
<pre>
REQUEST:
GET /api/scans/scan_4a8f9c1e-7b2d/findings?severity=Critical,High HTTP/1.1
Accept: application/json

RESPONSE:
HTTP/1.1 200 OK
Content-Type: application/json

{
  "scan_id": "scan_4a8f9c1e-7b2d",
  "total_findings": 3,
  "findings": [
    {
      "id": "find_8f2910a",
      "rule_id": "ST-001",
      "title": "Unauthenticated Administrative Endpoint",
      "severity": "Critical",
      "risk_score": 92.0,
      "endpoint": "/api/internal/debug-console",
      "method": "GET",
      "evidence": "Returned HTTP 200 with debug_mode: true",
      "remediation": "Enforce mandatory JWT bearer authentication dependency."
    }
  ]
}
</pre>
"""
