# -*- coding: utf-8 -*-
"""
Chapters 1, 2, and 3 for ShadowTrace engineering documentation.
"""

def get_ch01_to_03():
    return """
<!-- CHAPTER 1: THE MODERN API THREAT LANDSCAPE & PROBLEM DEFINITION -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 1</div>
  <h1 class="chapter-title">The Modern API Threat Landscape & Problem Definition</h1>
</div>

<h2>1.1 The Proliferation of Microservices and Single-Page Architectures</h2>
<p>
Over the past decade, enterprise software engineering has undergone a profound architectural migration from monolithic codebases to distributed microservice ecosystems and decoupled Single-Page Applications (SPAs). While this architectural paradigm enables continuous deployment and independent team velocity, it distributes application business logic across hundreds—often thousands—of distinct RESTful, RPC, and GraphQL network endpoints.
</p>
<p>
In contemporary cloud environments (AWS, GCP, Azure, and Kubernetes clusters), microservices communicate internally across private service meshes and externally through API Gateways and reverse proxies. However, as organizational development cadence accelerates, engineering synchronization routinely breaks down. Teams frequently release rapid hotfixes, spin up staging instances, create temporary webhook handlers, or refactor legacy controllers without updating central documentation or revoking legacy routing entries.
</p>
<p>
The resultant organizational state is termed <strong>API Sprawl</strong>. Security operations centers (SOCs) and AppSec teams find themselves responsible for defending attack surfaces whose exact perimeter, inventory, and exposed parameters are completely unknown. You cannot protect what you cannot see, and modern threat actors explicitly target forgotten, undocumented routes that exist outside the visibility of Web Application Firewalls (WAFs) and centralized authentication gateways.
</p>

<h2>1.2 Formal Taxonomy of Unmanaged APIs</h2>
<p>
To systematically address the API inventory crisis, ShadowTrace establishes a formal taxonomic classification of unmanaged, high-risk application routes. Understanding these distinct categories is critical for applying appropriate discovery heuristics and targeted remediation strategies:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 20%;">Classification</th>
      <th style="width: 35%;">Architectural Characteristics</th>
      <th style="width: 25%;">Primary Threat Vectors</th>
      <th style="width: 20%;">ShadowTrace Detection Rule</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Shadow API</strong></td>
      <td>Production endpoints actively receiving traffic or compiled into client JavaScript bundles, but omitted from central OpenAPI, Swagger, or API gateway catalogs.</td>
      <td>Bypasses central WAF rate limiting; frequently lacks mandatory authentication middleware; exposes internal schemas.</td>
      <td><span class="badge badge-high">Rule ST-013</span><br/>Undocumented Shadow Route</td>
    </tr>
    <tr>
      <td><strong>Zombie API</strong></td>
      <td>Deprecated older versions of an API (e.g., <code>/api/v1/</code>) left active on backend servers after a modern version (e.g., <code>/api/v2/</code>) was released.</td>
      <td>Relies on outdated cryptographic libraries; contains known, unpatched authorization vulnerabilities (BOLA/IDOR).</td>
      <td><span class="badge badge-medium">Rule ST-015</span><br/>Legacy Zombie Route</td>
    </tr>
    <tr>
      <td><strong>Orphaned API</strong></td>
      <td>Documented routes or exposed gateway paths whose underlying upstream service has been decommissioned, returning unhandled 502/503 errors or fallback handlers.</td>
      <td>Exposes internal infrastructure hostnames, upstream proxy topologies, and unhandled debug exceptions.</td>
      <td><span class="badge badge-low">Rule ST-014</span><br/>Orphaned Route</td>
    </tr>
    <tr>
      <td><strong>Drifted API</strong></td>
      <td>Active endpoints whose real runtime behavior (accepted request parameters, emitted response payloads) diverges from formal OpenAPI specifications.</td>
      <td>Excessive data exposure (backend fields leaked to client); parameter tampering and type confusion.</td>
      <td><span class="badge badge-medium">Rule ST-004</span><br/>Excessive Data Exposure</td>
    </tr>
    <tr>
      <td><strong>Hidden Admin Route</strong></td>
      <td>Internal administrative and debugging interfaces (e.g., <code>/admin/debug</code>, <code>/internal/actuator</code>) exposed without mandatory IP whitelisting or SSO.</td>
      <td>Complete platform takeover; unauthorized privilege escalation; arbitrary data modification.</td>
      <td><span class="badge badge-critical">Rule ST-001</span><br/>Unauthenticated Admin</td>
    </tr>
  </tbody>
</table>

<h2>1.3 OWASP API Security Top 10 (2023) Focus: API9:2023</h2>
<p>
The Open Worldwide Application Security Project (OWASP) recognized unmanaged APIs as a top-tier vulnerability category, codifying it as <strong>API9:2023: Improper Inventory Management</strong> in the official OWASP API Security Top 10 standard. OWASP explicitly warns:
</p>
<div class="callout callout-security">
  <strong>OWASP API9:2023 Definition:</strong> APIs tend to expose more endpoints than traditional web applications, making proper and updated documentation critical. Proper inventory of hosts and deployed API versions plays an important role in mitigating issues such as deprecated API versions and exposed debug endpoints. Lack of asset management allows attackers to exploit unpatched legacy endpoints that still possess access to production databases.
</div>
<p>
Modern threat actors specifically harvest client-side JavaScript bundles to locate old API routes. Because development teams assume legacy routes are forgotten, they rarely patch vulnerabilities in older code paths. Consequently, a Zombie <code>v1</code> endpoint often provides an attacker with direct SQL injection or Broken Object-Level Authorization (BOLA) directly into current production databases, completely bypassing the robust security controls implemented in modern <code>v2</code> endpoints.
</p>

<h2>1.4 Enterprise Compliance Mandates & Regulatory Pressures</h2>
<p>
Beyond direct security risks, maintaining an accurate and continuous inventory of all network and application endpoints is now a strict legal mandate across global compliance standards:
</p>
<ul>
  <li><strong>PCI-DSS 4.0 (Requirement 6.3.2):</strong> Mandates that organizations maintain a comprehensive inventory of bespoke and custom software, including all custom internal and external API endpoints. Failure to maintain an automated inventory results in immediate non-compliance penalties for payment processors.</li>
  <li><strong>SOC 2 Type II (Trust Services Criteria CC6.1 & CC6.6):</strong> Requires demonstrable logical boundaries, continuous asset discovery, and systematic vulnerability assessment across all publicly accessible cloud entry points.</li>
  <li><strong>ISO/IEC 27001:2022 (Control A.8.8 - Management of Technical Vulnerabilities):</strong> Requires organizations to obtain timely information about technical vulnerabilities of information systems being evaluated and implement effective measures to address associated risks.</li>
  <li><strong>HIPAA Security Rule (45 CFR § 164.308):</strong> Requires healthcare entities to maintain accurate records of all electronic Protected Health Information (ePHI) processing pathways, including all unmanaged web and mobile API interfaces.</li>
</ul>

<!-- CHAPTER 2: PROJECT OBJECTIVES, SCOPE & ETHICAL OPERATING GUARDRAILS -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 2</div>
  <h1 class="chapter-title">Project Objectives, Scope & Ethical Operating Guardrails</h1>
</div>

<h2>2.1 Core Engineering & Security Objectives</h2>
<p>
ShadowTrace was engineered during the HackHalt Cybersecurity Research Internship to solve enterprise API sprawl by providing continuous, automated, and mathematically verified visibility into external and internal API attack surfaces. The core engineering objectives defined for the project comprise:
</p>
<ol>
  <li><strong>Autonomous Multi-Tier Route Discovery:</strong> Implement a hybrid crawling engine capable of combining passive web spidering, JavaScript bundle lexical parsing, source map recovery, and well-known route probing into a unified route extraction pipeline.</li>
  <li><strong>Intelligent Route Normalization & Parameter Templating:</strong> Design robust deterministic regex tokenizers to collapse dynamic parameters (UUIDs, sequential integers, hashes, slugs) into canonical parameterized routes, eliminating route explosion.</li>
  <li><strong>SPA Soft-404 Mitigation:</strong> Develop an empirical multi-sample baseline calibration engine utilizing body entropy and DOM similarity metrics to completely suppress false-positive catch-all routes common to modern client-side routers.</li>
  <li><strong>Automated OpenAPI Baseline Reconciliation:</strong> Build a differential comparison engine capable of ingesting Swagger 2.0 and OpenAPI 3.0/3.1 specifications and categorizing runtime routes into Documented, Undocumented (Shadow), and Deprecated (Zombie) states.</li>
  <li><strong>Deterministic Monotonic Risk Scoring:</strong> Formulate a formal mathematical risk algorithm bounded between 0 and 100 that factors in base severity, discovery confidence, exposure scope, and exploitability.</li>
  <li><strong>Zero-Trust SSRF Protection:</strong> Enforce an unbreakable network barrier preventing the discovery engine from being weaponized as a proxy against internal private networks or cloud metadata services.</li>
</ol>

<h2>2.2 Functional vs. Non-Functional Requirements Specification</h2>
<p>
The platform was architected to fulfill rigorous functional specifications and strict non-functional performance, security, and scalability criteria:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Requirement Category</th>
      <th style="width: 45%;">Engineering Specification</th>
      <th style="width: 30%;">Validation Criteria</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Functional: Discovery</strong></td>
      <td>Extract routes from HTML, script tags, inline scripts, external JS files, and source maps up to depth 3.</td>
      <td>Achieve 100% route capture against benchmark SPA applications.</td>
    </tr>
    <tr>
      <td><strong>Functional: Reconciliation</strong></td>
      <td>Parse OAS 3.0/3.1 JSON/YAML baselines; match templated routes; isolate schema drift.</td>
      <td>Accurate classification of Shadow, Zombie, and Active routes in &lt; 250ms.</td>
    </tr>
    <tr>
      <td><strong>Functional: Auditing</strong></td>
      <td>Execute 17 standardized security auditing rules (ST-001 through ST-017) against all discovered endpoints.</td>
      <td>Zero unhandled exceptions; structured JSON findings schema output.</td>
    </tr>
    <tr>
      <td><strong>Non-Functional: Safety</strong></td>
      <td>Restrict all active probes to idempotent HTTP methods (GET, HEAD, OPTIONS); never mutate server state.</td>
      <td>100% compliance verified through network proxy inspection test suites.</td>
    </tr>
    <tr>
      <td><strong>Non-Functional: SSRF Defense</strong></td>
      <td>Pre-resolve all hostnames and block RFC 1918, RFC 3927, loopback, and cloud metadata (169.254.169.254).</td>
      <td>Zero leakage of private IP requests in automated SSRF attack test suites.</td>
    </tr>
    <tr>
      <td><strong>Non-Functional: Performance</strong></td>
      <td>Process 100 concurrent HTTP requests with asynchronous I/O; complete average site audit in &lt; 90 seconds.</td>
      <td>Average CPU utilization &lt; 40%; memory consumption &lt; 250MB.</td>
    </tr>
  </tbody>
</table>

<h2>2.3 The Non-Destructive Safe Probing Mandate & RFC 9110 Idempotency</h2>
<p>
A primary failure mode of commercial vulnerability scanners is operational disruption. Heavy scanners often inject fuzzing payloads or mutate server records by issuing unconstrained POST, PUT, or DELETE requests. In production environments, this can corrupt databases, trigger false financial transactions, or trigger denial-of-service (DoS) conditions.
</p>
<p>
ShadowTrace enforces a strict <strong>Non-Destructive Safe Probing Mandate</strong> based on the safe method definitions codified in <strong>RFC 9110 (HTTP Semantics)</strong>. Section 9.2.1 of RFC 9110 establishes:
</p>
<div class="callout callout-info">
  <strong>RFC 9110 Section 9.2.1 Safe Methods:</strong> Request methods are considered 'safe' if their defined semantics are essentially read-only; that is, the client does not request, and does not expect, any state change on the origin server as a result of applying such a method. The methods GET, HEAD, OPTIONS, and TRACE are defined as safe.
</div>
<p>
ShadowTrace's discovery and active verification engines are strictly prohibited from generating mutating HTTP requests. Active probes verify route existence, header configurations, authentication challenges, and CORS policies exclusively through safe GET, HEAD, and OPTIONS requests. This architectural constraint allows organizations to run continuous ShadowTrace audits against live production systems without risk of database corruption or business disruption.
</p>

<h2>2.4 Attestation Logging & Cryptographic Audit Trail Architecture</h2>
<p>
To ensure strict ethical and legal compliance with computer security legislation (such as the US Computer Fraud and Abuse Act and international equivalents), ShadowTrace requires explicit user authorization before initiating any discovery task. Operators must attest to having lawful authorization to test the targeted domain.
</p>
<p>
Every scan event, domain target creation, and verification action is immutably logged into an append-only SQLite audit table (<code>audit_logs</code>). Each audit record records:
</p>
<ul>
  <li><strong>Cryptographic User Identity:</strong> User ID and role attested during session authentication.</li>
  <li><strong>Target Scope & Timestamp:</strong> Normalized target domain, IP resolution at time of scan, and UTC millisecond timestamp.</li>
  <li><strong>Configuration Parameters:</strong> Crawl depth, probe rate limits, baseline specification hashes, and active rule toggles.</li>
  <li><strong>Network Attribution:</strong> Client source IP and user-agent string recorded for forensic non-repudiation.</li>
</ul>

<!-- CHAPTER 3: SYSTEM ARCHITECTURE & HIGH-LEVEL PROCESSING PIPELINE -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 3</div>
  <h1 class="chapter-title">System Architecture & High-Level Processing Pipeline</h1>
</div>

<h2>3.1 High-Level Multi-Tier Architectural Topology</h2>
<p>
ShadowTrace is engineered around a modern decoupled multi-tier architecture designed for high throughput, memory safety, and seamless real-time operator feedback. The platform separates concerns across four distinct architectural planes:
</p>
<ol>
  <li><strong>Presentation Plane (Vue 3 / Vite SPA):</strong> A modern, reactive single-page dashboard built with Vue 3 Composition API, Tailwind CSS, Lucide icons, and Chart.js. Communicates with the backend via REST APIs and listens to real-time scanning progress via Server-Sent Events (SSE).</li>
  <li><strong>Application & API Plane (FastAPI Core):</strong> High-performance asynchronous REST service implemented in Python 3.13 utilizing FastAPI and Starlette. Handles authentication, scan job orchestration, baseline ingestion, and reporting endpoints.</li>
  <li><strong>Autonomous Execution Engine (Async Scanner Subsystem):</strong> A multi-stage asynchronous pipeline powered by Python <code>asyncio</code> and <code>httpx</code>. Orchestrates passive spidering, lexical tokenization, heuristic probing, and risk scoring across non-blocking connection pools.</li>
  <li><strong>Persistence Plane (SQLite with WAL Mode):</strong> High-concurrency relational data storage configured with Write-Ahead Logging (WAL) and multi-reader connection pooling, storing targets, scans, endpoints, findings, and audit trails.</li>
</ol>

<div class="diagram-box">
+---------------------------------------------------------------------------------------------------------+
|                                    SHADOWTRACE ARCHITECTURAL TOPOLOGY                                   |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  +---------------------------------------------------------------------------------------------------+  |
|  | PRESENTATION TIER: Vue 3 Single-Page Application (Vite 6 / Tailwind CSS / Pinia / Lucide Icons)  |  |
|  |  - Real-Time Scan Monitor (SSE)   - Interactive Inventory Table   - Findings Detail & Remediation |  |
|  |  - Baseline Spec Upload Modal     - Risk Trend XY Charts         - One-Click Markdown/PDF Export  |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                       | HTTP REST APIs / Server-Sent Events (SSE)                       |
|                                       v                                                                 |
|  +---------------------------------------------------------------------------------------------------+  |
|  | APPLICATION TIER: FastAPI Core Service (Python 3.13 / Starlette / Uvicorn)                       |  |
|  |  - Auth & Session Guard (Argon2)  - Job Scheduler & Queue Router - OpenAPI Spec Ingestion Engine  |  |
|  |  - Attestation Audit Logger       - REST Route Controllers       - Report Compilation Subsystem  |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                       | Async Job Dispatch / Worker Invocations                         |
|                                       v                                                                 |
|  +---------------------------------------------------------------------------------------------------+  |
|  | AUTONOMOUS SCANNING ENGINE (AsyncIO / HTTPX Non-Blocking Pipeline)                                |  |
|  |  +-------------------------+  +--------------------------+  +----------------------------------+  |  |
|  |  | Stage 1: Pre-Flight     |  | Stage 2: Passive Crawler |  | Stage 3: Lexical AST Parser      |  |  |
|  |  | - Target Normalization  |  | - HTML Anchor Extraction |  | - JS Bundle Regex Tokenizer      |  |  |
|  |  | - SSRF Pre-DNS Validator |  | - External Script Scraping|  | - Source Map (.map) Recovery     |  |  |
|  |  +-------------------------+  +--------------------------+  +----------------------------------+  |  |
|  |                |                              |                              |                     |  |
|  |                v                              v                              v                     |  |
|  |  +-------------------------+  +--------------------------+  +----------------------------------+  |  |
|  |  | Stage 4: Templating     |  | Stage 5: Reconciliation  |  | Stage 6: Validation & Scoring    |  |  |
|  |  | - UUID / ID Parameter   |  | - OpenAPI Baseline Diff |  | - Multi-Sample Soft-404 Engine   |  |  |
|  |  | - Route Deduplication   |  | - Shadow / Zombie Flags  |  | - Monotonic Math Risk Formula    |  |  |
|  |  +-------------------------+  +--------------------------+  +----------------------------------+  |  |
|  +---------------------------------------------------------------------------------------------------+  |
|                                       | Read / Write Transactions (WAL Mode)                            |
|                                       v                                                                 |
|  +---------------------------------------------------------------------------------------------------+  |
|  | PERSISTENCE TIER: SQLite Relational Database Engine (WAL Mode, PRAGMA synchronous=NORMAL)          |  |
|  |  - targets Table     - scans Table     - endpoints Table     - findings Table     - audit_logs    |  |
|  +---------------------------------------------------------------------------------------------------+  |
+---------------------------------------------------------------------------------------------------------+
</div>

<h2>3.2 The 6-Stage Autonomous Discovery & Auditing Pipeline</h2>
<p>
The core intelligence of ShadowTrace resides in its deterministic 6-stage discovery and auditing pipeline. Each scan job progresses sequentially through these six distinct phases, emitting progress events to connected clients via Server-Sent Events (SSE):
</p>
<ul>
  <li><strong>Stage 1: Pre-Flight Validation & SSRF Guardrail Verification:</strong> Normalizes the target URL, extracts the canonical host, executes DNS pre-resolution, and tests all candidate IP addresses against zero-trust private network blacklists. If an IP resolves to private subnets or cloud metadata, the scan is rejected immediately.</li>
  <li><strong>Stage 2: Passive Spidering & Asset Harvesting:</strong> Initiates breadth-first HTTP crawling of the target domain. Parses HTML documents to harvest script tags, stylesheets, client manifests, and navigational links up to configured crawl depth.</li>
  <li><strong>Stage 3: JavaScript Lexical Parsing & Source Map Reconstruction:</strong> Downloads external and inline script bundles. Applies lexical tokenization and AST regex extractors to discover API calls (fetch, axios, ajax). Probes for corresponding <code>.map</code> files to reconstruct original developer source files.</li>
  <li><strong>Stage 4: Dynamic Parameter Tokenization & Route Normalization:</strong> Passes all discovered URL strings through the path templating engine. Concrete resource identifiers (UUIDs, sequential numbers, hashes, slugs) are tokenized into parameterized schemas to prevent route explosion.</li>
  <li><strong>Stage 5: OpenAPI Baseline Differential Reconciliation:</strong> Compares normalized routes against uploaded OpenAPI / Swagger baseline documentation. Flags undocumented routes as <em>Shadow APIs</em>, unretired old versions as <em>Zombie APIs</em>, and missing controllers as <em>Orphaned APIs</em>.</li>
  <li><strong>Stage 6: Safe Heuristic Validation & Monotonic Risk Scoring:</strong> Performs multi-sample soft-404 baseline calibration, validates live endpoint status codes via safe GET/HEAD requests, evaluates 17 security rules, and computes bounded mathematical risk scores.</li>
</ul>

<h2>3.3 Concurrency, Async Scheduling & Queue Backpressure Management</h2>
<p>
To ensure high scanning throughput without overwhelming target infrastructure or exceeding system memory limits, the discovery engine is constructed entirely upon Python's native <code>asyncio</code> event loop. Key concurrency features include:
</p>
<ul>
  <li><strong>Semaphore-Bounded Worker Pools:</strong> Network requests are throttled using <code>asyncio.Semaphore</code> to limit concurrent connections per target host (default: 10 concurrent requests). This prevents denial-of-service conditions on target servers.</li>
  <li><strong>Async Connection Pooling via HTTPX:</strong> Connection reuse, HTTP/2 multiplexing, and keep-alive socket pools are managed via <code>httpx.AsyncClient</code>, minimizing TCP handshake and TLS negotiation overhead.</li>
  <li><strong>Streaming Event Pipeline:</strong> Scan events, discovered endpoints, and security findings are queued in memory and flushed asynchronously to the persistence layer and SSE broadcast channels, eliminating I/O bottlenecks.</li>
</ul>

<h2>3.4 SQLite Write-Ahead Logging (WAL) Mode Transactional Model</h2>
<p>
While standard SQLite locks the entire database file during write transactions (causing <code>database is locked</code> errors under concurrent web and scanning workloads), ShadowTrace configures SQLite in <strong>Write-Ahead Logging (WAL) mode</strong>.
</p>
<p>
In WAL mode, readers do not block writers, and writers do not block readers. Changes are written to a separate <code>-wal</code> journal file and periodically checkpointed back to the primary database file. The initialization sequence executes the following performance pragmas:
</p>
<pre>
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA cache_size=-64000; -- 64MB memory cache
PRAGMA foreign_keys=ON;
</pre>
<p>
This configuration allows the background scanner to write continuous endpoint discoveries and finding records at high velocity while the web server concurrently serves dashboard queries and SSE streams to operators with zero locking latency.
</p>
"""
