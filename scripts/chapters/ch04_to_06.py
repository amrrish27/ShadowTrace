# -*- coding: utf-8 -*-
"""
Chapters 4, 5, and 6 for ShadowTrace engineering documentation.
"""

def get_ch04_to_06():
    return """
<!-- CHAPTER 4: DISCOVERY ENGINE & PASSIVE CRAWLING SUBSYSTEM -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 4</div>
  <h1 class="chapter-title">Discovery Engine & Passive Crawling Subsystem</h1>
</div>

<h2>4.1 Breadth-First Web Spidering & Asset Harvesting</h2>
<p>
The discovery pipeline begins with a deterministic breadth-first web spidering engine designed to traverse the target domain's public web surface without triggering defensive bot blocks or exceeding resource constraints. The crawler initiates from the root target URL and extracts links and embedded assets up to a configurable depth limit (default: 3 levels).
</p>
<p>
To ensure focused and ethical testing, the spider enforces strict boundary constraints:
</p>
<ul>
  <li><strong>Same-Origin & In-Scope Domain Boundary:</strong> The spider resolves candidate URLs and rejects any outbound link pointing outside the target apex domain or authorized subdomains.</li>
  <li><strong>Media & Binary Exclusion Filters:</strong> High-bandwidth binary assets (images, videos, audio, PDF documents, fonts, compressed archives) are filtered out via file extension matching and pre-flight MIME type checks, conserving network bandwidth.</li>
  <li><strong>Visited Set Deduplication:</strong> URLs are canonicalized (stripping tracking fragments, UTM query parameters, and normalizing trailing slashes) and checked against an in-memory SHA-256 hash set to prevent circular link loops.</li>
</ul>

<h2>4.2 JavaScript Lexical Parsing & Abstract Syntax Tree Tokenization</h2>
<p>
Modern Single-Page Applications (SPAs) built with React, Vue, Angular, Svelte, or Next.js do not expose application navigation in traditional HTML anchor tags (<code>&lt;a href="..."&gt;</code>). Instead, routes are declared inside client-side router configurations (React Router, Vue Router) and invoked via dynamic HTTP clients (Fetch API, Axios, jQuery AJAX).
</p>
<p>
To uncover these hidden endpoints, ShadowTrace implements a dedicated JavaScript Lexical Tokenizer and Abstract Syntax Tree (AST) analyzer. As script assets are harvested, the parser executes a series of optimized multi-stage regular expression extractors:
</p>

<pre>
// Comprehensive Lexical Extraction Patterns for Client-Side Script Bundles
const FETCH_AXIOS_REGEX = /(?:fetch|axios(?:\.get|\.post|\.put|\.delete|\.patch)?)\s*\(\s*['"`]([a-zA-Z0-9_\-\.\/:\$]+)['"`]/gi;
const API_PREFIX_REGEX = /['"`](\/(?:api|v[0-9]+|rest|graphql|internal|auth|v1|v2|v3)\/[a-zA-Z0-9_\-\.\/]+)['"`]/gi;
const ENDPOINT_STRING_REGEX = /['"`](https?:\/\/[a-zA-Z0-9_\-\.:]+\/(?:api|v[0-9]+)\/[a-zA-Z0-9_\-\.\/]+)['"`]/gi;
</pre>

<p>
The lexical parser extracts string literals matching standard API path conventions, template strings (e.g., <code>`/api/users/${userId}/profile`</code>), and relative path constants. Discovered candidates are normalized and queued for parameter templating and verification.
</p>

<h2>4.3 Source Map Reconstruction & Developer Code Recovery</h2>
<p>
One of ShadowTrace's most potent offensive and defensive capabilities is its automated <strong>Source Map (.map) Reconstruction Engine</strong>. When developers build modern frontend applications using Vite, Webpack, esbuild, or Rollup, production source code is typically minified, obfuscated, and bundled into monolithic JavaScript files.
</p>
<p>
However, development and DevOps teams frequently neglect to disable source map generation or inadvertently deploy <code>.js.map</code> files to public production servers. Source maps contain a complete, unminified snapshot of the original developer repository, including original file paths, TypeScript source files, unredacted comments, private backend route definitions, and internal API URLs.
</p>

<div class="diagram-box">
+---------------------------------------------------------------------------------------------------------+
|                                SOURCE MAP RECONSTRUCTION & CODE HARVESTING                              |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|  Production Web Asset:              Source Map Probe:                  Developer Source Recovery:       |
|  +-----------------------+          +------------------------+         +-----------------------------+  |
|  | /assets/app-x92f.js   | -------> | /assets/app-x92f.js.map| ------> | - src/api/adminController.ts|  |
|  | (Minified & Obfuscated|          | (V3 Source Map JSON)   |         | - src/services/auth.service |  |
|  |  Variables a, b, c)   |          | - sources: [...]       |         | - Internal Routes:          |  |
|  +-----------------------+          | - sourcesContent: [...]|         |   /api/internal/debug-tools |  |
|                                     +------------------------+         |   /api/v1/legacy-login      |  |
|                                                                        +-----------------------------+  |
+---------------------------------------------------------------------------------------------------------+
</div>

<p>
ShadowTrace's source map engine checks for source map references via two parallel mechanisms:
</p>
<ol>
  <li><strong>SourceMappingURL Comment Inspection:</strong> Reads the trailing comment syntax in downloaded JS files (<code>//# sourceMappingURL=bundle.js.map</code>).</li>
  <li><strong>Heuristic Suffix Probing:</strong> If no explicit comment is found, issues a safe HEAD probe appending <code>.map</code> to the script URI.</li>
</ol>
<p>
When a source map is detected, ShadowTrace downloads the JSON payload, validates the <code>version: 3</code> schema, iterates over the <code>sources</code> and <code>sourcesContent</code> arrays, and extracts raw developer source files. The lexical analyzer then scans the recovered source code for hidden administrative routes, development staging endpoints, and hardcoded authentication secrets.
</p>

<h2>4.4 Well-Known Security Metadata & Documentation Route Probing</h2>
<p>
In addition to spidering and script analysis, the discovery subsystem probes a curated catalog of standard "well-known" security metadata and API documentation locations:
</p>
<ul>
  <li><strong>OpenAPI & Swagger Documentation:</strong> Probes standard developer documentation routes including <code>/openapi.json</code>, <code>/swagger.json</code>, <code>/api/docs</code>, <code>/swagger-ui.html</code>, and <code>/v2/api-docs</code>. If an active specification is discovered, it is automatically passed to the baseline reconciliation engine.</li>
  <li><strong>GraphQL Schema Discovery:</strong> Probes common GraphQL entry points (<code>/graphql</code>, <code>/api/graphql</code>, <code>/v1/graphql</code>) and issues safe introspection queries to determine if schema exploration is publicly accessible.</li>
  <li><strong>Crawler & Security Directives:</strong> Inspects <code>/robots.txt</code>, <code>/sitemap.xml</code>, and <code>/.well-known/security.txt</code> for disallow entries and administrative paths that developers inadvertently disclose to web spiders.</li>
</ul>

<!-- CHAPTER 5: ROUTE NORMALIZATION, PARAMETER TEMPLATING & BASELINE RECONCILIATION -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 5</div>
  <h1 class="chapter-title">Normalization, Parameter Templating & Baseline Reconciliation</h1>
</div>

<h2>5.1 Mitigating Combinatorial Route Explosion</h2>
<p>
In modern RESTful architectures, entity identifiers are embedded directly into the URI hierarchy. For example, an e-commerce application might expose routes such as:
</p>
<pre>
/api/v2/organizations/d3b07384-d113-4ac4-a5ef-e6c9a912a23e/users/4921/orders/78291
/api/v2/organizations/a1c9e831-f402-4822-9b21-438902c4819a/users/5832/orders/19402
/api/v2/organizations/f47ac10b-58cc-4372-a567-0e02b2c3d479/users/1029/orders/94821
</pre>
<p>
To a naive web crawler, these three URLs appear as three distinct API endpoints. In an active production application with thousands of users, orders, and assets, this lack of normalization causes <strong>Combinatorial Route Explosion</strong>. The scanner attempts to probe millions of identical endpoints, leading to memory exhaustion, scanner timeouts, and repetitive, unreadable audit reports.
</p>

<h2>5.2 Dynamic Parameter Detection Heuristics</h2>
<p>
ShadowTrace solves route explosion through an algorithmic <strong>Path Templating Engine</strong>. The engine parses raw URL paths, tokenizes each path segment, and executes a battery of deterministic regular expression classifiers to identify dynamic values:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Parameter Type</th>
      <th style="width: 35%;">Detection Regex / Heuristic</th>
      <th style="width: 40%;">Transformation Example</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>UUID (v1–v5)</strong></td>
      <td><code>^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$</code></td>
      <td><code>/users/d3b07384-.../profile</code> &rarr; <code>/users/{id}/profile</code></td>
    </tr>
    <tr>
      <td><strong>Sequential Integer ID</strong></td>
      <td><code>^[0-9]{1,18}$</code></td>
      <td><code>/orders/849204/invoice</code> &rarr; <code>/orders/{id}/invoice</code></td>
    </tr>
    <tr>
      <td><strong>Hexadecimal Hash</strong></td>
      <td><code>^[0-9a-fA-F]{16,64}$</code> (MD5, SHA-1, SHA-256)</td>
      <td><code>/files/e3b0c44298fc.../view</code> &rarr; <code>/files/{hash}/view</code></td>
    </tr>
    <tr>
      <td><strong>Base64 / Alphanumeric Slug</strong></td>
      <td><code>^[a-zA-Z0-9_\-]{20,}$</code> (High-entropy tokens)</td>
      <td><code>/tokens/eyJhbGciOi.../verify</code> &rarr; <code>/tokens/{token}/verify</code></td>
    </tr>
    <tr>
      <td><strong>Date / Timestamp</strong></td>
      <td><code>^\d{4}-\d{2}-\d{2}$</code> or <code>^\d{10,13}$</code></td>
      <td><code>/reports/2026-11-02/summary</code> &rarr; <code>/reports/{date}/summary</code></td>
    </tr>
  </tbody>
</table>

<p>
Once segments are templated, the path is reconstructed into its canonical schema: <code>/api/v2/organizations/{id}/users/{id}/orders/{id}</code>. Duplicate concrete instances are collapsed into a single canonical inventory record, reducing report clutter by up to 95% while preserving route structure.
</p>

<h2>5.3 OpenAPI / Swagger Baseline Specification Ingestion Engine</h2>
<p>
To perform differential security auditing, ShadowTrace provides a robust <strong>Baseline Ingestion Subsystem</strong> capable of parsing OpenAPI 3.0, OpenAPI 3.1, and Swagger 2.0 specifications formatted in either JSON or YAML.
</p>
<p>
When an operator uploads an API specification (or when one is discovered automatically during well-known route probing), the parser extracts:
</p>
<ul>
  <li><strong>Declared Paths & Operations:</strong> All documented path templates and allowed HTTP methods (GET, POST, PUT, DELETE, etc.).</li>
  <li><strong>Server Base URLs:</strong> Production, staging, and development host definitions.</li>
  <li><strong>Security Schemes:</strong> Declared authentication mechanisms (Bearer JWT, OAuth 2.0, API Key headers, HTTP Basic).</li>
  <li><strong>Deprecation Metadata:</strong> Endpoints explicitly flagged with <code>deprecated: true</code>.</li>
</ul>

<h2>5.4 Differential Reconciliation Matrix: Isolating Shadow vs Zombie Endpoints</h2>
<p>
With both runtime discovered endpoints and declared baseline specifications normalized into canonical schemas, the <strong>Differential Reconciliation Engine</strong> matches the two sets and categorizes each endpoint into one of four distinct states:
</p>

<div class="diagram-box">
+---------------------------------------------------------------------------------------------------------+
|                                DIFFERENTIAL BASELINE RECONCILIATION ENGINE                              |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|       Runtime Discovered Routes                       OpenAPI Baseline Specification                    |
|      +--------------------------+                      +--------------------------+                     |
|      | /api/v2/users/{id}       |                      | /api/v2/users/{id}       |                     |
|      | /api/v1/users/{id}       |                      | /api/v2/orders           |                     |
|      | /api/internal/debug      |                      |                          |                     |
|      +--------------------------+                      +--------------------------+                     |
|                   \                                                 /                                   |
|                    \                                               /                                    |
|                     v                                             v                                     |
|               +---------------------------------------------------------+                               |
|               |       RECONCILIATION ENGINE & DIFFERENTIAL MATCHER      |                               |
|               +---------------------------------------------------------+                               |
|                                            |                                                            |
|         +-------------------+--------------+---------------+--------------------+                       |
|         |                   |                              |                    |                       |
|         v                   v                              v                    v                       |
|   DOCUMENTED ACTIVE    SHADOW API (UNDOCUMENTED)      ZOMBIE API           ORPHANED API                 |
|   /api/v2/users/{id}   /api/internal/debug            /api/v1/users/{id}   /api/v2/orders               |
|   (In Spec & Active)   (Not in Spec, Active!)         (Deprecated Version) (In Spec, 404/503)           |
+---------------------------------------------------------------------------------------------------------+
</div>

<ul>
  <li><strong>Documented Active (Verified Standard):</strong> Routes present in the OpenAPI specification that successfully return valid responses during runtime probing.</li>
  <li><strong>Shadow API (Undocumented Active - High Risk):</strong> Routes discovered during runtime crawling or client bundle scraping that do not exist anywhere in the formal OpenAPI documentation.</li>
  <li><strong>Zombie API (Deprecated Active - Medium Risk):</strong> Routes marked as deprecated in the specification, or legacy version routes (<code>/v1/</code>) discovered active when the specification defines modern versions (<code>/v2/</code>).</li>
  <li><strong>Orphaned API (Documented Inactive - Low Risk):</strong> Routes declared in the OpenAPI specification that consistently return HTTP 404, 502, or 503 errors during runtime probing, indicating broken deployments or decommissioned upstream services.</li>
</ul>

<!-- CHAPTER 6: SAFE HEURISTIC VALIDATION & SOFT-404 MITIGATION ENGINE -->
<div class="chapter-header">
  <div class="chapter-number">CHAPTER 6</div>
  <h1 class="chapter-title">Safe Heuristic Validation & Soft-404 Mitigation Engine</h1>
</div>

<h2>6.1 The Single-Page Application (SPA) Catch-All Routing Challenge</h2>
<p>
One of the most pervasive failure modes in automated API security scanning is the <strong>Single-Page Application (SPA) Soft-404 problem</strong>. In standard server-rendered architectures (e.g., Apache, Nginx serving PHP or Java), requesting a non-existent URL (such as <code>/api/non-existent-endpoint-xyz</code>) causes the web server to emit a definitive <strong>HTTP 404 Not Found</strong> status code.
</p>
<p>
However, modern web architectures deploy Single-Page Applications behind reverse proxies configured with client-side catch-all routing rules (e.g., <code>try_files $uri $uri/ /index.html;</code>). Under this configuration, when a client requests any arbitrary path, the server responds with <strong>HTTP 200 OK</strong> and serves the root HTML bundle (<code>index.html</code>), allowing the client-side JavaScript router (Vue Router, React Router) to handle page rendering.
</p>
<p>
To an automated scanner lacking soft-404 compensation, every single probed path appears to be a valid, live API endpoint returning HTTP 200 OK! The scanner mistakenly flags hundreds of phantom endpoints, generating massive report noise and destroying analyst trust in the tool.
</p>

<h2>6.2 Multi-Sample Baseline Calibration & Entropy Analysis</h2>
<p>
ShadowTrace eliminates soft-404 false positives through a sophisticated <strong>Multi-Sample Baseline Calibration Subsystem</strong>. Prior to executing active route validation, the engine issues a sequence of randomized, guaranteed-non-existent probes to establish the target host's fallback behavior:
</p>
<ol>
  <li><strong>Random Token Path Probing:</strong> Generates three cryptographic random paths unlikely to exist on any system (e.g., <code>/__shadowtrace_calib_8f3a9d1c/</code>).</li>
  <li><strong>Response Signature Profiling:</strong> Captures the HTTP status code, response headers, Content-Type, body byte length, and raw HTML/text payload for each calibration probe.</li>
  <li><strong>Shannon Entropy Calculation:</strong> Computes the Shannon entropy of the response body to measure information density:
  <pre>
  H(X) = - SUM [ P(x_i) * log2(P(x_i)) ]
  </pre>
  HTML fallback pages exhibit characteristic entropy signatures distinct from structured JSON API payloads.</li>
</ol>

<h2>6.3 Algorithmic Soft-404 Differentiator & False-Positive Elimination</h2>
<p>
During active validation of discovered candidate routes, every response is evaluated against the established calibration baseline using a multi-factor comparison algorithm:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Comparison Factor</th>
      <th style="width: 40%;">Evaluation Criteria</th>
      <th style="width: 35%;">Classification Decision</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Content-Type Mismatch</strong></td>
      <td>Candidate path claimed to be API, but server returned <code>text/html</code> matching root SPA page.</td>
      <td><strong>Soft-404 (Catch-All):</strong> Flagged as client router fallback; suppressed from API findings.</td>
    </tr>
    <tr>
      <td><strong>Body Length Variance</strong></td>
      <td>Response length within &plusmn;2% of calibration baseline byte length.</td>
      <td><strong>Soft-404 (Catch-All):</strong> High probability of static HTML template fallback.</td>
    </tr>
    <tr>
      <td><strong>DOM Structure Similarity</strong></td>
      <td>Levenshtein text distance or HTML tag sequence matching baseline with &gt; 92% similarity.</td>
      <td><strong>Soft-404 (Catch-All):</strong> Confirmed SPA fallback page.</td>
    </tr>
    <tr>
      <td><strong>JSON Structured Payload</strong></td>
      <td>Response Content-Type is <code>application/json</code> with valid parseable JSON body.</td>
      <td><strong>Genuine API Endpoint:</strong> Validated as live backend API service.</td>
    </tr>
    <tr>
      <td><strong>Definitive 404 / 405</strong></td>
      <td>Server returns explicit HTTP 404 Not Found or 405 Method Not Allowed.</td>
      <td><strong>Genuine HTTP Route:</strong> Categorized as inactive or method-restricted route.</td>
    </tr>
  </tbody>
</table>

<h2>6.4 Non-Destructive Active Verification Protocol & Response Classification</h2>
<p>
Once candidate routes have been cleared of soft-404 catch-all interference, ShadowTrace executes its <strong>Non-Destructive Active Verification Protocol</strong>. The validator probes each canonical endpoint using safe, read-only HTTP methods:
</p>
<ul>
  <li><strong>Safe Method Probing (GET / HEAD):</strong> Emits a non-destructive GET request with standardized security evaluation headers (<code>Accept: application/json</code>, <code>X-Scanner: ShadowTrace-Audit</code>).</li>
  <li><strong>HTTP Options Exploration (OPTIONS):</strong> Issues an OPTIONS request to inspect the <code>Allow</code> and <code>Access-Control-Allow-Methods</code> response headers, cataloging supported backend HTTP verbs without invoking them.</li>
  <li><strong>Status Code Categorization:</strong>
    <ul>
      <li><code>200–299 (Success):</code> Endpoint is live, active, and accessible.</li>
      <li><code>401 Unauthorized / 403 Forbidden:</code> Endpoint exists and enforces authentication/authorization barriers.</li>
      <li><code>405 Method Not Allowed:</code> Endpoint exists but restricts GET; records supported methods from headers.</li>
      <li><code>500 Internal Server Error:</code> Endpoint exists but encountered an unhandled exception (potential vulnerability).</li>
    </ul>
  </li>
</ul>
"""
