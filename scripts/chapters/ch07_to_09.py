# -*- coding: utf-8 -*-
"""
Chapters 7, 8, and 9 for ShadowTrace engineering documentation.
"""

def get_ch07_to_09():
    return """
<!-- CHAPTER 7: SECURITY DETECTION RULESET & VULNERABILITY CATALOG -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 7</div>
  <h1 class="chapter-title">Security Detection Ruleset & Vulnerability Catalog</h1>
</div>

<h2>7.1 Comprehensive Ruleset Catalog (Rules ST-001 through ST-017)</h2>
<p>
ShadowTrace enforces a standardized, modular detection engine comprising 17 distinct vulnerability and security hygiene rules. Each rule is mapped to formal industry taxonomies, including the OWASP API Security Top 10 (2023), Common Weakness Enumeration (CWE), and CVSS v3.1 impact vectors:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 10%;">Rule ID</th>
      <th style="width: 25%;">Vulnerability Title</th>
      <th style="width: 12%;">Severity</th>
      <th style="width: 20%;">OWASP / CWE Mapping</th>
      <th style="width: 33%;">Detection Mechanism & Indicator</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code>ST-001</code></td>
      <td>Unauthenticated Administrative Endpoint</td>
      <td><span class="badge badge-critical">Critical</span></td>
      <td>OWASP API1:2023<br/>CWE-306 (Missing Auth)</td>
      <td>Administrative path (<code>/admin</code>, <code>/internal</code>, <code>/debug</code>) returns HTTP 200 without auth challenge.</td>
    </tr>
    <tr>
      <td><code>ST-002</code></td>
      <td>Broken Object-Level Auth (BOLA) Heuristic</td>
      <td><span class="badge badge-high">High</span></td>
      <td>OWASP API1:2023<br/>CWE-639 (IDOR)</td>
      <td>Resource identifier parameter accessible across unprivileged token permutations.</td>
    </tr>
    <tr>
      <td><code>ST-003</code></td>
      <td>Sensitive Data Exposure in API Payload</td>
      <td><span class="badge badge-high">High</span></td>
      <td>OWASP API3:2023<br/>CWE-200 (Info Leak)</td>
      <td>Response contains unmasked PII (SSN, credit cards), password hashes, or private keys.</td>
    </tr>
    <tr>
      <td><code>ST-004</code></td>
      <td>Excessive Data Exposure / Schema Drift</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API3:2023<br/>CWE-213 (Over-fetching)</td>
      <td>API returns backend database model fields (e.g., <code>password_salt</code>, <code>internal_id</code>) omitted from OpenAPI spec.</td>
    </tr>
    <tr>
      <td><code>ST-005</code></td>
      <td>Broken Authentication / Missing Token</td>
      <td><span class="badge badge-high">High</span></td>
      <td>OWASP API2:2023<br/>CWE-287 (Improper Auth)</td>
      <td>State-sensitive route accessible without <code>Authorization</code> header or session cookie.</td>
    </tr>
    <tr>
      <td><code>ST-006</code></td>
      <td>Missing Rate Limiting Headers</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API4:2023<br/>CWE-799 (Uncontrolled Resource)</td>
      <td>Absence of standard rate-limiting headers (<code>X-RateLimit-*</code>, <code>Retry-After</code>) on public routes.</td>
    </tr>
    <tr>
      <td><code>ST-007</code></td>
      <td>Permissive Wildcard CORS Configuration</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API7:2023<br/>CWE-942 (Permissive CORS)</td>
      <td>Response emits <code>Access-Control-Allow-Origin: *</code> combined with credentials or sensitive endpoints.</td>
    </tr>
    <tr>
      <td><code>ST-008</code></td>
      <td>Verbose Server Headers & Stack Trace</td>
      <td><span class="badge badge-low">Low</span></td>
      <td>OWASP API7:2023<br/>CWE-209 (Error Disclosure)</td>
      <td>Responses leak precise server software versions (<code>Server</code>, <code>X-Powered-By</code>) or unhandled stack traces.</td>
    </tr>
    <tr>
      <td><code>ST-009</code></td>
      <td>Insecure HTTP Methods Permitted</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API7:2023<br/>CWE-650 (Insecure Methods)</td>
      <td>OPTIONS probe reveals support for dangerous or obsolete HTTP methods (<code>TRACE</code>, <code>TRACK</code>, <code>DEBUG</code>).</td>
    </tr>
    <tr>
      <td><code>ST-010</code></td>
      <td>Secret Leakage in Client Script Bundles</td>
      <td><span class="badge badge-high">High</span></td>
      <td>OWASP API9:2023<br/>CWE-798 (Hardcoded Creds)</td>
      <td>JavaScript bundle contains hardcoded cloud API keys (AWS, GitHub, Stripe, Private Keys).</td>
    </tr>
    <tr>
      <td><code>ST-011</code></td>
      <td>GraphQL Introspection Enabled in Production</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API7:2023<br/>CWE-16 (Configuration)</td>
      <td><code>__schema</code> introspection query successfully returns entire private GraphQL schema definition.</td>
    </tr>
    <tr>
      <td><code>ST-012</code></td>
      <td>GraphQL Excessive Query Depth / DoS Vector</td>
      <td><span class="badge badge-low">Low</span></td>
      <td>OWASP API4:2023<br/>CWE-400 (Resource Exhaustion)</td>
      <td>GraphQL endpoint lacks nested query depth limiting or batch request throttling controls.</td>
    </tr>
    <tr>
      <td><code>ST-013</code></td>
      <td>Undocumented Shadow API Endpoint</td>
      <td><span class="badge badge-high">High</span></td>
      <td>OWASP API9:2023<br/>CWE-1059 (Missing Spec)</td>
      <td>Active, reachable endpoint discovered during crawl that is completely absent from OpenAPI baseline.</td>
    </tr>
    <tr>
      <td><code>ST-014</code></td>
      <td>Orphaned API Route Detected</td>
      <td><span class="badge badge-low">Low</span></td>
      <td>OWASP API9:2023<br/>CWE-656 (Dead Code Route)</td>
      <td>Endpoint declared in OpenAPI baseline returns persistent HTTP 404/502/503 errors during active probing.</td>
    </tr>
    <tr>
      <td><code>ST-015</code></td>
      <td>Legacy Zombie API Version Reachable</td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>OWASP API9:2023<br/>CWE-1104 (Deprecated Code)</td>
      <td>Deprecated API version route (e.g., <code>/v1/</code>) responds successfully when modern <code>/v2/</code> is standard.</td>
    </tr>
    <tr>
      <td><code>ST-016</code></td>
      <td>Publicly Accessible Swagger / OpenAPI UI</td>
      <td><span class="badge badge-low">Low</span></td>
      <td>OWASP API7:2023<br/>CWE-200 (Recon Disclosure)</td>
      <td>Interactive API documentation UI exposed to unauthenticated public internet users.</td>
    </tr>
    <tr>
      <td><code>ST-017</code></td>
      <td>Catch-All Route / Soft-404 Observation</td>
      <td><span class="badge badge-info">Info</span></td>
      <td>Informational / Routing Architecture Observation</td>
      <td>Domain operates an SPA fallback catch-all router; documented for architectural record.</td>
    </tr>
  </tbody>
</table>

<h2>7.2 Deep-Dive into High-Risk Detection Modules & Triggers</h2>

<h3>Rule ST-001: Unauthenticated Administrative Endpoint (Critical)</h3>
<p>
Administrative interfaces control user roles, system configurations, and database management operations. When such interfaces are exposed to the public internet without requiring authentication (or when misconfigured reverse proxies bypass authentication middleware), attackers can achieve instant, total compromise.
</p>
<p>
<strong>Detection Trigger:</strong> ShadowTrace flags ST-001 when an endpoint whose path matches sensitive administrative lexical patterns (<code>/admin/</code>, <code>/internal/</code>, <code>/dashboard/</code>, <code>/actuator/</code>, <code>/system/</code>) returns an HTTP status code in the 200–299 range, serves a non-empty payload, and does not redirect to a login gateway.
</p>
<p>
<strong>Sample Probing Sequence:</strong>
</p>
<pre>
GET /api/internal/debug-console HTTP/1.1
Host: target-api.production.example
Accept: application/json
X-Scanner: ShadowTrace-Audit

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 342

{
  "status": "ready",
  "environment": "production",
  "active_sessions": 1420,
  "internal_queue": "celery-default",
  "database_host": "db-cluster-primary.internal.local",
  "debug_mode": true
}
</pre>

<h3>Rule ST-010: Secret Disclosure in Client Script Bundles (High)</h3>
<p>
Modern frontend builds frequently incorporate third-party cloud SDKs (AWS S3, Firebase, Stripe, GitHub). Inexperienced developers often embed backend private tokens directly into client-side code instead of managing secrets on a backend server or utilizing short-lived token exchange protocols.
</p>
<p>
<strong>Detection Trigger:</strong> The lexical analyzer executes high-precision regular expressions against downloaded JavaScript bundles, looking for known credential formats:
</p>
<ul>
  <li><strong>Amazon Web Services (AWS) Access Keys:</strong> <code>AKIA[0-9A-Z]{16}</code></li>
  <li><strong>GitHub Personal Access Tokens:</strong> <code>ghp_[a-zA-Z0-9]{36}</code></li>
  <li><strong>Stripe Live Secret Keys:</strong> <code>sk_live_[0-9a-zA-Z]{24}</code></li>
  <li><strong>Generic High-Entropy API Secrets:</strong> <code>api[_-]?key\\s*[:=]\s*['"][a-zA-Z0-9\-_]{24,}['"]</code></li>
</ul>

<h3>Rule ST-013: Undocumented Shadow API Endpoint (High)</h3>
<p>
The core objective of ShadowTrace is identifying Shadow APIs. When an engineering team develops features out of sync with central API governance, routes go live without security reviews, vulnerability testing, or rate-limiting enforcement.
</p>
<p>
<strong>Detection Trigger:</strong> An endpoint is flagged as ST-013 when all of the following conditions are met:
</p>
<ol>
  <li>The route is actively discovered via crawler, script parsing, or source map reconstruction.</li>
  <li>The route returns a valid API response (HTTP 200, 401, 403, or 405) that passes soft-404 entropy validation.</li>
  <li>The normalized path schema does not match any route declared in the ingested OpenAPI/Swagger baseline.</li>
</ol>

<h2>7.3 Technical Remediation Blueprint Across Multiple Frameworks</h2>
<p>
To assist engineering teams in rapidly resolving identified vulnerabilities, ShadowTrace provides concrete code-level remediation patterns across primary enterprise web frameworks:
</p>

<h3>Remediation for ST-001 / ST-005 (Mandatory Authentication Middleware)</h3>
<pre>
# Python (FastAPI): Enforce JWT Authentication Dependency on Protected Routes
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    if not validate_jwt_signature(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token"
        )
    return token

admin_router = APIRouter(prefix="/api/internal", dependencies=[Depends(verify_token)])
</pre>

<h3>Remediation for ST-007 (Strict CORS Configuration in Node.js Express)</h3>
<pre>
// Node.js (Express): Restrict CORS to Explicit Whitelisted Origins
const cors = require('cors');

const allowedOrigins = [
  'https://app.example.com',
  'https://admin.example.com'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      callback(new Error('CORS policy: Access denied for this origin.'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']
}));
</pre>

<h3>Remediation for ST-008 (Stripping Server Version Headers in Nginx)</h3>
<pre>
# Nginx Reverse Proxy: Suppress Server Footprints and Error Disclosure
server {
    listen 443 ssl http2;
    server_name api.example.com;

    # Disable Nginx version in Server header and default error pages
    server_tokens off;

    # Strip upstream application headers that leak framework versions
    proxy_hide_header X-Powered-By;
    proxy_hide_header X-AspNet-Version;
    proxy_hide_header Server;

    # Generic error intercept
    proxy_intercept_errors on;
    error_page 500 502 503 504 /custom_error.json;
}
</pre>

<!-- CHAPTER 8: MATHEMATICAL RISK SCORING MODEL & REMEDIATION PRIORITIZATION -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 8</div>
  <h1 class="chapter-title">Mathematical Risk Scoring Model & Remediation Prioritization</h1>
</div>

<h2>8.1 Mathematical Risk Formula & Variable Definitions</h2>
<p>
A persistent failure of commercial vulnerability management platforms is arbitrary, opaque risk scoring. Commercial tools frequently assign arbitrary 1–10 scores based on subjective proprietary algorithms, creating inconsistent prioritization across different audit runs.
</p>
<p>
ShadowTrace introduces a deterministic, formal <strong>Mathematical Risk Scoring Model</strong>. The risk score for each identified finding is bounded strictly between 0 and 100 and calculated as a function of four primary variables:
</p>
<div class="callout callout-info">
  <strong>The ShadowTrace Formal Risk Formula:</strong><br/>
  <code>RiskScore = min(100, round( S_base * C_factor * E_multiplier + V_penalty ))</code>
</div>

<p>
The mathematical parameters are defined as follows:
</p>
<ul>
  <li><strong>Base Severity Score ($S_{base}$):</strong> The intrinsic theoretical severity of the vulnerability class based on CVSS v3.1 impact:
    <ul>
      <li>Critical (ST-001, ST-002): $S_{base} = 90.0$</li>
      <li>High (ST-003, ST-005, ST-010, ST-013): $S_{base} = 70.0$</li>
      <li>Medium (ST-004, ST-006, ST-007, ST-009, ST-011, ST-015): $S_{base} = 45.0$</li>
      <li>Low (ST-008, ST-012, ST-014, ST-016): $S_{base} = 20.0$</li>
      <li>Informational (ST-017): $S_{base} = 5.0$</li>
    </ul>
  </li>
  <li><strong>Confidence Factor ($C_{factor} \in [0.5, 1.0]$):</strong> The empirical reliability of the discovery method:
    <ul>
      <li>$C = 1.0$: Verified via direct runtime HTTP response with status code 200 and valid JSON body.</li>
      <li>$C = 0.85$: Extracted via unminified source map reconstruction with confirmed route syntax.</li>
      <li>$C = 0.70$: Discovered via client script regex matching; unconfirmed active status.</li>
      <li>$C = 0.50$: Inferred via soft-404 heuristic or ambiguous static string literal.</li>
    </ul>
  </li>
  <li><strong>Exposure Multiplier ($E_{multiplier} \in [0.8, 1.2]$):</strong> The environmental accessibility of the endpoint:
    <ul>
      <li>$E = 1.2$: Public apex domain accessible without authentication or IP restrictions.</li>
      <li>$E = 1.0$: Subdomain or internal route requiring standard user session credentials.</li>
      <li>$E = 0.8$: Internal staging or administrative host protected by network access controls.</li>
    </ul>
  </li>
  <li><strong>Verified Exploitability Penalty ($V_{penalty} \in \{0, 10\}$):</strong>
    <ul>
      <li>$V = +10$: If the active verification probe confirmed that sensitive data (PII, credentials, debug objects) was directly returned in the response payload.</li>
      <li>$V = 0$: Standard configuration or route observation without immediate data leakage.</li>
    </ul>
  </li>
</ul>

<h2>8.2 Formal Proof of Monotonicity & Bounded Range [0, 100]</h2>
<p>
To ensure that security teams can trust the automated ranking, the scoring function satisfies a crucial mathematical property: <strong>Monotonic Severity Ordering</strong>. A finding with higher base severity must always outrank a finding of lower base severity under equivalent confidence and exposure parameters.
</p>
<p>
<strong>Proof Sketch:</strong><br/>
Let $A$ and $B$ be two findings such that $S_{base}(A) > S_{base}(B)$. For fixed confidence $C$ and exposure $E$:
</p>
<pre>
RiskScore(A) - RiskScore(B) = (S_base(A) - S_base(B)) * C * E + (V(A) - V(B))
</pre>
<p>
Since $C \ge 0.5$ and $E \ge 0.8$, the product $C \times E \ge 0.40$. Across our calibrated severity steps:
</p>
<ul>
  <li>Critical vs High: $\Delta S_{base} = 90 - 70 = 20$. Minimum score delta: $20 \times 0.4 = 8.0$.</li>
  <li>High vs Medium: $\Delta S_{base} = 70 - 45 = 25$. Minimum score delta: $25 \times 0.4 = 10.0$.</li>
  <li>Medium vs Low: $\Delta S_{base} = 45 - 20 = 25$. Minimum score delta: $25 \times 0.4 = 10.0$.</li>
  <li>Low vs Info: $\Delta S_{base} = 20 - 5 = 15$. Minimum score delta: $15 \times 0.4 = 6.0$.</li>
</ul>
<p>
Because the maximum negative exploitability penalty offset $(V_B - V_A)$ cannot exceed 10 under equal conditions, the calibrated boundary tiers guarantee that high-severity findings reliably outrank lower-severity findings, preventing misallocated remediation effort.
</p>

<h2>8.3 Automated Severity Bucketing & Enterprise Remediation SLAs</h2>
<p>
Once the mathematical risk score is computed, ShadowTrace maps the numerical score into standardized enterprise severity buckets and assigns recommended Service Level Agreement (SLA) remediation deadlines:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 15%;">Risk Score Range</th>
      <th style="width: 15%;">Severity Tier</th>
      <th style="width: 20%;">Recommended Remediation SLA</th>
      <th style="width: 50%;">Operational Response Protocol</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>85 – 100</strong></td>
      <td><span class="badge badge-critical">Critical</span></td>
      <td>Within 24 Hours</td>
      <td>Immediate incident response escalation. Block route at API Gateway or WAF level immediately; revoke exposed credentials; initiate forensic log audit.</td>
    </tr>
    <tr>
      <td><strong>65 – 84</strong></td>
      <td><span class="badge badge-high">High</span></td>
      <td>Within 7 Days</td>
      <td>Assign to owning engineering team for priority patch. Ingest route into central OpenAPI catalog and enforce mandatory authentication middleware.</td>
    </tr>
    <tr>
      <td><strong>40 – 64</strong></td>
      <td><span class="badge badge-medium">Medium</span></td>
      <td>Within 30 Days</td>
      <td>Schedule for upcoming sprint release. Update CORS whitelists, enforce rate-limiting headers, and decommission unneeded legacy v1 endpoints.</td>
    </tr>
    <tr>
      <td><strong>15 – 39</strong></td>
      <td><span class="badge badge-low">Low</span></td>
      <td>Within 90 Days</td>
      <td>General engineering hygiene. Strip server version banners, disable public Swagger UI in production environments, and clean up orphaned routes.</td>
    </tr>
    <tr>
      <td><strong>0 – 14</strong></td>
      <td><span class="badge badge-info">Informational</span></td>
      <td>No Fixed SLA</td>
      <td>Architectural observation. Logged in inventory catalog for audit trail completeness and routing topology documentation.</td>
    </tr>
  </tbody>
</table>

<!-- CHAPTER 9: DEFENSE-IN-DEPTH & SSRF PROTECTION ARCHITECTURE -->
<div class="chapter-header">
  <div class="chapter-kicker">CHAPTER 9</div>
  <h1 class="chapter-title">Defense-in-Depth & SSRF Protection Architecture</h1>
</div>

<h2>9.1 The SSRF Threat Vector in Automated Security Tools</h2>
<p>
Automated vulnerability scanners and crawling tools are uniquely attractive targets for <strong>Server-Side Request Forgery (SSRF)</strong> attacks. Because a scanner accepts user-supplied URLs and issues outbound HTTP requests on behalf of the operator, an attacker with access to the tool can attempt to input malicious URLs pointing to internal private infrastructure:
</p>
<pre>
http://127.0.0.1:8000/admin/
http://10.0.0.15/internal-api/keys
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://[::1]:5432/
</pre>
<p>
If the scanning engine blindly issues requests to these addresses, it acts as a weaponized internal proxy. An attacker can use the scanner to steal cloud instance credentials from the AWS metadata service, interact with internal Redis or PostgreSQL databases, or access unauthenticated microservices inside a private VPC.
</p>

<h2>9.2 Zero-Trust IP Validation Engine & RFC Blacklist Mapping</h2>
<p>
To ensure absolute isolation, ShadowTrace implements a multi-layer <strong>Zero-Trust SSRF Barrier</strong>. Every target URL and discovered endpoint candidate must pass through a strict pre-flight network validation engine before any TCP connection or HTTP request is initiated.
</p>
<p>
The validation engine performs pre-resolution of target hostnames and verifies that every resolved IP address does not fall within restricted, private, or reserved network CIDR blocks:
</p>

<table>
  <thead>
    <tr>
      <th style="width: 25%;">Network Classification</th>
      <th style="width: 30%;">Restricted IP Range / CIDR</th>
      <th style="width: 45%;">Security Justification & Threat Vector</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><strong>Loopback Addresses</strong></td>
      <td><code>127.0.0.0/8</code>, <code>::1/128</code></td>
      <td>Blocks requests to the scanner host itself (local admin panels, local databases, localhost ports).</td>
    </tr>
    <tr>
      <td><strong>RFC 1918 Private IPv4</strong></td>
      <td><code>10.0.0.0/8</code><br/><code>172.16.0.0/12</code><br/><code>192.168.0.0/16</code></td>
      <td>Blocks internal corporate intranets, private enterprise VPCs, and local network equipment.</td>
    </tr>
    <tr>
      <td><strong>Link-Local / Cloud Metadata</strong></td>
      <td><code>169.254.0.0/16</code><br/><code>fe80::/10</code></td>
      <td><strong>CRITICAL:</strong> Blocks AWS, GCP, Azure, and OpenStack instance metadata endpoints (<code>169.254.169.254</code>).</td>
    </tr>
    <tr>
      <td><strong>Carrier-Grade NAT (CGNAT)</strong></td>
      <td><code>100.64.0.0/10</code></td>
      <td>Blocks ISP shared address space and internal telecom routing boundaries (RFC 6598).</td>
    </tr>
    <tr>
      <td><strong>Documentation & Testnets</strong></td>
      <td><code>192.0.2.0/24</code>, <code>198.51.100.0/24</code><br/><code>203.0.113.0/24</code></td>
      <td>Blocks reserved non-routable documentation subnets (RFC 5737).</td>
    </tr>
    <tr>
      <td><strong>Multicast & Broadcast</strong></td>
      <td><code>224.0.0.0/4</code>, <code>255.255.255.255/32</code></td>
      <td>Blocks multicast group communications and local broadcast networks.</td>
    </tr>
  </tbody>
</table>

<h2>9.3 Anti-DNS-Rebinding Socket Pinning Architecture</h2>
<p>
A common vulnerability in naive SSRF defenses is the <strong>Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding attack</strong>. In this attack:
</p>
<ol>
  <li>An attacker configures a domain name (e.g., <code>rebind.attacker.com</code>) with a very low DNS Time-To-Live (TTL = 0 seconds).</li>
  <li>When ShadowTrace performs pre-flight validation, the domain resolves to a benign public IP (e.g., <code>1.1.1.1</code>). The pre-flight check passes.</li>
  <li>Millisecond later, when the HTTP client actually initiates the connection, the attacker's DNS server answers with <code>169.254.169.254</code> or <code>127.0.0.1</code>! The HTTP client connects directly to the private target, bypassing the pre-flight check.</li>
</ol>
<p>
To eliminate DNS rebinding entirely, ShadowTrace employs <strong>Socket-Level IP Pinning</strong>. The engine performs explicit DNS resolution up front, validates the IP address, and establishes the TCP socket directly to the validated IP address, passing the original domain name exclusively in the HTTP <code>Host</code> header and TLS Server Name Indication (SNI) extension. This eliminates any secondary DNS lookup, guaranteeing that the IP verified during pre-flight is the exact IP connected to at the socket level.
</p>
"""
