"""ShadowLab — a deliberately flawed, synthetic target for ShadowTrace.

Safety of construction: this service performs no code execution, no file reads and
no injection on behalf of a caller.  Its weaknesses are *exposure* and
*configuration* facts that read-only requests can reveal.  Hostile responses are
bounded so they cannot harm the host even if the scanner's defences fail.

Run:  python lab/app/lab.py --host 127.0.0.1 --port 8099
"""
from __future__ import annotations

import argparse
import gzip
import json
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FAKE_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # documented AWS example value, not live
SERVER_BANNER = "nginx/1.18.0 (ShadowLab)"
LAB_VERSION = "2.0.0"

BASELINE = {
    "openapi": "3.0.3",
    "info": {"title": "ShadowLab Orders API", "version": "2.0.0"},
    "paths": {
        "/api/v1/orders": {
            "get": {"summary": "List orders", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "ok"}}}
        },
        "/api/v1/users/{userId}": {
            "get": {"summary": "Fetch a user", "security": [{"bearerAuth": []}], "responses": {"200": {"description": "ok"}}}
        },
        "/api/v2/users": {"get": {"summary": "List users", "responses": {"200": {"description": "ok"}}}},
        "/api/v2/profile": {"get": {"summary": "Current profile", "responses": {"200": {"description": "ok"}}}},
        "/api/v2/secure": {
            "get": {"summary": "Secured endpoint", "security": [{"bearerAuth": []}], "responses": {"401": {"description": "auth required"}}}
        },
        "/api/v2/orders": {"get": {"summary": "Orders (v2)", "responses": {"200": {"description": "ok"}}}},
        "/api/v2/reports": {"get": {"summary": "Reports (documented, removed)", "responses": {"200": {"description": "ok"}}}},
        "/api/v1/health": {"get": {"summary": "Health", "responses": {"200": {"description": "ok"}}}},
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

HOME_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShadowLab — Enterprise Edge Hardware & Cloud Systems</title>
  <meta name="api-base" content="/api/v1">
  <script src="/static/app.js" defer></script>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  <div class="top-bar">
    🚚 Complimentary express shipping on all enterprise hardware kits · Worldwide dispatch
  </div>

  <header class="site-header">
    <div class="header-container">
      <a href="/" class="brand-logo">
        <div class="logo-symbol">⚡</div>
        ShadowLab
      </a>
      <nav class="main-nav">
        <a href="/catalog" class="nav-item">Products</a>
        <a href="/catalog" class="nav-item">Enterprise Servers</a>
        <a href="/catalog" class="nav-item">Edge Routers</a>
        <a href="/catalog" class="nav-item">Security Modules</a>
      </nav>
      <div class="user-actions">
        <form action="/api/v1/legacy/users" method="get" class="search-form">
          <input type="text" name="q" placeholder="Search hardware, specs, SKUs..." class="search-input">
          <button type="submit" class="search-btn">Search</button>
        </form>
        <a href="/lab/auth/login" class="btn-ghost">Sign In</a>
        <a href="/lab/transport/checkout" class="btn-cart">
          <span>Cart</span>
          <span class="cart-count">0</span>
        </a>
      </div>
    </div>
  </header>

  <section class="hero">
    <div class="hero-pill">Next-Gen Enterprise Infrastructure · Gen 4 Systems</div>
    <h1 class="hero-title">High-Performance Edge Hardware & Cloud Infrastructure</h1>
    <p class="hero-subtitle">
      Purpose-built neural accelerators, multi-gigabit mesh routers, and secure enclave HSMs engineered for demanding enterprise deployments.
    </p>
    <div class="hero-cta">
      <a href="/catalog" class="btn-primary">Browse All Hardware</a>
      <a href="/catalog" class="btn-secondary">Explore Systems</a>
    </div>
  </section>

  <div class="brands-section">
    <div class="brands-label">Trusted by Infrastructure Teams Globally</div>
    <div class="brands-row">
      <span class="brand-item">VERCEL</span>
      <span class="brand-item">CLOUDFLARE</span>
      <span class="brand-item">STRIPE</span>
      <span class="brand-item">DATADOG</span>
      <span class="brand-item">SUPABASE</span>
      <span class="brand-item">REDIS</span>
    </div>
  </div>

  <main class="page-container">
    <div class="section-header">
      <div>
        <h2 class="section-title">Featured Systems & Appliances</h2>
        <p class="section-desc">Factory-calibrated hardware appliances ready for immediate deployment.</p>
      </div>
      <a href="/catalog" class="btn-secondary" style="font-size: 13px; padding: 8px 16px;">View All Catalog (6)</a>
    </div>

    <div class="product-grid">
      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🖥️</span>
          <span class="product-tag">Enterprise Rack</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Quantum Core X-9 Server</h3>
          <p class="product-summary">64-core ARM v9 coprocessor server with redundant power supply, PCIe Gen 5 expansion, and remote management BMC.</p>
          <div class="product-meta">
            <span class="product-price">$1,299.00</span>
            <button class="btn-buy" onclick="addToCart('Quantum Core X-9 Server', 1299)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🌐</span>
          <span class="product-tag">Networking</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Edge Router Pro v2</h3>
          <p class="product-summary">10GbE dual-WAN rackmount gateway with line-rate packet inspection, automated failover, and hardware WireGuard acceleration.</p>
          <div class="product-meta">
            <span class="product-price">$499.00</span>
            <button class="btn-buy" onclick="addToCart('Edge Router Pro v2', 499)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">⚡</span>
          <span class="product-tag">AI Acceleration</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Neural Accelerator USB Stick</h3>
          <p class="product-summary">Compact Type-C inference coprocessor delivering 32 TOPS INT8 performance for on-premise vision and language models at 5W TDP.</p>
          <div class="product-meta">
            <span class="product-price">$249.00</span>
            <button class="btn-buy" onclick="addToCart('Neural Accelerator USB Stick', 249)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🛡️</span>
          <span class="product-tag">Zero Trust Gateway</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Cloud Sentinel Gateway</h3>
          <p class="product-summary">Dedicated API security reverse proxy appliance featuring rate limiting, real-time traffic monitoring, and Layer 7 protection.</p>
          <div class="product-meta">
            <span class="product-price">$899.00</span>
            <button class="btn-buy" onclick="addToCart('Cloud Sentinel Gateway', 899)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🔐</span>
          <span class="product-tag">Hardware Security</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Secure Enclave HSM Module</h3>
          <p class="product-summary">FIPS 140-3 Level 4 certified physical crypto vault with tamper-detection switches and air-gapped root-of-trust key storage.</p>
          <div class="product-meta">
            <span class="product-price">$1,599.00</span>
            <button class="btn-buy" onclick="addToCart('Secure Enclave HSM Module', 1599)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">📦</span>
          <span class="product-tag">Starter Kit</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Developer Hardware Lab Kit</h3>
          <p class="product-summary">All-in-one prototyping kit including breakout boards, high-speed debug probes, and reference firmware samples.</p>
          <div class="product-meta">
            <span class="product-price">$199.00</span>
            <button class="btn-buy" onclick="addToCart('Developer Hardware Lab Kit', 199)">Add to Cart</button>
          </div>
        </div>
      </div>
    </div>

    <div class="features-grid">
      <div class="feature-box">
        <div class="feature-icon">⚡</div>
        <h4 class="feature-title">Ultra-Low Latency</h4>
        <p class="feature-text">Engineered for sub-millisecond packet traversal and instant hardware inference response.</p>
      </div>
      <div class="feature-box">
        <div class="feature-icon">🔒</div>
        <h4 class="feature-title">Hardware-Rooted Trust</h4>
        <p class="feature-text">Zero-trust architecture backed by physical tamper-resistant microcontrollers and encrypted storage.</p>
      </div>
      <div class="feature-box">
        <div class="feature-icon">🌍</div>
        <h4 class="feature-title">Global Fast Shipping</h4>
        <p class="feature-text">Regional stock distributed across 6 global warehouses with same-day express handling.</p>
      </div>
      <div class="feature-box">
        <div class="feature-icon">🛠️</div>
        <h4 class="feature-title">Enterprise Warranty</h4>
        <p class="feature-text">Comprehensive 3-year advance hardware replacement and 24/7 dedicated enterprise support.</p>
      </div>
    </div>
  </main>

  <footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-col">
        <h4>ShadowLab Systems</h4>
        <p style="font-size: 13px; line-height: 1.6; margin-top: 8px;">
          Next-generation edge systems, enterprise accelerators, and mission-critical hardware infrastructure.
        </p>
      </div>
      <div class="footer-col">
        <h4>Hardware</h4>
        <ul>
          <li><a href="/catalog">Enterprise Rack Servers</a></li>
          <li><a href="/catalog">Edge Gateway Routers</a></li>
          <li><a href="/catalog">Neural AI Accelerators</a></li>
          <li><a href="/catalog">Hardware Security Modules</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Customer Care</h4>
        <ul>
          <li><a href="/api/v1/orders">Track Customer Orders</a></li>
          <li><a href="/catalog">Global Dispatch Locations</a></li>
          <li><a href="/catalog">Enterprise Warranty</a></li>
          <li><a href="/catalog">Volume Licensing</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Account</h4>
        <ul>
          <li><a href="/lab/auth/login">Customer Sign In</a></li>
          <li><a href="/lab/transport/checkout">Shopping Cart</a></li>
          <li><a href="/catalog">Product Catalog</a></li>
        </ul>
      </div>
    </div>

    <!-- Scanner discovery endpoints (subtle / hidden to regular visitors) -->
    <div style="display:none;" aria-hidden="true">
      <a href="/docs-page">Partner Docs</a>
      <a href="/lab">Training Scenarios</a>
      <a href="/traps">System Diagnostics</a>
      <a href="/lab/api/auth/admin-panel">Admin Portal</a>
      <a href="/openapi.json">OpenAPI Spec</a>
      <a href="/swagger-ui.html">Swagger Console</a>
      <a href="/redoc">ReDoc Explorer</a>
      <a href="/healthz">Health Check</a>
      <a href="/api-docs.json">API Docs JSON</a>
    </div>

    <div class="footer-bottom">
      <span>© 2026 ShadowLab Systems, Inc. All rights reserved.</span>
      <span>Enterprise Edge Platform</span>
    </div>
  </footer>

  <script>
    function addToCart(name, price) {
      try {
        var cart = JSON.parse(localStorage.getItem('shadow_cart') || '[]');
        cart.push({ name: name, price: price });
        localStorage.setItem('shadow_cart', JSON.stringify(cart));
      } catch(e) {}
      window.location.href = '/lab/transport/checkout';
    }

    (function() {
      try {
        var cart = JSON.parse(localStorage.getItem('shadow_cart') || '[]');
        if (cart.length > 0) {
          var badges = document.querySelectorAll('.cart-count');
          badges.forEach(function(b) { b.textContent = cart.length; });
        }
      } catch(e) {}
    })();

    // inline bootstrap call discovered by the HTML inline-script extractor
    fetch('/api/v1/orders').then(function (r) { return r.json(); });
  </script>
  <!-- decoy: this string in a comment is NOT a real endpoint: /api/v1/decoy-only-in-comment -->
</body>
</html>
"""

APP_JS = """/* ShadowLab bundle (synthetic) */
const API_BASE = '/api/v1';
function loadOrders() {
  return fetch(API_BASE + '/orders');
}
function loadProfile() {
  return fetch(`/api/v2/profile`);
}
export async function chunkModule() {
  return import('/static/lazy.chunk.js');
}
const reportClient = axios.create({ baseURL: API_BASE });
reportClient.get(`${API_BASE}/reports/summary`);
var xhr = new XMLHttpRequest();
xhr.open('GET', '/api/v1/users/1234');
xhr.send();
$.get('/api/admin/backup', function () {});
const graphql = fetch('/graphql', { method: 'POST', body: '{"query":"query Orders { orders { id } }"}' });
// build constant, intentionally fake credential in the documented AWS example format
const dummy = '""" + FAKE_AWS_KEY + """';
//# sourceMappingURL=/static/app.js.map
"""

LAZY_CHUNK = """/* lazy chunk */
export function run() {
  return fetch('/api/internal/export?format=csv');
}
//# sourceMappingURL=/static/lazy.chunk.js.map
"""

SOURCE_MAP = {
    "version": 3,
    "file": "app.js",
    "sources": ["webpack://shadowlab/src/report.js", "webpack://shadowlab/src/legacy.js"],
    "sourcesContent": [
        "import { client } from './client';\nexport const load = () => client.get('/api/v1/secret-report');\n",
        "export function legacyCheckout() { return fetch('/api/legacy/checkout'); }\n",
    ],
    "mappings": "AAAA",
}

CATALOG_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Products — ShadowLab Storefront</title>
  <link rel="stylesheet" href="/static/site.css">
  <script src="/static/app.js"></script>
</head>
<body>
  <div class="top-bar">
    🚚 Complimentary express shipping on all enterprise hardware kits · Worldwide dispatch
  </div>

  <header class="site-header">
    <div class="header-container">
      <a href="/" class="brand-logo">
        <div class="logo-symbol">⚡</div>
        ShadowLab
      </a>
      <nav class="main-nav">
        <a href="/" class="nav-item">Home</a>
        <a href="/catalog" class="nav-item" style="color:var(--primary);">Products</a>
        <a href="/catalog" class="nav-item">Enterprise Servers</a>
        <a href="/catalog" class="nav-item">Edge Routers</a>
        <a href="/catalog" class="nav-item">Security Modules</a>
      </nav>
      <div class="user-actions">
        <form action="/api/v1/legacy/users" method="get" class="search-form">
          <input type="text" name="q" placeholder="Search hardware, specs, SKUs..." class="search-input">
          <button type="submit" class="search-btn">Search</button>
        </form>
        <a href="/lab/auth/login" class="btn-ghost">Sign In</a>
        <a href="/lab/transport/checkout" class="btn-cart">
          <span>Cart</span>
          <span class="cart-count">0</span>
        </a>
      </div>
    </div>
  </header>

  <main class="page-container" style="padding-top:40px;">
    <div class="section-header">
      <div>
        <h1 class="section-title">Hardware &amp; Systems Catalog</h1>
        <p class="section-desc">Browse our full inventory of enterprise-grade hardware appliances and cloud systems.</p>
      </div>
    </div>

    <div class="product-grid" style="margin-top:28px;">
      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🖥️</span>
          <span class="product-tag">Enterprise Rack</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Quantum Core X-9 Server</h3>
          <p class="product-summary">64-core ARM v9 coprocessor server with redundant power supply, PCIe Gen 5, and remote management BMC.</p>
          <div class="product-meta">
            <span class="product-price">$1,299.00</span>
            <button class="btn-buy" onclick="addToCart('Quantum Core X-9 Server', 1299)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🌐</span>
          <span class="product-tag">Networking</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Edge Router Pro v2</h3>
          <p class="product-summary">10GbE dual-WAN rackmount gateway with line-rate packet inspection and hardware WireGuard acceleration.</p>
          <div class="product-meta">
            <span class="product-price">$499.00</span>
            <button class="btn-buy" onclick="addToCart('Edge Router Pro v2', 499)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">⚡</span>
          <span class="product-tag">AI Acceleration</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Neural Accelerator USB Stick</h3>
          <p class="product-summary">Compact Type-C inference coprocessor delivering 32 TOPS INT8 performance for on-premise AI workloads at 5W TDP.</p>
          <div class="product-meta">
            <span class="product-price">$249.00</span>
            <button class="btn-buy" onclick="addToCart('Neural Accelerator USB Stick', 249)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🛡️</span>
          <span class="product-tag">API Security</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Cloud Sentinel Gateway</h3>
          <p class="product-summary">Dedicated API security reverse proxy appliance with real-time traffic monitoring and Layer 7 protection.</p>
          <div class="product-meta">
            <span class="product-price">$899.00</span>
            <button class="btn-buy" onclick="addToCart('Cloud Sentinel Gateway', 899)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">🔐</span>
          <span class="product-tag">Hardware Security</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Secure Enclave HSM Module</h3>
          <p class="product-summary">FIPS 140-3 Level 4 certified physical crypto vault with tamper-detection switches and air-gapped key storage.</p>
          <div class="product-meta">
            <span class="product-price">$1,599.00</span>
            <button class="btn-buy" onclick="addToCart('Secure Enclave HSM Module', 1599)">Add to Cart</button>
          </div>
        </div>
      </div>

      <div class="product-card">
        <div class="product-image-wrap">
          <span class="product-icon">📦</span>
          <span class="product-tag">Starter Kit</span>
        </div>
        <div class="product-content">
          <h3 class="product-name">Developer Hardware Lab Kit</h3>
          <p class="product-summary">All-in-one prototyping kit including breakout boards, high-speed debug probes, and reference firmware samples.</p>
          <div class="product-meta">
            <span class="product-price">$199.00</span>
            <button class="btn-buy" onclick="addToCart('Developer Hardware Lab Kit', 199)">Add to Cart</button>
          </div>
        </div>
      </div>
    </div>
  </main>

  <footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-col">
        <h4>ShadowLab Systems</h4>
        <p style="font-size:13px;line-height:1.6;margin-top:8px;">Next-generation edge systems, accelerators, and developer hardware infrastructure.</p>
      </div>
      <div class="footer-col">
        <h4>Hardware</h4>
        <ul>
          <li><a href="/catalog">All Products</a></li>
          <li><a href="/catalog">Edge Routers</a></li>
          <li><a href="/catalog">Neural Accelerators</a></li>
          <li><a href="/catalog">Hardware HSMs</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Customer Care</h4>
        <ul>
          <li><a href="/api/v1/orders">Track Orders</a></li>
          <li><a href="/catalog">Warranty Information</a></li>
          <li><a href="/catalog">Enterprise Inquiries</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Account</h4>
        <ul>
          <li><a href="/lab/auth/login">Sign In</a></li>
          <li><a href="/lab/transport/checkout">Checkout</a></li>
        </ul>
      </div>
    </div>

    <div style="display:none;" aria-hidden="true">
      <a href="/docs-page">Documentation</a>
      <a href="/lab">Training scenarios</a>
      <a href="/traps">Diagnostics</a>
      <a href="/lab/api/auth/admin-panel">Admin Portal</a>
    </div>

    <div class="footer-bottom">
      <span>© 2026 ShadowLab Systems, Inc. All rights reserved.</span>
      <span>Enterprise Edge Platform</span>
    </div>
  </footer>

  <script>
    function addToCart(name, price) {
      try {
        var cart = JSON.parse(localStorage.getItem('shadow_cart') || '[]');
        cart.push({ name: name, price: price });
        localStorage.setItem('shadow_cart', JSON.stringify(cart));
      } catch(e) {}
      window.location.href = '/lab/transport/checkout';
    }

    (function() {
      try {
        var cart = JSON.parse(localStorage.getItem('shadow_cart') || '[]');
        if (cart.length > 0) {
          var badges = document.querySelectorAll('.cart-count');
          badges.forEach(function(b) { b.textContent = cart.length; });
        }
      } catch(e) {}
    })();
  </script>
</body>
</html>
"""

DOCS_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Partner Integration — ShadowLab</title>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  <div class="top-bar">
    🚚 Complimentary express shipping on all enterprise hardware kits · Worldwide dispatch
  </div>

  <header class="site-header">
    <div class="header-container">
      <a href="/" class="brand-logo">
        <div class="logo-symbol">⚡</div>
        ShadowLab
      </a>
      <nav class="main-nav">
        <a href="/" class="nav-item">Home</a>
        <a href="/catalog" class="nav-item">Products</a>
        <a href="/catalog" class="nav-item">Enterprise Servers</a>
        <a href="/catalog" class="nav-item">Edge Routers</a>
      </nav>
      <div class="user-actions">
        <a href="/lab/auth/login" class="btn-ghost">Sign In</a>
        <a href="/lab/transport/checkout" class="btn-cart">
          <span>Cart</span>
          <span class="cart-count">0</span>
        </a>
      </div>
    </div>
  </header>

  <main class="page-container" style="padding-top:48px;max-width:860px;">
    <h1 id="partners" style="font-size:28px;font-weight:700;margin-bottom:12px;">Partner API Reference</h1>
    <p style="color:var(--text-muted);margin-bottom:28px;">Authenticated partner endpoints for integration and invoicing workflows.</p>

    <div style="background:var(--bg-card);border:1px solid var(--border-color);border-radius:10px;padding:20px;margin-bottom:24px;">
      <p style="font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:10px;">Endpoints</p>
      <pre style="font-family:var(--font-mono);font-size:14px;color:#93c5fd;line-height:1.8;">GET /api/v1/partners
GET /api/v1/partners/{partnerId}/invoices</pre>
    </div>

    <p style="margin-bottom:24px;color:var(--text-muted);">Decoy in prose (not a route): <code style="background:var(--bg-card);padding:2px 6px;border-radius:4px;color:#fca5a5;">GET /api/v1/decoy-in-prose</code></p>

    <div style="display:flex;gap:12px;flex-wrap:wrap;">
      <a href="/api-docs.json" class="btn-primary" style="font-size:13px;padding:10px 20px;">Download Collection</a>
      <a href="/openapi.json" class="btn-secondary" style="font-size:13px;padding:10px 20px;">OpenAPI Spec</a>
    </div>
  </main>

  <footer class="site-footer" style="margin-top:80px;">
    <div class="footer-bottom">
      <span>© 2026 ShadowLab Systems, Inc. All rights reserved.</span>
      <span>Enterprise Edge Platform</span>
    </div>
  </footer>
</body>
</html>
"""

POSTMAN = {
    "info": {"name": "ShadowLab collection", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
    "variable": [{"key": "baseUrl", "value": "http://127.0.0.1:8099"}],
    "item": [
        {"name": "orders", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/api/v1/orders"}}},
        {"name": "shipments", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/api/internal/shipments"}}},
        {"name": "invoices", "request": {"method": "GET", "url": {"raw": "{{baseUrl}}/api/v1/invoices/77"}}},
    ],
}

ROBOTS = """User-agent: *
Disallow: /api/internal/
Disallow: /api/v1/legacy/
Sitemap: http://127.0.0.1:8099/sitemap.xml
"""

SITEMAP = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:8099/api/v1/legacy/orders</loc></url>
  <url><loc>http://127.0.0.1:8099/catalog</loc></url>
</urlset>
"""

SITEMAP_BOMB = """<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY a "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">]>
<urlset><url><loc>http://127.0.0.1:8099/&a;&a;&a;&a;&a;</loc></url></urlset>
"""

GRAPHQL_INTROSPECTION = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "Query"}, {"name": "Order"}, {"name": "User"}],
        }
    }
}

TECH_ORDERS = [
    {"id": 1001, "status": "shipped"},
    {"id": 1002, "status": "processing"},
]

USERS = [
    {"id": 1, "email": "ada@example.test", "name": "Ada"},
    {"id": 2, "email": "grace@example.test", "name": "Grace"},
]

TOKENS_RESPONSE = {
    "service": "internal-token-service",
    "api_key": "ST-DEMO-EXAMPLE-KEY-not-real",
    "password": "example-only-not-a-real-password",
    "note": "synthetic training data",
}

REMOTE_REF_SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Ref test", "version": "1"},
    "paths": {"/api/v1/remote": {"get": {"$ref": "http://169.254.169.254/latest/meta-data/iam"}}},
}


LAB_INDEX_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ShadowLab training scenarios</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0b1020;color:#e6e9f2}
  main{max-width:1080px;margin:0 auto;padding:32px 20px 64px}
  h1{margin:0 0 8px;font-size:28px}
  .warn{border:1px solid #a15c00;background:#2b1a00;color:#ffcf8a;padding:12px 16px;border-radius:10px;margin:18px 0}
  table{width:100%;border-collapse:collapse;margin-top:18px;font-size:14px}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #232a44;vertical-align:top}
  th{color:#9aa4c4;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
  code{background:#141a30;padding:2px 6px;border-radius:5px;font-size:12px}
  a{color:#7fb2ff}
  .muted{color:#9aa4c4}
</style></head>
<body><main>
<h1>ShadowLab training scenarios</h1>
<p class="muted">A deliberately vulnerable storefront API used to exercise ShadowTrace.
Every record here is synthetic and every “vulnerability” is a canned response.</p>
<div class="warn"><strong>Intentionally vulnerable.</strong> Bound to loopback only.
Never expose this service to a network or run it in production.</div>
<table>
<thead><tr><th>Scenario</th><th>Title</th><th>Expected rules</th><th>Open</th></tr></thead>
<tbody>
<tr><td><code>transport</code></td><td><strong>Cleartext HTTP transport</strong><br><span class="muted">A checkout page served over cleartext HTTP with no HSTS, so the whole flow is readable on the wire.</span></td><td>ST-012, ST-013</td><td><a href="/lab/transport/checkout">/lab/transport/checkout</a></td></tr>
<tr><td><code>headers</code></td><td><strong>Security headers missing</strong><br><span class="muted">A page rendered without CSP, X-Content-Type-Options or X-Frame-Options.</span></td><td>ST-013</td><td><a href="/lab/api/headers/ping">/lab/api/headers/ping</a></td></tr>
<tr><td><code>cookies</code></td><td><strong>Session cookie without security attributes</strong><br><span class="muted">A session cookie issued without HttpOnly, Secure or SameSite, so it is readable by script and sent on cross-site requests.</span></td><td>ST-018</td><td><a href="/lab/api/cookies/session">/lab/api/cookies/session</a></td></tr>
<tr><td><code>verbose-errors</code></td><td><strong>Verbose error messages</strong><br><span class="muted">A failing request returns a stack trace with internal file paths and the query that broke.</span></td><td>ST-008</td><td><a href="/lab/api/errors/checkout">/lab/api/errors/checkout</a></td></tr>
<tr><td><code>cors</code></td><td><strong>Insecure CORS configuration</strong><br><span class="muted">A profile endpoint answers with Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.</span></td><td>ST-006</td><td><a href="/lab/api/cors/profile">/lab/api/cors/profile</a></td></tr>
<tr><td><code>reflected-xss</code></td><td><strong>Reflected input rendered unencoded</strong><br><span class="muted">A search page echoes the name parameter into HTML without encoding it.</span></td><td>ST-019</td><td><a href="/lab/api/xss/echo?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E">/lab/api/xss/echo?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E</a></td></tr>
<tr><td><code>sql-injection</code></td><td><strong>SQL injection (error-based simulation)</strong><br><span class="muted">A product lookup passes the id parameter into a query and returns the database error verbatim.</span></td><td>ST-020</td><td><a href="/lab/api/sqli/product?id=1%27">/lab/api/sqli/product?id=1%27</a></td></tr>
<tr><td><code>path-traversal</code></td><td><strong>Path traversal (synthetic filesystem)</strong><br><span class="muted">A download endpoint accepts a file path parameter and returns a synthetic file from a fake filesystem.</span></td><td>ST-021</td><td><a href="/lab/api/files/download?file=../../../../etc/passwd">/lab/api/files/download?file=../../../../etc/passwd</a></td></tr>
<tr><td><code>idor</code></td><td><strong>Insecure direct object reference</strong><br><span class="muted">Account records are addressed by a sequential id and returned without authentication; 1002 and 1003 belong to other synthetic customers.</span></td><td>ST-023, ST-001</td><td><a href="/lab/api/idor/account/1001">/lab/api/idor/account/1001</a></td></tr>
<tr><td><code>authz-flaws</code></td><td><strong>Authentication and authorization logic flaws</strong><br><span class="muted">An administrative panel is served without any authentication, and the login form posts over cleartext with a synthetic account list.</span></td><td>ST-003, ST-001</td><td><a href="/lab/api/auth/admin-panel">/lab/api/auth/admin-panel</a></td></tr>
<tr><td><code>upload</code></td><td><strong>Unsafe file-upload validation</strong><br><span class="muted">An upload form accepts any extension and does not validate content type. ShadowLab refuses the POST itself, so nothing is ever stored or executed.</span></td><td>ST-001, ST-013</td><td><a href="/lab/upload">/lab/upload</a></td></tr>
<tr><td><code>open-redirect</code></td><td><strong>Open redirect</strong><br><span class="muted">A continue parameter is used as the redirect target. ShadowLab only redirects to local paths and refuses absolute URLs, which keeps the demo contained.</span></td><td>ST-022</td><td><a href="/lab/api/redirect?next=/lab/landing">/lab/api/redirect?next=/lab/landing</a></td></tr>
<tr><td><code>diagnostics</code></td><td><strong>Exposed debug and diagnostic routes</strong><br><span class="muted">Diagnostic routes publish a synthetic environment, build metadata and a feature-flag dump to anyone.</span></td><td>ST-003, ST-011</td><td><a href="/lab/api/diagnostics/env">/lab/api/diagnostics/env</a></td></tr>
<tr><td><code>access-control</code></td><td><strong>Insecure API access control</strong><br><span class="muted">An export endpoint returns API keys for every synthetic tenant without checking who is asking.</span></td><td>ST-011, ST-001</td><td><a href="/lab/api/api-keys/export">/lab/api/api-keys/export</a></td></tr>
<tr><td><code>input-validation</code></td><td><strong>Weak input validation</strong><br><span class="muted">A quantity parameter accepts negative numbers, quotes and markup, and reflects the raw value back into the page.</span></td><td>ST-019</td><td><a href="/lab/api/input/quantity?q=-1%27%3E%3Cscript%3E">/lab/api/input/quantity?q=-1%27%3E%3Cscript%3E</a></td></tr>
</tbody></table>
<p class="muted" style="margin-top:24px">ShadowTrace refuses to scan this host unless the
deployment operator allow-lists it (<code>ST_PRIVATE_ALLOWLIST</code>) and the target was
registered as an approved lab target.</p>
</main></body></html>
"""


class LabHandler(BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = ""

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str = "application/json", extra_headers=None,
              hardened: bool = True) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # `hardened=False` is used by exactly one scenario (ST-013): an endpoint that really
        # does answer without nosniff/CSP, so the scanner's finding is a true observation.
        if hardened:
            self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, status: int, payload, extra_headers=None) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json", extra_headers)

    def _html(self, body: str, extra_headers=None) -> None:
        self._send(200, body.encode(), "text/html; charset=utf-8", extra_headers)

    def _not_found_json(self) -> None:
        self._json(404, {"error": "not found"})

    # -- routing ---------------------------------------------------------
    def do_HEAD(self) -> None:  # noqa: N802
        self.route(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self.route()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.route()

    def do_POST(self) -> None:  # noqa: N802
        # State-changing calls are never used by ShadowTrace; the lab refuses them.
        self._json(405, {"error": "read-only lab"}, {"Allow": "GET, HEAD, OPTIONS"})

    def do_PUT(self) -> None:  # noqa: N802
        self._json(405, {"error": "read-only lab"}, {"Allow": "GET, HEAD, OPTIONS"})

    def do_DELETE(self) -> None:  # noqa: N802
        self._json(405, {"error": "read-only lab"}, {"Allow": "GET, HEAD, OPTIONS"})

    def route(self, head_only: bool = False) -> None:
        path = urlsplit(self.path).path.rstrip("/") or "/"
        handlers = {
            "/": self.home,
            "/catalog": self.catalog,
            "/docs-page": self.docs_page,
            "/traps": self.traps_page,
            "/api-docs.json": self.postman,
            "/openapi.json": self.openapi,
            "/swagger-ui.html": self.swagger_ui,
            "/redoc": self.redoc,
            "/robots.txt": self.robots,
            "/sitemap.xml": self.sitemap,
            "/graphql": self.graphql,
            "/static/app.js": self.app_js,
            "/static/app.js.map": self.source_map,
            "/static/lazy.chunk.js": self.lazy_chunk,
            "/static/lazy.chunk.js.map": self.source_map,
            "/static/site.css": self.css,
            "/api/v1/orders": self.orders_v1,
            "/api/v1/health": self.health_documented,
            "/api/v2/secure": self.secure,
            "/api/v2/profile": self.profile_cors,
            "/api/v2/orders": self.orders_verbose_error,
            "/api/v1/legacy/users": self.legacy_users,
            "/api/v1/users": self.users,
            "/api/v2/users": self.users_v2,
            "/api/v1/users/1234": self.user_detail,
            "/api/v2/reports": self.zombie_reports,
            "/api/internal/export": self.internal_export,
            "/api/internal/shipments": self.internal_shipments,
            "/api/internal/tokens": self.internal_tokens,
            "/api/v1/secret-report": self.secret_report,
            "/api/v1/debug/config": self.debug_config,
            "/api/admin/backup": self.admin_backup,
            "/api/v1/partners": self.partners,
            "/api/v1/partners/9/invoices": self.partner_invoices,
            "/api/v1/invoices/77": self.invoices,
            "/api/v1/legacy/orders": self.legacy_orders,
            "/api/legacy/checkout": self.legacy_checkout,
            "/api/v1/reports/summary": self.reports_summary,
            "/api/v1/customers/8842": self.customer_detail,
            "/api/internal/audit-log": self.internal_audit,
            "/api/v1/remote": self.remote_ref_endpoint,
            "/redirect-metadata": self.redirect_metadata,
            "/redirect-loopback": self.redirect_loopback,
            "/redirect-loop": self.redirect_loop,
            "/redirect-cross-origin": self.redirect_cross,
            "/bomb.gz": self.compression_bomb,
            "/endless": self.endless,
            "/slow": self.slow,
            "/huge-headers": self.huge_headers,
            "/big.js": self.big_js,
            "/nested.json": self.nested_json,
            "/spec-remote-ref.json": self.remote_ref_spec,
            "/sitemap-bomb.xml": self.sitemap_bomb,
            "/xss.json": self.xss_payload,
            # -- training lab -------------------------------------------------
            "/healthz": self.healthz,
            "/lab": self.lab_index,
            "/lab/transport/checkout": self.lab_transport,
            "/lab/headers/console": self.lab_headers,
            "/lab/api/headers/ping": self.lab_headers_json,
            "/lab/api/cookies/session": self.lab_cookies,
            "/lab/api/errors/checkout": self.lab_verbose_error,
            "/lab/api/cors/profile": self.lab_cors,
            "/lab/api/xss/echo": self.lab_xss,
            "/lab/api/sqli/product": self.lab_sqli,
            "/lab/api/files/download": self.lab_file_download,
            "/lab/auth/login": self.lab_login,
            "/lab/api/auth/admin-panel": self.lab_admin_panel,
            "/lab/upload": self.lab_upload,
            "/lab/api/redirect": self.lab_redirect,
            "/lab/landing": self.lab_landing,
            "/lab/api/api-keys/export": self.lab_api_keys,
            "/lab/api/input/quantity": self.lab_input,
            "/lab/api/diagnostics/env": self.lab_diagnostics_env,
            "/lab/api/diagnostics/config": self.lab_diagnostics_config,
        }
        handler = handlers.get(path)
        if handler is not None:
            handler(head_only)
            return
        if path.startswith("/lab/api/idor/account/"):
            self.lab_idor_account(head_only)
            return
        if path.startswith("/api/v1/users/"):
            self.user_detail(head_only)
            return
        if path.startswith("/api/v1/customers/"):
            self.customer_detail(head_only)
            return
        if path.startswith("/api/v1/invoices/"):
            self.invoices(head_only)
            return
        if path.startswith("/api/v1/partners/") and path.endswith("/invoices"):
            self.partner_invoices(head_only)
            return
        # SPA catch-all: returns 200 for unknown paths (soft-404 negative control).
        self._html(
            "<!doctype html><html><head><title>ShadowLab</title></head><body><div id=\"root\">"
            "Loading storefront…</div></body></html>"
        )

    # -- pages -----------------------------------------------------------
    def home(self, head_only=False) -> None:
        self._html(HOME_HTML, {"Content-Security-Policy": "default-src 'self'; connect-src 'self' https://api.partner.example"})

    def catalog(self, head_only=False) -> None:
        self._html(CATALOG_HTML)

    def docs_page(self, head_only=False) -> None:
        self._html(DOCS_HTML)

    def traps_page(self, head_only=False) -> None:
        self._html(
            "<!doctype html><html><head><title>Diagnostics</title></head><body>"
            "<ul>"
            "<li><a href=\"/redirect-metadata\">redirect metadata</a></li>"
            "<li><a href=\"/redirect-loopback\">redirect loopback</a></li>"
            "<li><a href=\"/redirect-loop\">redirect loop</a></li>"
            "<li><a href=\"/redirect-cross-origin\">redirect cross-origin</a></li>"
            "<li><a href=\"/bomb.gz\">compression bomb</a></li>"
            "<li><a href=\"/endless\">endless response</a></li>"
            "<li><a href=\"/huge-headers\">huge headers</a></li>"
            "<li><a href=\"/big.js\">oversized javascript</a></li>"
            "<li><a href=\"/nested.json\">deeply nested json</a></li>"
            "<li><a href=\"/spec-remote-ref.json\">remote spec ref</a></li>"
            "<li><a href=\"/sitemap-bomb.xml\">entity expansion sitemap</a></li>"
            "<li><a href=\"/slow\">slow response</a></li>"
            "<script src=\"/big.js\"></script>"
            "<li><a href=\"/api/v1/debug/config\">debug config</a></li>"
            "<li><a href=\"/api/internal/tokens\">token service</a></li>"
            "<li><a href=\"/api/v1/users\">user directory</a></li>"
            "</ul></body></html>"
        )

    def css(self, head_only=False) -> None:
        css_file = Path(__file__).resolve().parent / "site.css"
        if css_file.is_file():
            self._send(200, css_file.read_bytes(), "text/css")
        else:
            self._send(200, b"body{background:#0b1020;color:#e6e9f2;font-family:system-ui}", "text/css")

    def swagger_ui(self, head_only=False) -> None:
        self._html("<!doctype html><html><head><title>Swagger UI</title></head><body><div id=\"swagger-ui\">swagger openapi ui</div></body></html>")

    def redoc(self, head_only=False) -> None:
        self._html("<!doctype html><html><head><title>ReDoc</title></head><body><redoc spec-url=\"/openapi.json\"></redoc></body></html>")

    def openapi(self, head_only=False) -> None:
        self._json(200, BASELINE)

    def postman(self, head_only=False) -> None:
        self._json(200, POSTMAN)

    def robots(self, head_only=False) -> None:
        self._send(200, ROBOTS.encode(), "text/plain")

    def sitemap(self, head_only=False) -> None:
        self._send(200, SITEMAP.encode(), "application/xml")

    def sitemap_bomb(self, head_only=False) -> None:
        self._send(200, SITEMAP_BOMB.encode(), "application/xml")

    def graphql(self, head_only=False) -> None:
        self._json(200, GRAPHQL_INTROSPECTION)

    # -- javascript ------------------------------------------------------
    def app_js(self, head_only=False) -> None:
        self._send(200, APP_JS.encode(), "application/javascript")

    def lazy_chunk(self, head_only=False) -> None:
        self._send(200, LAZY_CHUNK.encode(), "application/javascript")

    def source_map(self, head_only=False) -> None:
        self._json(200, SOURCE_MAP, {"SourceMap": "/static/app.js.map"})

    def big_js(self, head_only=False) -> None:
        padding = "// " + ("A" * 1024) + "\n"
        body = (padding * 4096).encode()  # ~4 MiB, above the scanner's response cap
        self._send(200, body, "application/javascript")

    # -- documented endpoints -------------------------------------------
    def orders_v1(self, head_only=False) -> None:
        # Declared protected in the baseline yet reachable anonymously (ST-002).
        self._json(200, {"orders": TECH_ORDERS})

    def users(self, head_only=False) -> None:
        self._json(200, {"users": USERS})

    def users_v2(self, head_only=False) -> None:
        self._json(200, {"users": USERS, "version": 2})

    def user_detail(self, head_only=False) -> None:
        self._json(200, {"id": 1234, "email": "user1234@example.test", "name": "Synthetic User"})

    def health_documented(self, head_only=False) -> None:
        self._json(200, {"status": "ok"}, {"Cache-Control": "no-store"})

    def secure(self, head_only=False) -> None:
        self._json(401, {"error": "authentication required"}, {"WWW-Authenticate": "Bearer"})

    def profile_cors(self, head_only=False) -> None:
        self._json(
            200,
            {"profile": {"id": 1, "email": "ada@example.test"}},
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        )

    def orders_verbose_error(self, head_only=False) -> None:
        self._send(
            500,
            (
                b'{"error":"Traceback (most recent call last): File \\"/srv/app/orders.py\\", line 42, '
                b'in <module> db.query(sql)\\n SQLException: syntax error at or near \\"SELECT\\""}'
            ),
            "application/json",
        )

    def zombie_reports(self, head_only=False) -> None:
        self._json(404, {"error": "removed in v2.1"})

    # -- shadow endpoints ------------------------------------------------
    def legacy_users(self, head_only=False) -> None:
        self._json(200, {"legacy": True, "users": USERS[:1]})

    def internal_export(self, head_only=False) -> None:
        self._json(200, {"export": [{"order": 1001, "total": 2500}], "internal": True})

    def internal_shipments(self, head_only=False) -> None:
        self._json(200, {"shipments": [{"id": "SHP-1", "carrier": "synthetic"}]})

    def internal_tokens(self, head_only=False) -> None:
        self._json(200, TOKENS_RESPONSE)

    def secret_report(self, head_only=False) -> None:
        self._json(200, {"report": "legacy revenue", "rows": [{"month": "2025-01", "total": 424242}]})

    def debug_config(self, head_only=False) -> None:
        self._json(200, {"debug": True, "queue": "synthetic", "workers": 2})

    def admin_backup(self, head_only=False) -> None:
        self._json(
            200,
            {"backups": ["synthetic-2026-01-01.sql"], "verified": False},
            {"Allow": "GET, HEAD, OPTIONS, PUT, DELETE", "Access-Control-Allow-Methods": "GET, PUT, DELETE"},
        )

    def partners(self, head_only=False) -> None:
        self._json(200, {"partners": [{"id": 9, "name": "Synthetic Partner"}]})

    def partner_invoices(self, head_only=False) -> None:
        self._json(200, {"invoices": [{"id": "INV-1", "amount": 100}]})

    def invoices(self, head_only=False) -> None:
        self._json(200, {"invoice": {"id": 77, "status": "paid"}})

    def legacy_orders(self, head_only=False) -> None:
        self._json(200, {"orders": TECH_ORDERS, "legacy": True})

    def legacy_checkout(self, head_only=False) -> None:
        self._json(200, {"checkout": "legacy flow"})

    def reports_summary(self, head_only=False) -> None:
        self._json(200, {"summary": {"orders": 2, "revenue": 2500}})

    def remote_ref_endpoint(self, head_only=False) -> None:
        self._json(200, {"ok": True})

    def customer_detail(self, head_only=False) -> None:
        self._json(200, {"customer": {"id": 8842, "email": "customer8842@example.test", "tier": "gold"}})

    def internal_audit(self, head_only=False) -> None:
        self._json(200, {"audit": [{"actor": "system", "action": "synthetic"}]})

    def xss_payload(self, head_only=False) -> None:
        self._json(
            200,
            {
                "name": "<script>alert('xss')</script>",
                "path": "/api/v1/users/<img src=x onerror=alert(1)>",
                "note": "<iframe src=javascript:alert(1)>",
            },
            {"X-Lab-Note": "<script>alert('header-xss')</script>"},
        )

    # -- hostile traps ---------------------------------------------------
    def redirect_metadata(self, head_only=False) -> None:
        self.send_response(302)
        self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def redirect_loopback(self, head_only=False) -> None:
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.1:9001/api/internal/tokens")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def redirect_loop(self, head_only=False) -> None:
        self.send_response(302)
        self.send_header("Location", "/redirect-loop")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def redirect_cross(self, head_only=False) -> None:
        self.send_response(302)
        self.send_header("Location", "https://example.com/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def compression_bomb(self, head_only=False) -> None:
        payload = gzip.compress(b"\x00" * (24 * 1024 * 1024), compresslevel=9)
        self._send(200, payload, "application/octet-stream", {"Content-Encoding": "gzip"})

    def endless(self, head_only=False) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        chunk = b"B" * 65536
        for _ in range(1024):  # 64 MiB maximum, bounded on purpose
            try:
                self.wfile.write(chunk)
            except Exception:
                return

    def slow(self, head_only=False) -> None:
        time.sleep(12)
        self._json(200, {"slow": True})

    def huge_headers(self, head_only=False) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        for index in range(200):
            self.send_header(f"X-Pad-{index}", "P" * 900)
        self.end_headers()
        self.wfile.write(b"{}")

    def nested_json(self, head_only=False) -> None:
        depth = 400
        self._send(200, ("[" * depth + "]" * depth).encode(), "application/json")

    def remote_ref_spec(self, head_only=False) -> None:
        self._json(200, REMOTE_REF_SPEC)

    # -- training lab ----------------------------------------------------
    #
    # Every handler below is a *demonstration*: the vulnerable behaviour is the response
    # itself (a header, an echo, a canned error). Nothing is executed, no host file is
    # opened, no query is run, no upload is stored, and every value is synthetic.
    def healthz(self, head_only=False) -> None:
        self._json(200, {"status": "ok", "lab": "shadowlab", "version": LAB_VERSION})

    def lab_index(self, head_only=False) -> None:
        self._html(LAB_INDEX_HTML)

    def lab_landing(self, head_only=False) -> None:
        self._html("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                   "<title>ShadowLab landing</title></head><body>"
                   "<h1>Redirect destination</h1><p>You arrived at the lab landing page.</p>"
                   "</body></html>")

    def lab_transport(self, head_only=False) -> None:
        # Deliberately no HSTS and no CSP: the training point is the missing transport policy (ST-012, ST-013).
        # Real-looking storefront checkout with cleartext payment card form.
        parsed = urlsplit(self.path)
        qs = parse_qs(parsed.query)
        card_val = qs.get("card", [""])[0]

        success_banner = ""
        if card_val:
            masked = card_val[-4:] if len(card_val) >= 4 else "1111"
            success_banner = (
                '<div class="alert-success">'
                '<strong>Order Confirmed!</strong> Thank you for your purchase. Your payment with card ending in '
                + masked + ' has been received. Order tracking number: <strong>#SL-92841</strong>.</div>'
            )

        template = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Checkout — ShadowLab Storefront</title>
  <link rel="stylesheet" href="/static/site.css">
</head>
<body>
  <div class="top-bar">
    🚚 Complimentary express shipping on all enterprise hardware kits · Worldwide dispatch
  </div>

  <header class="site-header">
    <div class="header-container">
      <a href="/" class="brand-logo">
        <div class="logo-symbol">⚡</div>
        ShadowLab
      </a>
      <nav class="main-nav">
        <a href="/" class="nav-item">Home</a>
        <a href="/catalog" class="nav-item">Products</a>
        <a href="/catalog" class="nav-item">Enterprise Servers</a>
      </nav>
      <div class="user-actions">
        <a href="/catalog" class="btn-ghost">Continue Shopping</a>
        <a href="/lab/transport/checkout" class="btn-cart">
          <span>Cart</span>
          <span class="cart-count">1</span>
        </a>
      </div>
    </div>
  </header>

  <main class="checkout-container">
    {{SUCCESS_BANNER}}

    <div class="section-header" style="margin-bottom: 24px;">
      <div>
        <h1 class="section-title">Order Checkout</h1>
        <p class="section-desc">Review your selected enterprise appliances and complete payment.</p>
      </div>
    </div>

    <div class="checkout-grid">
      <div class="checkout-card">
        <h3>Order Summary</h3>
        <div id="cart-items">
          <div class="order-item">
            <div>
              <strong style="color:#ffffff;">Quantum Core X-9 Server</strong>
              <div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Enterprise Rack · 64-Core ARM v9</div>
            </div>
            <span style="font-weight:600;color:#ffffff;">$1,299.00</span>
          </div>
        </div>
        <div class="order-item" style="color:var(--text-muted);">
          <span>Express Handling &amp; Worldwide Shipping</span>
          <span style="color:var(--accent-green);font-weight:600;">FREE</span>
        </div>
        <div class="order-item" style="color:var(--text-muted);">
          <span>Estimated Sales Tax</span>
          <span>$0.00</span>
        </div>
        <div class="order-total-row">
          <span>Total Due</span>
          <span id="order-total" style="color:var(--primary);">$1,299.00</span>
        </div>
      </div>

      <div class="checkout-card">
        <h3>Payment &amp; Billing</h3>
        <!-- Preserves vulnerability: GET form transmitting card number in cleartext without TLS or CSP -->
        <form action="/lab/transport/checkout" method="get">
          <div class="form-group">
            <label class="form-label">Cardholder Full Name</label>
            <input type="text" class="form-control" placeholder="Alex Morgan" required>
          </div>
          <div class="form-group">
            <label class="form-label">Payment Card Number</label>
            <input name="card" class="form-control" placeholder="4111 1111 1111 1111" value="{{CARD_VAL}}" autocomplete="cc-number" required>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:1;">
              <label class="form-label">Expires</label>
              <input type="text" class="form-control" placeholder="MM/YY" required>
            </div>
            <div class="form-group" style="flex:1;">
              <label class="form-label">CVV</label>
              <input type="text" class="form-control" placeholder="123" required>
            </div>
          </div>
          <button type="submit" class="btn-primary" style="width:100%;padding:14px;font-size:15px;font-weight:600;margin-top:8px;cursor:pointer;">
            Complete Order &amp; Pay
          </button>
        </form>
      </div>
    </div>
  </main>

  <footer class="site-footer" style="margin-top:60px;">
    <div class="footer-bottom">
      <span>© 2026 ShadowLab Systems, Inc. All rights reserved.</span>
      <span>Enterprise Edge Platform</span>
    </div>
  </footer>

  <script>
    (function() {
      try {
        var cart = JSON.parse(localStorage.getItem('shadow_cart') || '[]');
        if (cart.length > 0) {
          var container = document.getElementById('cart-items');
          var total = 0;
          container.innerHTML = '';
          cart.forEach(function(item) {
            total += Number(item.price) || 0;
            var div = document.createElement('div');
            div.className = 'order-item';
            div.innerHTML = '<div><strong style="color:#ffffff;">' + item.name + '</strong>' +
              '<div style="font-size:12px;color:var(--text-muted);margin-top:2px;">Factory Certified Hardware</div></div>' +
              '<span style="font-weight:600;color:#ffffff;">$' + Number(item.price).toLocaleString() + '.00</span>';
            container.appendChild(div);
          });
          document.getElementById('order-total').textContent = '$' + total.toLocaleString() + '.00';
          var badges = document.querySelectorAll('.cart-count');
          badges.forEach(function(b) { b.textContent = cart.length; });
        }
      } catch(e) {}
    })();
  </script>
</body>
</html>"""
        html = template.replace("{{SUCCESS_BANNER}}", success_banner).replace("{{CARD_VAL}}", card_val)
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def lab_headers(self, head_only=False) -> None:
        self._send(
            200,
            b"<!doctype html><html><head><title>Support console</title></head><body>"
            b"<h1>Support console</h1><p>No CSP, no nosniff, no frame options.</p></body></html>",
            "text/html; charset=utf-8",
            hardened=False,
        )

    def lab_headers_json(self, head_only=False) -> None:
        """A JSON API response with no nosniff and no CSP — the ST-013 scenario."""
        self._send(
            200,
            b'{"service":"support-console","status":"ready","synthetic":true}',
            "application/json",
            hardened=False,
        )

    def lab_cookies(self, head_only=False) -> None:
        self._json(
            200,
            {"session": "ST-DEMO-SESSION-not-real", "note": "synthetic session"},
            {
                "Set-Cookie": "lab_session=ST-DEMO-SESSION-not-real; Path=/",
                "Cache-Control": "no-store",
            },
        )

    def lab_verbose_error(self, head_only=False) -> None:
        self._send(
            500,
            (
                b'{"error":"Traceback (most recent call last): File \"/srv/shadowlab/checkout.py\", '
                b'line 118, in submit\\n    cursor.execute(query)\\n'
                b'psycopg2.errors.SyntaxError: syntax error at or near \\"None\\"\\n'
                b'LINE 1: SELECT * FROM carts WHERE id = None"}'
            ),
            "application/json",
        )

    def lab_cors(self, head_only=False) -> None:
        self._json(
            200,
            {"profile": {"id": 1001, "email": "ada@example.test", "tenant": "synthetic"}},
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        )

    def lab_xss(self, head_only=False) -> None:
        query = parse_qs(urlsplit(self.path).query)
        name = (query.get("name") or [""])[0][:200]
        # Intentional: reflected without HTML-encoding. Text only — the page runs no script.
        body = (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Search</title></head><body><h1>Search results</h1>"
            f"<p>You searched for: {name}</p><p>No products matched.</p></body></html>"
        )
        self._send(200, body.encode("utf-8", "replace"), "text/html; charset=utf-8")

    def lab_sqli(self, head_only=False) -> None:
        query = parse_qs(urlsplit(self.path).query)
        raw = (query.get("id") or [""])[0][:100]
        if "'" in raw or "\\" in raw or " or " in raw.lower():
            # Canned database error. No query is built and no database is contacted.
            payload = {
                "error": 'SQLITE_ERROR: near "{}": syntax error'.format(raw.replace('"', "")),
                "query": "SELECT * FROM products WHERE id = '{}'".format(raw[:40]),
                "hint": "synthetic error from the ShadowLab training fixture",
            }
            self._send(
                500,
                json.dumps(payload).encode("utf-8", "replace"),
                "application/json",
            )
            return
        self._json(200, {"product": {"id": raw or "1", "name": "Synthetic widget"}})

    # A fake filesystem: path -> content. The host filesystem is never touched.
    LAB_FILES = {
        "readme.txt": "ShadowLab synthetic readme.\n",
        "etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
        "windows/win.ini": "[fonts]\r\n[extensions]\r\n; for 16-bit app support\r\n",
        "app/config.php": "<?php // synthetic config\n$db_password = 'example-only-not-real';\n",
    }

    def lab_file_download(self, head_only=False) -> None:
        query = parse_qs(urlsplit(self.path).query)
        requested = (query.get("file") or [""])[0][:200]
        # Intentional: the traversal is honoured (that is the lesson) but only against a
        # hard-coded in-memory table. Every path is normalised to a key; nothing is opened.
        key = requested.replace("\\", "/")
        while "../" in key:
            key = key.replace("../", "")
        key = key.lstrip("./")
        for candidate, content in self.LAB_FILES.items():
            if key.endswith(candidate):
                self._send(
                    200,
                    content.encode(),
                    "text/plain; charset=utf-8",
                    {"Content-Disposition": f"attachment; filename=\"{candidate.split('/')[-1]}\""},
                )
                return
        self._json(404, {"error": "file not found in the synthetic filesystem"})

    LAB_ACCOUNTS = {
        "1001": {"id": 1001, "owner": "ada@example.test", "iban": "GB00LAB00000000001001", "balance": 1250.00},
        "1002": {"id": 1002, "owner": "grace@example.test", "iban": "GB00LAB00000000001002", "balance": 9800.00},
        "1003": {"id": 1003, "owner": "linus@example.test", "iban": "GB00LAB00000000001003", "balance": 12.50},
    }

    def lab_idor_account(self, head_only=False) -> None:
        account_id = urlsplit(self.path).path.rsplit("/", 1)[-1][:12]
        account = self.LAB_ACCOUNTS.get(account_id)
        if account is None:
            self._json(404, {"error": "account not found"})
            return
        # Intentional: any caller may read any sequential account id.
        self._json(200, {"account": account, "authenticated": False})

    def lab_login(self, head_only=False) -> None:
        self._html(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Sign in</title></head><body><h1>Sign in</h1>"
            "<form action=\"/lab/auth/login\" method=\"post\">"
            "<input name=\"user\" autocomplete=\"username\">"
            "<input name=\"pass\" type=\"password\" autocomplete=\"current-password\">"
            "<button type=\"submit\">Sign in</button></form>"
            "<p>Synthetic accounts: ada@example.test / grace@example.test</p></body></html>"
        )

    def lab_admin_panel(self, head_only=False) -> None:
        # Intentional: no authentication at all.
        self._json(
            200,
            {
                "panel": "admin",
                "authenticated": False,
                "users": [
                    {"email": "ada@example.test", "role": "admin"},
                    {"email": "grace@example.test", "role": "billing"},
                ],
                "note": "synthetic training data",
            },
        )

    def lab_upload(self, head_only=False) -> None:
        self._html(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Upload avatar</title></head><body><h1>Upload avatar</h1>"
            "<p>Accepts any extension and trusts the declared content type.</p>"
            "<form action=\"/lab/upload\" method=\"post\" enctype=\"multipart/form-data\">"
            "<input type=\"file\" name=\"avatar\"><button type=\"submit\">Upload</button>"
            "</form><p>Training note: every POST to this lab is refused (405) and nothing is stored.</p>"
            "</body></html>",
        )

    def lab_redirect(self, head_only=False) -> None:
        query = parse_qs(urlsplit(self.path).query)
        target = (query.get("next") or ["/lab/landing"])[0][:300]
        # Intentional: the caller controls the target. Contained on purpose: absolute URLs
        # are refused, so the demo can never send a browser off the machine.
        if "://" in target or target.startswith("//"):
            self._json(400, {"error": "only local redirect targets are allowed in the lab"})
            return
        if not target.startswith("/"):
            target = "/" + target
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def lab_api_keys(self, head_only=False) -> None:
        self._json(
            200,
            {
                "keys": [
                    {"tenant": "synthetic-a", "key": "ST-DEMO-KEY-aaaa-not-real"},
                    {"tenant": "synthetic-b", "key": "ST-DEMO-KEY-bbbb-not-real"},
                ],
                "authenticated": False,
            },
        )

    def lab_input(self, head_only=False) -> None:
        query = parse_qs(urlsplit(self.path).query)
        raw = (query.get("q") or [""])[0][:200]
        body = (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Basket</title></head><body><h1>Basket</h1>"
            f"<p>Quantity accepted: {raw}</p>"
            "<p>No range check, no type check, no encoding.</p></body></html>"
        )
        self._send(200, body.encode("utf-8", "replace"), "text/html; charset=utf-8")

    def lab_diagnostics_env(self, head_only=False) -> None:
        # Synthetic placeholders only; the real environment is never read.
        self._json(
            200,
            {
                "env": "production",
                "DATABASE_URL": "postgres://demo:example-only-not-real@db.internal:5432/orders",
                "SECRET_KEY": "ST-DEMO-DIAGNOSTIC-not-real",
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "build": "shadowlab-2.0.0+9f2c1a",
            },
        )

    def lab_diagnostics_config(self, head_only=False) -> None:
        self._json(
            200,
            {
                "debug": True,
                "feature_flags": {"allow_anonymous_admin": True, "skip_csrf": True},
                "workers": 2,
                "queue": "synthetic",
                "note": "diagnostics route exposed to anyone",
            },
        )

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Keep the lab quiet; access logs are not needed for the demo.
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="ShadowLab synthetic target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    server.daemon_threads = True
    print(f"ShadowLab listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
