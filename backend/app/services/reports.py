"""Report generation and export.

Everything is generated server-side from stored, already-redacted data.
Escaping is contextual: HTML escaping for HTML, formula neutralization for CSV,
backtick/pipe escaping for Markdown.  Exports are served as attachments with
``X-Content-Type-Options: nosniff``.
"""
from __future__ import annotations

import csv
import html
import io
import json
import sqlite3
from typing import Any, Dict, Iterable, List

from ..db import now

LIMITATIONS = [
    "Only read-only requests were sent: GET, HEAD and OPTIONS. No state-changing request, "
    "exploit payload, fuzzing, brute force or authentication-bypass attempt was performed.",
    "Only unauthenticated behaviour was observed. Authentication, authorization (BOLA) and "
    "business-logic flaws were not tested.",
    "Rate limiting, injection and client-side vulnerabilities were not tested by design.",
    "Findings describe exposure and configuration indicators observed in responses; they are not "
    "exploit confirmations.",
    "Discovery depends on the sources enabled for the scan; endpoints reachable only behind "
    "authentication or absent from every source will be missed.",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _rows(conn: sqlite3.Connection, sql: str, params: Iterable[Any] = ()) -> List[sqlite3.Row]:
    return list(conn.execute(sql, tuple(params)).fetchall())


def load_report_data(conn: sqlite3.Connection, *, scan_id: str, org_id: str) -> Dict[str, Any]:
    scan = conn.execute("SELECT * FROM scans WHERE id = ? AND org_id = ?", (scan_id, org_id)).fetchone()
    if scan is None:
        raise ValueError("scan not found")
    target = conn.execute("SELECT * FROM targets WHERE id = ? AND org_id = ?", (scan["target_id"], org_id)).fetchone()
    counters = json.loads(scan["counters"] or "{}")
    findings = [
        dict(row)
        for row in _rows(
            conn,
            """
            SELECT f.*, t.status AS triage_status, t.reason AS triage_reason,
                   e.method AS endpoint_method, e.path_template AS endpoint_path, e.host AS endpoint_host
            FROM findings f
            LEFT JOIN endpoints e ON e.id = f.endpoint_id
            LEFT JOIN triage_records t ON t.target_id = f.target_id AND t.fingerprint = f.fingerprint
            WHERE f.scan_id = ? AND f.org_id = ?
            ORDER BY f.risk_score DESC, f.severity
            """,
            (scan_id, org_id),
        )
    ]
    for finding in findings:
        finding["triage_status"] = finding["triage_status"] or "open"
        try:
            finding["evidence"] = json.loads(finding["evidence"] or "{}")
        except json.JSONDecodeError:
            finding["evidence"] = {"detail": "evidence unavailable"}
    inventory = [
        dict(row)
        for row in _rows(
            conn,
            """
            SELECT e.method, e.path_template, e.host, e.classification, e.validation_status,
                   e.response_status, e.first_seen_at, e.last_seen_at, e.id,
                   (SELECT COUNT(*) FROM endpoint_sources s WHERE s.endpoint_id = e.id) AS source_count,
                   (SELECT GROUP_CONCAT(DISTINCT s.source_type) FROM endpoint_sources s WHERE s.endpoint_id = e.id) AS source_types
            FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id
            WHERE se.scan_id = ?
            ORDER BY e.classification, e.path_template
            """,
            (scan_id,),
        )
    ]
    for item in inventory:
        if item.get("validation_status") == "unvalidated" and item.get("method") in ("POST", "PUT", "PATCH", "DELETE"):
            item["validation_display"] = "declared, unconfirmed"
        else:
            item["validation_display"] = item.get("validation_status") or "unvalidated"
    source_breakdown: Dict[str, int] = {}
    for row in _rows(
        conn,
        """
        SELECT s.source_type, COUNT(DISTINCT s.endpoint_id) AS endpoints
        FROM endpoint_sources s WHERE s.scan_id = ? GROUP BY s.source_type ORDER BY endpoints DESC
        """,
        (scan_id,),
    ):
        source_breakdown[str(row["source_type"])] = int(row["endpoints"])
    zombies = [
        dict(row)
        for row in _rows(
            conn,
            """
            SELECT f.title, f.rationale, f.evidence FROM findings f
            WHERE f.scan_id = ? AND f.rule_id = 'ST-016'
            """,
            (scan_id,),
        )
    ]
    summary_by_severity = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        summary_by_severity[finding["severity"]] = summary_by_severity.get(finding["severity"], 0) + 1
    return {
        "generated_at": now(),
        "scan": {
            "id": scan["id"],
            "state": scan["state"],
            "created_at": scan["created_at"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "partial": bool(scan["partial"]),
            "counters": counters,
            "config": json.loads(scan["config"] or "{}"),
        },
        "target": {
            "id": target["id"],
            "name": target["name"],
            "base_url": target["base_url"],
            "authorization_mode": target["authorization_mode"],
            "authorization_status": target["authorization_status"],
        },
        "summary": {
            "endpoints_found": counters.get("endpoints_found", len(inventory)),
            "endpoints_validated": counters.get("endpoints_validated", 0),
            "shadow_endpoints": counters.get("shadow_endpoints", 0),
            "documented_endpoints": sum(1 for item in inventory if item["classification"] == "documented"),
            "zombie_endpoints": counters.get("zombies", 0),
            "findings": len(findings),
            "findings_by_severity": summary_by_severity,
            "requests_used": counters.get("requests_used", 0),
        },
        "source_breakdown": source_breakdown,
        "inventory": inventory,
        "findings": findings,
        "zombies": zombies,
        "limitations": LIMITATIONS,
        "methodology": [
            "Enumerate sources: crawl in-scope HTML, parse JavaScript (AST + bounded fallback), source maps, "
            "OpenAPI/Swagger, Postman, documentation pages, robots.txt, sitemaps, HAR imports and response headers.",
            "Normalize discovered routes into path templates and reconcile them against the documented baseline.",
            "Validate each route with a single read-only request through the SSRF-hardened client, honoring "
            "budgets, rate limits and cancellation.",
            "Analyze responses for exposure indicators, then score risk from severity, confidence and exposure.",
        ],
    }


# -- renderers ---------------------------------------------------------------
def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    if text.startswith(("=", "+", "-", "@", "\t", "\r")):
        text = "'" + text
    if len(text) > 4000:
        text = text[:4000] + "..."
    return text


def render_csv_inventory(data: Dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["method", "path", "host", "classification", "validation_status", "response_status", "sources", "first_seen", "last_seen"])
    for item in data["inventory"]:
        writer.writerow(
            [
                _csv_safe(item["method"]),
                _csv_safe(item["path_template"]),
                _csv_safe(item["host"]),
                _csv_safe(item["classification"]),
                _csv_safe(item.get("validation_display", item["validation_status"])),
                _csv_safe(item["response_status"]),
                _csv_safe(item.get("source_types") or ""),
                _csv_safe(item["first_seen_at"]),
                _csv_safe(item["last_seen_at"]),
            ]
        )
    return buffer.getvalue()


def render_csv_findings(data: Dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["rule", "severity", "confidence", "status", "risk_score", "title", "method", "path", "triage", "remediation"])
    for finding in data["findings"]:
        writer.writerow(
            [
                _csv_safe(finding["rule_id"]),
                _csv_safe(finding["severity"]),
                _csv_safe(finding["confidence"]),
                _csv_safe(finding["status"]),
                _csv_safe(finding["risk_score"]),
                _csv_safe(finding["title"]),
                _csv_safe(finding.get("endpoint_method") or ""),
                _csv_safe(finding.get("endpoint_path") or ""),
                _csv_safe(finding.get("triage_status") or "open"),
                _csv_safe(finding["remediation"]),
            ]
        )
    return buffer.getvalue()


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


def render_markdown(data: Dict[str, Any]) -> str:
    scan = data["scan"]
    summary = data["summary"]
    lines = [
        f"# ShadowTrace report — {_md(data['target']['name'])}",
        "",
        f"- Target: `{_md(data['target']['base_url'])}`",
        f"- Scan: `{scan['id']}` ({scan['state']})",
        f"- Generated: {scan['finished_at'] or scan['created_at']} (epoch seconds)",
        f"- Partial results: {'yes' if scan['partial'] else 'no'}",
        "",
        "## Executive summary",
        "",
        f"The scan discovered **{summary['endpoints_found']}** endpoints, of which "
        f"**{summary['shadow_endpoints']}** are absent from the documented baseline and "
        f"**{summary['zombie_endpoints']}** documented endpoints were not reachable. "
        f"**{summary['findings']}** findings were recorded "
        f"({', '.join(f'{k}: {v}' for k, v in summary['findings_by_severity'].items() if v)}).",
        "",
        "Findings describe observed exposure indicators produced by read-only requests. They are not "
        "exploit confirmations.",
        "",
        "## Scope and methodology",
        "",
    ]
    lines.extend(f"- {_md(item)}" for item in data["methodology"])
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {_md(item)}" for item in data["limitations"])
    lines.extend(["", "## Inventory summary", "", "| Method | Path | Classification | Validation | Sources |", "|---|---|---|---|---|"])
    for item in data["inventory"][:1000]:
        lines.append(
            f"| {_md(item['method'])} | `{_md(item['path_template'])}` | {_md(item['classification'])} | "
            f"{_md(item.get('validation_display', item['validation_status']))} | {_md(item.get('source_types') or '')} |"
        )
    lines.extend(["", "## Findings", ""])
    for finding in data["findings"]:
        lines.extend(
            [
                f"### {finding['severity'].upper()} — {_md(finding['title'])} ({finding['rule_id']})",
                "",
                f"- Endpoint: `{_md(finding.get('endpoint_method') or '')} {_md(finding.get('endpoint_path') or '')}`",
                f"- Confidence: {_md(finding['confidence'])} · Status: {_md(finding['status'])} · Risk score: {finding['risk_score']}",
                f"- Triage: {_md(finding.get('triage_status') or 'open')}",
                "",
                f"**Rationale.** {_md(finding['rationale'])}",
                "",
                f"**Evidence.** `{_md(finding['evidence'].get('detail') or finding['evidence'].get('response', {}).get('body_excerpt', ''))}`",
                "",
                f"**Reproduction.** `{_md(finding['evidence'].get('reproduction', ''))}`",
                "",
                f"**Remediation.** {_md(finding['remediation'])}",
                "",
                f"**Limitations.** {_md(finding['limitations'])}",
                "",
            ]
        )
    lines.extend(["## Remediation roadmap", ""])
    for index, finding in enumerate(data["findings"][:50], start=1):
        lines.append(f"{index}. **{finding['severity'].upper()}** — {_md(finding['title'])}: {_md(finding['remediation'])}")
    return "\n".join(lines)


def render_html(data: Dict[str, Any]) -> str:
    esc = html.escape
    scan = data["scan"]
    summary = data["summary"]
    rows = []
    for finding in data["findings"]:
        rows.append(
            "<tr>"
            f"<td><span class='sev sev-{esc(finding['severity'])}'>{esc(finding['severity'])}</span></td>"
            f"<td>{esc(finding['title'])}</td>"
            f"<td>{esc(finding.get('endpoint_method') or '')} {esc(finding.get('endpoint_path') or '')}</td>"
            f"<td>{esc(finding['confidence'])}</td>"
            f"<td>{finding['risk_score']}</td>"
            f"<td>{esc(finding.get('triage_status') or 'open')}</td>"
            "</tr>"
        )
    inv_rows = []
    for item in data["inventory"][:2000]:
        inv_rows.append(
            "<tr>"
            f"<td>{esc(item['method'])}</td><td>{esc(item['path_template'])}</td>"
            f"<td>{esc(item['classification'])}</td><td>{esc(item.get('validation_display', item['validation_status']))}</td>"
            f"<td>{esc(item.get('source_types') or '')}</td></tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ShadowTrace report {esc(scan['id'])}</title>
<style>
:root{{color-scheme:dark}}
body{{background:#0b1020;color:#e6e9f2;font:14px/1.6 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;padding:32px}}
h1{{font-size:24px;margin:0 0 4px}} h2{{margin-top:32px;font-size:18px;border-bottom:1px solid #26304d;padding-bottom:6px}}
.muted{{color:#9aa4bf}} table{{border-collapse:collapse;width:100%;margin-top:12px;font-size:13px}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #1d2540;vertical-align:top}}
th{{color:#9aa4bf;font-weight:600}}
.sev{{padding:2px 8px;border-radius:999px;font-size:11px;text-transform:uppercase}}
.sev-critical{{background:#4c0519;color:#ffb4c0}} .sev-high{{background:#4a1d0b;color:#ffc9a3}}
.sev-medium{{background:#4a3f0b;color:#ffe08a}} .sev-low{{background:#0b3a4a;color:#a5e8ff}}
.sev-info{{background:#1c2440;color:#b9c3de}}
.card{{background:#111830;border:1px solid #1d2540;border-radius:12px;padding:16px 20px;margin:12px 0}}
.kpis{{display:flex;gap:12px;flex-wrap:wrap}} .kpi{{flex:1;min-width:120px}}
.kpi b{{display:block;font-size:22px}}
code{{background:#0a0f1e;padding:1px 5px;border-radius:5px;font-size:12px}}
footer{{margin-top:40px;color:#6b7694;font-size:12px}}
</style></head>
<body>
<h1>ShadowTrace report</h1>
<p class="muted">Target <code>{esc(data['target']['base_url'])}</code> · scan {esc(scan['id'])} · {esc(scan['state'])}</p>
<div class="card kpis">
  <div class="kpi"><span class="muted">Endpoints</span><b>{summary['endpoints_found']}</b></div>
  <div class="kpi"><span class="muted">Shadow</span><b>{summary['shadow_endpoints']}</b></div>
  <div class="kpi"><span class="muted">Zombies</span><b>{summary['zombie_endpoints']}</b></div>
  <div class="kpi"><span class="muted">Findings</span><b>{summary['findings']}</b></div>
  <div class="kpi"><span class="muted">Requests used</span><b>{summary['requests_used']}</b></div>
</div>
<h2>Executive summary</h2>
<p>The scan reconciled discovered routes against the documented baseline. All findings were produced by
read-only requests (GET, HEAD, OPTIONS) and describe exposure indicators, not exploit confirmations.</p>
<h2>Limitations</h2>
<ul>{''.join(f'<li>{esc(item)}</li>' for item in data['limitations'])}</ul>
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Title</th><th>Endpoint</th><th>Confidence</th><th>Risk</th><th>Triage</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="6">No findings</td></tr>'}</tbody></table>
<h2>Inventory</h2>
<table><thead><tr><th>Method</th><th>Path</th><th>Classification</th><th>Validation</th><th>Sources</th></tr></thead>
<tbody>{''.join(inv_rows) or '<tr><td colspan="5">No endpoints</td></tr>'}</tbody></table>
<h2>Remediation roadmap</h2>
<ol>{''.join(f"<li><b>{esc(f['severity'].upper())}</b> — {esc(f['title'])}: {esc(f['remediation'])}</li>" for f in data['findings'][:50])}</ol>
<footer>Generated by ShadowTrace from stored scan data. No scripts are included in this document.</footer>
</body></html>"""


def render_openapi_stub(data: Dict[str, Any]) -> str:
    paths: Dict[str, Any] = {}
    for item in data["inventory"]:
        if item["classification"] not in {"shadow", "unknown"}:
            continue
        path = item["path_template"]
        paths.setdefault(path, {})[item["method"].lower()] = {
            "summary": "Discovered by ShadowTrace (undocumented at scan time)",
            "responses": {"default": {"description": f"Observed validation status: {item.get('validation_display', item['validation_status'])}"}},
        }
    stub = {
        "openapi": "3.0.3",
        "info": {
            "title": f"Discovered endpoints — {data['target']['name']}",
            "version": "discovered",
            "description": "Draft stub generated from a ShadowTrace scan. Not a verified contract.",
        },
        "paths": paths,
    }
    return json.dumps(stub, indent=2)


def render_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, indent=2, default=str)


def attachment_headers(filename: str, content_type: str) -> Dict[str, str]:
    return {
        "Content-Type": content_type,
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "no-store",
    }
