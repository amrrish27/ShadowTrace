"""Scanner evaluation against the lab ground truth.

    python scripts/evaluate.py --scan-id <id> [--out docs/evidence]

Computes recall/precision of discovered shadow endpoints, reconciliation accuracy,
per-rule detection rate, negative-control false positives and trap outcomes.
Outputs JSON + Markdown evidence files. Never mutates the ground truth.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parent.parent
DYNAMIC_RE = re.compile(r"\{[^}]+\}")
DISCOVERY_NOISE_RULES = {"ST-010", "ST-011", "ST-019"}


def collapse(path: str) -> str:
    return DYNAMIC_RE.sub("{param}", path.rstrip("/") or "/")


def load_scan(db_path: str, scan_id: str) -> Tuple[sqlite3.Connection, dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if scan is None:
        raise SystemExit(f"scan {scan_id} not found in {db_path}")
    return conn, dict(scan)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scan-id", required=True)
    parser.add_argument("--db", default=os.environ.get("ST_DATABASE_PATH", "/tmp/st_smoke.db"))
    parser.add_argument("--out", default=str(ROOT / "docs" / "evidence"))
    parser.add_argument("--json-out", default="")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero unless recall/precision/rules/negatives/traps are all perfect",
    )
    args = parser.parse_args()
    ground_truth = json.loads((ROOT / "lab" / "ground_truth.json").read_text())
    conn, scan = load_scan(args.db, args.scan_id)

    discovered = [
        {
            "method": row["method"],
            "path": row["path_template"],
            "classification": row["classification"],
            "validation": row["validation_status"],
            "status": row["response_status"],
        }
        for row in conn.execute(
            """
            SELECT e.method, e.path_template, e.classification, e.validation_status, e.response_status
            FROM scan_endpoints se JOIN endpoints e ON e.id = se.endpoint_id WHERE se.scan_id = ?
            """,
            (args.scan_id,),
        )
    ]
    findings = [
        {
            "rule": row["rule_id"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "status": row["status"],
            "risk": row["risk_score"],
            "method": row["endpoint_method"] or "",
            "path": row["endpoint_path"] or "",
            "title": row["title"],
        }
        for row in conn.execute(
            """
            SELECT f.rule_id, f.severity, f.confidence, f.status, f.risk_score, f.title,
                   e.method AS endpoint_method, e.path_template AS endpoint_path
            FROM findings f LEFT JOIN endpoints e ON e.id = f.endpoint_id
            WHERE f.scan_id = ?
            """,
            (args.scan_id,),
        )
        if row["rule_id"] not in DISCOVERY_NOISE_RULES
    ]

    gt_shadow = {(item["method"], collapse(item["path"])) for item in ground_truth["shadow_endpoints"]}
    gt_validation = {
        (item["method"], collapse(item["path"])): item["validation"] for item in ground_truth["shadow_endpoints"]
    }
    found_shadow = {(item["method"], collapse(item["path"])) for item in discovered if item["classification"] == "shadow"}
    matched = gt_shadow & found_shadow
    recall = len(matched) / len(gt_shadow) if gt_shadow else 0.0
    precision = len(matched) / len(found_shadow) if found_shadow else 0.0
    missing = sorted(f"{m} {p}" for m, p in (gt_shadow - found_shadow))
    extra = sorted(f"{m} {p}" for m, p in (found_shadow - gt_shadow))
    validation_ok = [
        {"endpoint": f"{method} {path}", "expected": expected,
         "observed": next((d["validation"] for d in discovered if d["method"] == method and collapse(d["path"]) == path), "missing")}
        for (method, path), expected in gt_validation.items()
    ]

    baseline_paths = json.loads((ROOT / "lab" / "app" / "baseline.json").read_text())["paths"]
    documented_found = {
        collapse(item["path"]) for item in discovered if item["classification"] == "documented"
    }
    reconciliation = {
        "documented_expected": len(baseline_paths),
        "documented_observed": len(documented_found),
        "shadow_expected": len(gt_shadow),
        "shadow_observed": len(found_shadow),
        "zombies_expected": len(ground_truth["zombies"]),
        "zombies_observed": len([f for f in findings if f["rule"] == "ST-016"]),
    }

    detection: List[dict] = []
    for planted in ground_truth["planted_findings"]:
        rule = planted["rule"]
        if rule in DISCOVERY_NOISE_RULES:
            continue
        endpoint = planted["endpoint"].split(" ", 1)[-1]
        endpoint_collapsed = collapse(endpoint)
        hits = [
            f for f in findings
            if f["rule"] == rule and (
                not endpoint
                or endpoint.startswith("/st-nonexistent")
                or collapse(f["path"]) == endpoint_collapsed
                or f["path"] == endpoint
                or (rule in {"ST-014", "ST-015", "ST-016", "ST-010"} and not f["path"])
            )
        ]
        if rule in {"ST-014", "ST-015", "ST-016", "ST-010", "ST-009", "ST-012", "ST-017"}:
            hits = [f for f in findings if f["rule"] == rule]
        detection.append(
            {
                "rule": rule,
                "endpoint": planted["endpoint"],
                "detected": bool(hits),
                "count": len(hits),
            }
        )
    detected_count = sum(1 for item in detection if item["detected"])
    detection_rate = detected_count / len(detection) if detection else 0.0

    negative_controls = []
    for control in ground_truth["negative_controls"]:
        path = control["path"]
        if "decoy" in path:
            matching_endpoint = [
                item for item in discovered if path.rstrip("*") in item["path"]
            ]
            matching_findings = [
                f for f in findings if path.rstrip("*") in (f["path"] or "")
            ]
            negative_controls.append(
                {
                    "path": path,
                    "expected": control["expect"],
                    "findings": len(matching_findings),
                    "inventory_entries": len(matching_endpoint),
                    "pass": len(matching_findings) == 0,
                }
            )
        else:
            matching_findings = [f for f in findings if collapse(f["path"] or "") in {collapse(path)}]
            negative_controls.append(
                {
                    "path": path,
                    "expected": control["expect"],
                    "findings": len(matching_findings),
                    "pass": len(matching_findings) == 0,
                }
            )

    observations = {
        row["url"]: {"status": row["status_code"], "error": row["error"]}
        for row in conn.execute("SELECT url, status_code, error FROM observations WHERE scan_id = ?", (args.scan_id,))
    }
    events = [
        row["message"]
        for row in conn.execute("SELECT message FROM scan_events WHERE scan_id = ?", (args.scan_id,))
    ]
    traps = []
    for trap in ground_truth["traps"]:
        url = f"{ground_truth['target']}{trap['path']}"
        matched_obs = [obs for obs_url, obs in observations.items() if obs_url.startswith(url)]
        matched_events = [message for message in events if trap["path"] in message]
        refused_notes = [
            message for message in events
            if trap["path"] in ("/spec-remote-ref.json", "/sitemap-bomb.xml")
            and ("refused_remote_refs" in message or "sitemap_rejected" in message)
        ]
        blocked = any(obs["error"] for obs in matched_obs) or bool(matched_events) or bool(refused_notes)
        traps.append({"path": trap["path"], "expected": trap["expected"], "handled": blocked,
                      "observed": (matched_obs[:1] or matched_events[:1])})

    by_severity: Dict[str, int] = {}
    for finding in findings:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    # Discovery provenance: which extraction sources contributed endpoints.
    source_rows = conn.execute(
        """
        SELECT source_type, COUNT(DISTINCT endpoint_id) AS endpoints
        FROM endpoint_sources WHERE scan_id = ? GROUP BY source_type ORDER BY endpoints DESC, source_type
        """,
        (args.scan_id,),
    ).fetchall()
    sources = {
        "distinct_sources": len(source_rows),
        "required_minimum": 5,
        "meets_minimum": len(source_rows) >= 5,
        "breakdown": {str(row["source_type"]): int(row["endpoints"]) for row in source_rows},
    }

    report = {
        "scan_id": args.scan_id,
        "scan_state": scan["state"],
        "partial": bool(scan["partial"]),
        "counters": json.loads(scan["counters"] or "{}"),
        "discovery": {
            "shadow_recall": round(recall, 4),
            "shadow_precision": round(precision, 4),
            "matched": len(matched),
            "expected": len(gt_shadow),
            "observed": len(found_shadow),
            "missing": missing,
            "unexpected": extra,
            "validation_check": validation_ok,
        },
        "sources": sources,
        "reconciliation": reconciliation,
        "rules": {
            "planted": len(detection),
            "detected": detected_count,
            "detection_rate": round(detection_rate, 4),
            "details": detection,
            "findings_by_severity": by_severity,
        },
        "negative_controls": negative_controls,
        "negative_controls_passed": sum(1 for item in negative_controls if item["pass"]),
        "negative_controls_total": len(negative_controls),
        "traps": traps,
        "traps_handled": sum(1 for item in traps if item["handled"]),
        "traps_total": len(traps),
        "findings": findings,
    }
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = Path(args.json_out) if args.json_out else out_dir / "scanner-evaluation.json"
    json_path.write_text(json.dumps(report, indent=2))

    lines = [
        "# Scanner evaluation against ShadowLab ground truth",
        "",
        f"- Scan: `{args.scan_id}` ({scan['state']}, partial={bool(scan['partial'])})",
        f"- Shadow endpoints: recall **{recall:.1%}** ({len(matched)}/{len(gt_shadow)}), precision **{precision:.1%}** "
        f"({len(matched)}/{len(found_shadow)})",
        f"- Planted findings detected: **{detected_count}/{len(detection)}** ({detection_rate:.1%})",
        f"- Negative controls passed: **{sum(1 for item in negative_controls if item['pass'])}/{len(negative_controls)}**",
        f"- Hostile traps handled: **{sum(1 for item in traps if item['handled'])}/{len(traps)}**",
        f"- Discovery sources used: **{sources['distinct_sources']}** "
        f"({'meets' if sources['meets_minimum'] else 'BELOW'} the five-source minimum)",
        "",
        "## Discovery sources",
        "",
        "| Source | Endpoints contributed |",
        "|---|---|",
        *[f"| {name} | {count} |" for name, count in sources["breakdown"].items()],
        "",
        "## Reconciliation",
        "",
        f"- Baseline operations: {reconciliation['documented_expected']} documented, observed {reconciliation['documented_observed']}",
        f"- Shadow: {reconciliation['shadow_observed']} observed of {reconciliation['shadow_expected']} planted",
        f"- Zombies: {reconciliation['zombies_observed']} reported of {reconciliation['zombies_expected']} planted",
        "",
        "## Per-rule detection",
        "",
        "| Rule | Planted endpoint | Detected | Findings |",
        "|---|---|---|---|",
    ]
    for item in detection:
        lines.append(f"| {item['rule']} | `{item['endpoint']}` | {'yes' if item['detected'] else 'NO'} | {item['count']} |")
    lines += [
        "",
        "## Missing shadow endpoints",
        "",
        *([f"- `{item}`" for item in missing] if missing else ["- none"]),
        "",
        "## Unexpected (not in ground truth)",
        "",
        *([f"- `{item}`" for item in extra] if extra else ["- none"]),
        "",
        "## Negative controls",
        "",
        "| Control | Expected | Findings | Pass |",
        "|---|---|---|---|",
    ]
    for item in negative_controls:
        lines.append(f"| `{item['path']}` | {item['expected']} | {item.get('findings')} | {'yes' if item['pass'] else 'NO'} |")
    lines += ["", "## Hostile traps", "", "| Trap | Expected | Handled |", "|---|---|---|"]
    for item in traps:
        lines.append(f"| `{item['path']}` | {item['expected']} | {'yes' if item['handled'] else 'NO'} |")
    lines += [
        "",
        "## Validation status vs ground truth",
        "",
        "| Endpoint | Expected | Observed |",
        "|---|---|---|",
    ]
    for item in validation_ok:
        lines.append(f"| `{item['endpoint']}` | {item['expected']} | {item['observed']} |")
    lines += ["", "Full structured data: `scanner-evaluation.json`."]
    (out_dir / "scanner-evaluation.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({k: report[k] for k in ("discovery", "sources", "reconciliation", "rules", "negative_controls", "traps")}, indent=2)[:4000])
    print("written:", json_path)
    if args.strict:
        failures = []
        disc = report["discovery"]
        if disc.get("shadow_recall") != 1.0:
            failures.append(f"shadow_recall={disc.get('shadow_recall')}")
        if disc.get("shadow_precision") != 1.0:
            failures.append(f"shadow_precision={disc.get('shadow_precision')}")
        rules = report["rules"]
        if rules.get("detected") != rules.get("planted") or not rules.get("planted"):
            failures.append(f"rules={rules.get('detected')}/{rules.get('planted')}")
        if report.get("negative_controls_passed") != report.get("negative_controls_total"):
            failures.append(
                f"negative_controls={report.get('negative_controls_passed')}/{report.get('negative_controls_total')}"
            )
        if report.get("traps_handled") != report.get("traps_total"):
            failures.append(f"traps={report.get('traps_handled')}/{report.get('traps_total')}")
        sources = report["sources"]
        if not sources.get("meets_minimum"):
            failures.append(f"sources={sources.get('distinct_sources')}")
        if report.get("scan_state") != "completed" or report.get("partial"):
            failures.append(f"scan_state={report.get('scan_state')} partial={report.get('partial')}")
        if failures:
            print("STRICT EVALUATION FAILED: " + "; ".join(failures))
            return 1
        print(
            "strict evaluation passed:"
            f" recall={disc['shadow_recall']} precision={disc['shadow_precision']}"
            f" rules={rules['detected']}/{rules['planted']}"
            f" negatives={report['negative_controls_passed']}/{report['negative_controls_total']}"
            f" traps={report['traps_handled']}/{report['traps_total']}"
            f" sources={sources['distinct_sources']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
