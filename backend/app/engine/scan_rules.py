"""Scan-level rules (facts that are not tied to a single endpoint response)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

from ..security.redaction import make_snippet
from .evidence import repro_command
from .types import RuleHit


@dataclass
class ScanFacts:
    base_url: str
    source_maps: List[str] = field(default_factory=list)
    zombies: List[Tuple[str, str]] = field(default_factory=list)
    legacy: List[Tuple[str, str, str]] = field(default_factory=list)
    soft_404_detected: bool = False
    soft_404_sample: str = ""
    exposed_specs: List[str] = field(default_factory=list)


def _evidence(url: str, method: str, detail: str) -> Dict[str, object]:
    return {
        "request": {"method": method, "url": url},
        "detail": make_snippet(detail, 300),
        "reproduction": repro_command(method, url),
        "captured": "live response from the authorized target",
    }


def source_map_exposed(url: str, sources: int = 0) -> RuleHit:
    return RuleHit(
        rule_id="ST-014",
        title="Source map is publicly served",
        severity="medium",
        confidence="confirmed",
        status="confirmed",
        exposure=0.6,
        rationale=(
            f"The source map at {url} is publicly readable, exposing original source files"
            f"{f' ({sources} embedded sources)' if sources else ''}. This is an exposure indicator "
            "that can reveal internal routes and comments."
        ),
        limitations="The map was fetched read-only; no original path was resolved to a filesystem location.",
        remediation="Stop publishing source maps in production, or restrict them to authenticated internal users.",
        evidence=_evidence(url, "GET", f"sourceMappingURL -> {url}"),
    )


def legacy_api(shadow_path: str, documented_path: str, method: str, base_url: str) -> RuleHit:
    return RuleHit(
        rule_id="ST-015",
        title="Legacy API version is still reachable",
        severity="medium",
        confidence="high",
        status="confirmed",
        exposure=0.6,
        rationale=(
            f"{method} {shadow_path} mirrors the documented {documented_path} under an older version "
            "prefix and is still reachable. Legacy versions commonly lag behind current security fixes."
        ),
        limitations="Only reachability was observed; behaviour was not compared between versions.",
        remediation="Retire the legacy version, or document it as supported and apply the same controls as the current version.",
        evidence=_evidence(base_url.rstrip("/") + shadow_path.replace("{param}", "1"), method, f"{shadow_path} <-> {documented_path}"),
    )


def zombie_endpoint(method: str, path: str, base_url: str) -> RuleHit:
    return RuleHit(
        rule_id="ST-016",
        title="Documented endpoint is no longer reachable",
        severity="info",
        confidence="high",
        status="confirmed",
        exposure=0.1,
        rationale=(
            f"The baseline documents {method} {path}, but no scan traffic or probe reached it. "
            "Documentation drift causes integrators to rely on routes that no longer exist."
        ),
        limitations="The endpoint may require credentials or request parameters that were not supplied by design.",
        remediation="Remove the operation from the specification or restore the route.",
        evidence={"detail": f"{method} {path}", "reproduction": repro_command(method, base_url.rstrip("/") + path.replace("{param}", "1"))},
    )


def soft_404(sample: str) -> RuleHit:
    return RuleHit(
        rule_id="ST-017",
        title="Catch-all route returns success for unknown paths",
        severity="info",
        confidence="confirmed",
        status="confirmed",
        exposure=0.0,
        rationale=(
            "The target answers random, non-existent paths with the same successful response as real "
            "routes (a soft-404 catch-all). Endpoint validation in this scan compensates for it."
        ),
        limitations="This is a routing observation; it is not a vulnerability by itself.",
        remediation="Return a real 404 for unknown API paths, or document the catch-all behaviour.",
        evidence={"detail": make_snippet(sample, 200)},
    )


def technology_banner(server: str, powered: str, url: str) -> RuleHit:
    has_version = any(ch.isdigit() for ch in f"{server}{powered}")
    return RuleHit(
        rule_id="ST-009",
        title="Technology and version banners are disclosed",
        severity="low" if has_version else "info",
        confidence="confirmed",
        status="confirmed",
        exposure=0.2,
        rationale=(
            "The responses disclose technology banners (Server/X-Powered-By). "
            + ("A version number is included." if has_version else "No version number was identified.")
        ),
        limitations="Banner data can be spoofed and is weak evidence on its own; it was not correlated with a CVE.",
        remediation="Remove or generalize Server and X-Powered-By headers at the proxy.",
        evidence=_evidence(url, "GET", f"Server: {server or '(none)'}; X-Powered-By: {powered or '(none)'}"),
    )


def cleartext_http(url: str, sample_path: str) -> RuleHit:
    return RuleHit(
        rule_id="ST-012",
        title="API is served over cleartext HTTP",
        severity="medium",
        confidence="confirmed",
        status="confirmed",
        exposure=0.5,
        rationale=(
            f"The target base URL {url} uses cleartext HTTP; API traffic to {sample_path} and the rest of "
            "the origin is not protected in transit by TLS."
        ),
        limitations="Only the probing scheme is observed; an HTTPS listener may also exist on the host.",
        remediation="Serve the API exclusively over HTTPS and redirect HTTP to HTTPS at the proxy.",
        evidence=_evidence(url, "GET", f"cleartext origin: {url}"),
    )


def secret_in_bundle(url: str, kinds: Sequence[str]) -> RuleHit:
    return RuleHit(
        rule_id="ST-010",
        title="Credential-shaped string found in a public script",
        severity="high",
        confidence="medium",
        status="suspected",
        exposure=0.6,
        rationale=(
            f"The publicly served script {url} matches credential patterns ({', '.join(kinds)}). "
            "The match is pattern-based and may be a documented example value; the value was redacted, "
            "never validated against any provider and never used."
        ),
        limitations="Pattern matching only. A dummy or example value produces the same signal as a real secret.",
        remediation="Remove the value from client-accessible bundles, rotate it if real, and add a secret scanner to the build pipeline.",
        evidence=_evidence(url, "GET", f"matched patterns: {', '.join(kinds)} (value redacted)"),
    )


SCAN_RULES = (
    {"id": "ST-009", "title": "Technology and version banners are disclosed", "severity": "low", "confidence": "confirmed", "status": "confirmed"},
    {"id": "ST-012", "title": "API is served over cleartext HTTP", "severity": "medium", "confidence": "confirmed", "status": "confirmed"},
    {"id": "ST-014", "title": "Source map is publicly served", "severity": "medium", "confidence": "confirmed", "status": "confirmed"},
    {"id": "ST-015", "title": "Legacy API version is still reachable", "severity": "medium", "confidence": "high", "status": "confirmed"},
    {"id": "ST-016", "title": "Documented endpoint is no longer reachable", "severity": "info", "confidence": "high", "status": "confirmed"},
    {"id": "ST-017", "title": "Catch-all route returns success for unknown paths", "severity": "info", "confidence": "confirmed", "status": "confirmed"},
)
