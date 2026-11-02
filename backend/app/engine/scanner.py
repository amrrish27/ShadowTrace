"""Scan orchestration: discovery -> reconciliation -> validation -> analysis -> findings."""
from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..config import Settings
from ..security.labgrant import lab_grant_ports
from . import persistence as store
from .crawler import CrawlOutcome, Crawler
from .extractors.har_extract import parse_har
from .normalizer import NormalizedEndpoint, normalize_endpoint
from .reconciler import Baseline, build_baseline, legacy_version_hint, match_key, reconcile
from .api_gate import api_likeness
from .rules import evaluate_endpoint, lint_wording
from .risk import risk_score
from .safe_http import RequestBudget, SafeHttpClient, ScanCancelled, ScanError
from .scan_rules import (
    ScanFacts,
    cleartext_http,
    legacy_api,
    secret_in_bundle,
    soft_404,
    source_map_exposed,
    technology_banner,
    zombie_endpoint,
)
from .scope import ScopePolicy
from .types import DiscoveredEndpoint, ExtractionResult, RuleInput, RuleHit
from .urlguard import canonicalize
from .validator import Soft404Probe, Validator

log = logging.getLogger("shadowtrace.scanner")

# Paths that name the caller's own session. ST-023 stays silent on these: a numeric id on
# /session/42 is not evidence of a missing object-level check. Container nouns such as
# "account" and "profile" are deliberately *not* in this list — /accounts/1002 is exactly
# where an object-level authorization failure lives, so suppressing it would hide the bug.
_AUTH_HINT = re.compile(r"/(?:me|self|session|sessions|whoami)(?:/|$)", re.IGNORECASE)

HARD_CAPS = {
    "max_requests": 2000,
    "max_pages": 200,
    "max_scripts": 100,
    "max_seconds": 900,
}


class ScanTimeout(Exception):
    pass


#: How many crawl-time responses the analyser reads (the crawler keeps up to 80).
MAX_ANALYSED_SAMPLES = 40


def _same_url(left: str, right: str) -> bool:
    """Compare two URLs ignoring the query string (and trailing slash)."""
    if not right:
        return False
    return left.split("?", 1)[0].rstrip("/") == str(right).split("?", 1)[0].rstrip("/")


def _observed_path(sources: List[DiscoveredEndpoint]) -> str:
    """The first concrete path the crawler/extractors actually saw for this endpoint."""
    for source in sources:
        candidate = str(getattr(source, "path", "") or "")
        if candidate and candidate != "/":
            return candidate[:300]
    return ""


@dataclass
class _SampleResponse:
    """The subset of a response a rule needs, built from a retained crawl sample."""

    url: str
    status: int
    headers: Dict[str, str]
    text: str

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


@dataclass
class ScanSummary:
    endpoints_found: int = 0
    endpoints_validated: int = 0
    shadow_endpoints: int = 0
    candidate_endpoints: int = 0
    discovered_endpoints: int = 0
    baseline_origin: str = "none"
    zombies: int = 0
    findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    pages_fetched: int = 0
    scripts_analyzed: int = 0
    requests_used: int = 0
    source_maps: int = 0
    external_references: int = 0
    requests_failed: int = 0
    unreachable: bool = False
    partial: bool = False
    cancelled: bool = False
    # Live phase, so the UI can say what the scan is doing right now.
    phase: str = "queued"
    # Honest outcome classification (see `_classify`): ok | unreachable | policy_blocked |
    # timeout | cancelled | empty | error. A scan that fetched nothing is never `ok`.
    outcome: str = ""
    policy_blocked: int = 0

    def as_counters(self) -> Dict[str, object]:
        return {
            "endpoints_found": self.endpoints_found,
            "endpoints_validated": self.endpoints_validated,
            "shadow_endpoints": self.shadow_endpoints,
            "candidate_endpoints": self.candidate_endpoints,
            "discovered_endpoints": self.discovered_endpoints,
            "baseline_origin": self.baseline_origin,
            "zombies": self.zombies,
            "findings": self.findings,
            "findings_by_severity": self.findings_by_severity,
            "pages_fetched": self.pages_fetched,
            "scripts_analyzed": self.scripts_analyzed,
            "requests_used": self.requests_used,
            "source_maps": self.source_maps,
            "external_references": self.external_references,
            "requests_failed": self.requests_failed,
            "unreachable": self.unreachable,
            "partial": self.partial,
            "phase": self.phase,
            "outcome": self.outcome,
            "policy_blocked": self.policy_blocked,
        }


def _clamp_int(value: object, default: int, hard_cap: int, minimum: int = 1) -> int:
    try:
        parsed = int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, hard_cap))


def _query_from_template(query_template: str) -> str:
    if not query_template:
        return ""
    parts = []
    for pair in query_template.split("&"):
        key = pair.split("=", 1)[0][:40]
        if key:
            parts.append(f"{key}=1")
    return "&".join(parts)


class Scanner:
    """Runs one scan. The worker owns the transaction/heartbeat around it."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        settings: Settings,
        *,
        scan: Dict[str, object],
        target: Dict[str, object],
        baseline_document: Optional[object] = None,
        baseline_label: str = "",
        har_text: Optional[str] = None,
        har_name: str = "",
        event: Optional[Callable[[str, str, str], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
        progress: Optional[Callable[[Dict[str, object]], None]] = None,
    ) -> None:
        self.conn = conn
        self.settings = settings
        self.scan = scan
        self.target = target
        self.scan_id = str(scan["id"])
        self.org_id = str(scan["org_id"])
        self.target_id = str(scan["target_id"])
        self.config: Dict[str, object] = json.loads(str(scan.get("config") or "{}"))
        self.baseline_document = baseline_document
        self.baseline_label = baseline_label
        self.har_text = har_text
        self.har_name = har_name
        self.event_cb = event
        self.cancel_check = cancel_check or (lambda: False)
        self.progress_cb = progress
        self.summary = ScanSummary()
        self.deadline = time.monotonic() + _clamp_int(
            self.config.get("max_seconds"), 300, HARD_CAPS["max_seconds"], minimum=10
        )
        self.result = ExtractionResult()
        self.crawl_outcome: Optional[CrawlOutcome] = None
        # Verified, signed lab grants for this target (empty unless the target is an
        # approved operator-authorized lab target). See security/labgrant.py.
        self.lab_grants = lab_grant_ports(dict(target), settings.secret_key)
        ports = json.loads(str(target.get("ports") or "[80,443]"))
        prefixes = json.loads(str(target.get("path_prefixes") or "[]"))
        self.base_url = str(target["base_url"]).rstrip("/")
        self.origin = f"{urlsplit(self.base_url).scheme}://{urlsplit(self.base_url).netloc}"
        self.scope = ScopePolicy.build(
            host=str(target["host"]),
            ports=[int(p) for p in ports],
            path_prefixes=[str(p) for p in prefixes],
        )
        self.baseline: Optional[Baseline] = None
        self.baseline_origin = "uploaded" if baseline_document is not None else "none"
        if baseline_document is not None:
            self.baseline = build_baseline(baseline_document, baseline_label or "baseline")
        self.endpoint_ids: Dict[str, str] = {}
        self.classifications: Dict[str, str] = {}
        self.statuses: Dict[str, str] = {}
        self.status_by_match: Dict[str, str] = {}
        self.raw_by_key: Dict[str, List[DiscoveredEndpoint]] = {}
        self.facts = ScanFacts(base_url=self.base_url)
        self.crawler: Optional[Crawler] = None
        self.budget: Optional[RequestBudget] = None

    # -- infrastructure --------------------------------------------------
    def event(self, kind: str, message: str, level: str = "info") -> None:
        if self.event_cb:
            self.event_cb(kind, message, level)
        else:
            store.add_event(self.conn, self.scan_id, kind, message, level)

    def _time_left(self) -> float:
        return self.deadline - time.monotonic()

    def _check_deadline(self) -> None:
        if self._time_left() <= 0:
            raise ScanTimeout()

    def _cancelled(self) -> bool:
        try:
            return bool(self.cancel_check())
        except Exception:
            return False

    def _progress(self) -> None:
        if self.budget is not None:
            self.summary.requests_used = self.budget.used
        if self.crawler is not None:
            self.summary.pages_fetched = self.crawler.outcome.pages_fetched
            self.summary.scripts_analyzed = self.crawler.outcome.scripts_analyzed
        if self.progress_cb:
            self.progress_cb(self.summary.as_counters())

    # -- pipeline --------------------------------------------------------
    def run(self) -> ScanSummary:
        self.event("scan.started", f"Scan started against {self.base_url}")
        self._phase("discover")
        budget = RequestBudget(
            limit=_clamp_int(self.config.get("max_requests"), 300, min(HARD_CAPS["max_requests"], self.settings.max_requests_per_scan_hard_cap))
        )
        self.budget = budget
        client = SafeHttpClient(
            self.settings,
            scope=self.scope,
            target_ports=tuple((self.scope.hosts[0], port) for port in self.scope.ports),
            lab_grants=self.lab_grants,
            budget=budget,
            scan_id=self.scan_id,
            cancel_check=self._cancelled,
            rate_per_second=8.0,
        )
        try:
            if self._discover(client):
                self._phase("normalize")
                self._normalize()
                self._phase("reconcile")
                self._reconcile()
                self._persist_endpoints()
                self._phase("validate")
                self._validate(client)
                self._phase("analyze")
                self._analyze()
        except ScanCancelled:
            self.summary.cancelled = True
            self.summary.partial = True
            self.event("scan.cancelled", "Cancellation requested; partial results kept", "warning")
        except ScanTimeout:
            self.summary.partial = True
            self.event("scan.timeout", "Scan time limit reached; partial results kept", "warning")
        finally:
            self.summary.requests_used = budget.used
            self.summary.policy_blocked = len(getattr(client, "blocked_attempts", []))
            self.summary.phase = "done"
            self.summary.outcome = self._classify()
            if self.summary.outcome != "ok":
                self.event(
                    "scan.outcome",
                    f"Scan outcome: {self.summary.outcome}"
                    + ("" if self.summary.outcome == "empty" else " — see the errors above"),
                    "warning" if self.summary.outcome in {"empty", "unreachable", "policy_blocked"} else "info",
                )
            self._progress()
        return self.summary

    def _phase(self, phase: str) -> None:
        """Record and publish the current phase so the UI can show real progress."""
        self.summary.phase = phase
        self._progress()

    def _classify(self) -> str:
        """Name what actually happened, instead of letting every scan look successful.

        ``ok``          at least one page was fetched and no policy refusal dominated
        ``policy_blocked`` the target was refused by policy and nothing was fetched
        ``unreachable`` the target could not be reached (connection/timeout/DNS)
        ``timeout``     the wall-clock budget ran out before the crawl finished
        ``cancelled``   a user cancelled the scan
        ``empty``       the target answered but yielded no endpoints at all
        """
        if self.summary.cancelled:
            return "cancelled"
        if self.summary.pages_fetched == 0:
            if self.summary.policy_blocked:
                return "policy_blocked"
            if self.summary.unreachable:
                return "unreachable"
            return "error"
        if self.summary.endpoints_found == 0:
            return "empty"
        return "ok"

    def _discover(self, client: SafeHttpClient) -> bool:
        self._check_deadline()
        if self._cancelled():
            raise ScanCancelled()
        if self.config.get("include_crawler", True):
            crawler = Crawler(
                client,
                self.scope,
                self.base_url,
                max_pages=_clamp_int(self.config.get("max_pages"), 12, HARD_CAPS["max_pages"]),
                max_scripts=_clamp_int(self.config.get("max_scripts"), 20, HARD_CAPS["max_scripts"]),
                max_source_maps=6 if self.config.get("include_source_maps", True) else 0,
                max_spec_probes=200 if self.config.get("include_specs", True) else 0,
                event=self.event,
                progress=self._progress,
            )
            self.crawler = crawler
            seed_urls = [self.base_url + "/"]
            configured_seeds = self.config.get("seeds") or []
            if isinstance(configured_seeds, list):
                for seed in configured_seeds[:10]:
                    try:
                        canonical = canonicalize(str(seed))
                    # Rationale: invalid seed is skipped and reported by the caller
                    except Exception:  # nosec B112
                        continue
                    if self.scope.check(canonical)[0]:
                        seed_urls.append(str(canonical))
            try:
                outcome = crawler.crawl(seeds=seed_urls)
            except ScanError:
                outcome = crawler.outcome
            self.crawl_outcome = outcome
            self.result.extend(outcome.result)
            self.summary.pages_fetched = outcome.pages_fetched
            self.summary.scripts_analyzed = outcome.scripts_analyzed
            self.summary.source_maps = outcome.source_maps_analyzed
            self.summary.external_references = len(outcome.external_references)
            for note in outcome.result.notes[:40]:
                if any(token in note for token in ("refused_remote_refs", "sitemap_rejected", "specification_rejected", "specification_unparseable", "source_map_traversal", "sitemap_entries:0")):
                    self.event("crawl.note", note.replace(":", ": ") + f" ({len(outcome.result.notes)} notes)", "warning")
            self.summary.requests_failed = len(outcome.errors)
            for error in outcome.errors[:20]:
                self.event("crawl.error", error, "warning")
            if outcome.pages_fetched == 0 and outcome.errors:
                # Nothing could be fetched: the honest result is "we could not look", not
                # "we looked and found nothing". Marking the scan partial keeps the state
                # machine untouched while making the failure visible in the counters, the
                # event log and the API payload.
                self.summary.unreachable = True
                self.summary.partial = True
                self.event(
                    "scan.target_unreachable",
                    f"No page could be fetched from the target ({len(outcome.errors)} request(s) failed); "
                    "the scan found nothing because it could not reach the target, not because the target is clean",
                    "error",
                )
            self.facts.source_maps = list(outcome.source_map_urls)
            self.secret_hits = list(outcome.secret_hits)
            self.facts.exposed_specs = list(outcome.spec_urls)
            self.event(
                "discovery.crawl",
                f"Crawled {outcome.pages_fetched} pages, analysed {outcome.scripts_analyzed} scripts, "
                f"{outcome.source_maps_analyzed} source maps; {len(outcome.external_references)} external references recorded",
            )
        if self.config.get("include_specs", True) and self.crawl_outcome is None:
            crawler = Crawler(client, self.scope, self.base_url, max_pages=0, max_scripts=0, event=self.event, progress=self._progress)
            self.crawler = crawler
            crawler.probe_well_known()
            self.result.extend(crawler.outcome.result)
        if self.baseline is not None:
            for key in sorted(self.baseline.endpoints):
                method, _, path = key.partition(" ")
                self.result.endpoints.append(
                    DiscoveredEndpoint(
                        method=method,
                        path=path,
                        source_type="openapi",
                        source_url=self.baseline_label or "baseline",
                        location="baseline operation",
                        snippet=f"{method} {path}",
                        extractor="baseline_route",
                        confidence=1.0,
                        base_url=self.base_url,
                    )
                )
            self.event("discovery.baseline", f"{len(self.baseline.endpoints)} documented operations added to the inventory")
        if self.har_text:
            har = parse_har(
                self.har_text,
                source_name=self.har_name or "upload.har",
                base_url=self.base_url,
                policy_hosts=(str(self.target["host"]),),
            )
            self.result.extend(har.result)
            self.event(
                "discovery.har",
                f"HAR import: {har.entries_total} entries, {har.entries_in_scope} in scope, "
                f"{har.entries_out_of_scope} out of scope dropped",
            )
        self.event("discovery.done", f"{len(self.result.endpoints)} raw endpoint candidates extracted")
        self._progress()
        return True

    def _normalize(self) -> None:
        grouped: Dict[str, Tuple[NormalizedEndpoint, List[DiscoveredEndpoint]]] = {}
        out_of_scope = 0
        gate_filtered = 0
        for raw in self.result.endpoints:
            normalized = normalize_endpoint(raw, self.base_url)
            if normalized is None:
                continue
            if not self.scope.host_in_scope(normalized.host):
                out_of_scope += 1
                continue
            if not self.scope.path_in_scope(normalized.path_template):
                continue
            key = normalized.fingerprint
            if key in grouped:
                grouped[key][1].append(raw)
            else:
                grouped[key] = (normalized, [raw])
        self.grouped = grouped
        self.summary.endpoints_found = len(grouped)
        if out_of_scope:
            self.event("discovery.out_of_scope", f"{out_of_scope} out-of-scope references recorded and not fetched", "info")
        if len(grouped) == 0 and self.summary.pages_fetched > 0:
            # Emit a structured explanation so the UI and event log show a helpful reason
            # rather than a bare "0 endpoints found". Count each category of loss.
            raw_total = len(self.result.endpoints)
            external_refs = self.summary.external_references
            # Count external script refs that were skipped (out_of_scope above)
            reasons: list[str] = []
            if raw_total == 0:
                reasons.append("no endpoints extracted from the page source (possibly a script-rendered SPA or a site with no inline API calls)")
            if out_of_scope:
                reasons.append(f"{out_of_scope} extracted reference(s) pointed to out-of-scope hosts (external scripts or CDN URLs excluded)")
            if external_refs:
                reasons.append(f"{external_refs} external reference(s) recorded but not fetched (out-of-scope host)")
            if not reasons:
                reasons.append("all extracted path patterns failed the API-likeness gate (static assets, HTML pages, or image-CDN URL fragments)")
            self.event(
                "discovery.zero_candidates",
                "No API endpoint candidates found after normalization. Likely reasons: "
                + "; ".join(reasons)
                + ". Consider uploading an OpenAPI/Postman baseline or a HAR file to provide ground-truth coverage.",
                "warning",
            )
        self._progress()

    def _reconcile(self) -> None:
        discovered_keys = [(normalized.method, normalized.path_template) for normalized, _raw in self.grouped.values()]

        # Baseline-less mode: if no baseline was uploaded, auto-discover specs on the target
        if self.baseline is None:
            spec_source_types = {"openapi", "swagger_ui", "redoc", "postman", "graphql"}
            spec_endpoints = set()
            for normalized, sources in self.grouped.values():
                for src in sources:
                    if src.source_type in spec_source_types:
                        spec_endpoints.add((normalized.method, normalized.path_template))
                        break
            if spec_endpoints or (hasattr(self, "facts") and self.facts.exposed_specs):
                self.baseline_origin = "auto-discovered"
                self.baseline_label = "auto-discovered openapi.json"
                paths_dict: Dict[str, Any] = {}
                for m, p in spec_endpoints:
                    paths_dict.setdefault(p, {})[m.lower()] = {"summary": "Discovered spec operation"}
                self.baseline = build_baseline({"paths": paths_dict}, self.baseline_label)
                self.event(
                    "reconcile.auto_baseline",
                    f"Auto-discovered specification on target ({len(spec_endpoints)} operations); classifying against auto-baseline",
                )
            else:
                self.baseline_origin = "none"
                self.baseline_label = "none"

        self.summary.baseline_origin = self.baseline_origin

        self.reconciliation = reconcile(
            discovered_keys,
            self.baseline,
            seen_paths=[path for _method, path in discovered_keys],
        )

        # Initial tentative classification: in baseline -> documented; not in baseline -> candidate
        for normalized, _sources in self.grouped.values():
            key = match_key(normalized.method, normalized.path_template)
            if self.baseline and key in self.baseline.endpoints:
                self.reconciliation.classifications[key] = "documented"
            else:
                self.reconciliation.classifications[key] = "candidate"

        self.facts.zombies = list(self.reconciliation.zombies)
        self.facts.legacy = legacy_version_hint(self.reconciliation.documented_keys, self.reconciliation.shadow_keys)
        self.summary.shadow_endpoints = 0  # Only live endpoints become shadow after validation
        self.summary.candidate_endpoints = len(self.grouped) - self.reconciliation.documented_count
        self.summary.zombies = self.reconciliation.zombie_count
        self.event(
            "reconcile.done",
            f"Reconciled {len(discovered_keys)} endpoints against baseline ({self.baseline_origin}): "
            f"{self.reconciliation.documented_count} documented, {len(discovered_keys) - self.reconciliation.documented_count} candidate",
        )

    def _classification_for(self, normalized: object) -> str:
        key = match_key(normalized.method, normalized.path_template)  # type: ignore[attr-defined]
        return self.reconciliation.classifications.get(key, "unknown")

    def _persist_endpoints(self) -> None:
        for normalized, sources in self.grouped.values():
            classification = self._classification_for(normalized)
            endpoint_id = store.upsert_endpoint(
                self.conn,
                org_id=self.org_id,
                target_id=self.target_id,
                normalized=normalized,
                scan_id=self.scan_id,
                classification=classification,
            )
            self.endpoint_ids[normalized.fingerprint] = endpoint_id
            self.classifications[normalized.fingerprint] = classification
            self.raw_by_key[normalized.fingerprint] = sources
            seen: set = set()
            for source in sources[:3]:
                signature = (source.source_type, source.location, source.extractor)
                if signature in seen:
                    continue
                seen.add(signature)
                store.add_source(
                    self.conn,
                    endpoint_id=endpoint_id,
                    scan_id=self.scan_id,
                    source=source,
                )
            store.link_scan_endpoint(self.conn, self.scan_id, endpoint_id, "unvalidated", classification)
        self.conn.commit()

    def _url_for(self, normalized: object) -> str:
        path = normalized.path_template.replace("{param}", "1").replace("{hash}", "abc123")  # type: ignore[attr-defined]
        path = path.replace("{id}", "1").replace("{uuid}", "00000000-0000-4000-8000-000000000000").replace("{date}", "2024-01-01")
        path = path.replace("{token}", "token")
        query = _query_from_template(normalized.query_template)  # type: ignore[attr-defined]
        return normalized.origin + path + (f"?{query}" if query else "")  # type: ignore[attr-defined]

    def _validate(self, client: SafeHttpClient) -> None:
        if not self.config.get("active_validation", True):
            self.event("validation.skipped", "Active validation disabled by scan configuration", "info")
            return
        soft404 = Soft404Probe(client, self.base_url)
        try:
            soft404.detect()
        except (ScanCancelled, ScanTimeout):
            raise
        except ScanError:
            pass
        if soft404.detected:
            self.facts.soft_404_detected = True
            self.facts.soft_404_sample = soft404.sample_url
            self.event("validation.soft_404", "Target returns a catch-all response for unknown paths; soft-404 matching enabled")
        validator = Validator(client, soft404=soft404, backoff_seconds=0.2)
        keys = sorted(
            self.grouped.keys(),
            key=lambda key: (
                0 if self.classifications.get(key) == "shadow" else 1,
                self.grouped[key][0].path_template.count("{param}") if hasattr(self.grouped[key][0], "path_template") else 0,
            ),
        )
        for index, key in enumerate(keys):
            self._check_deadline()
            if self._cancelled():
                raise ScanCancelled()
            normalized, _sources = self.grouped[key]
            endpoint_id = self.endpoint_ids[key]
            url = self._url_for(normalized)
            outcome = validator.validate(normalized.method, url)
            response = outcome.response
            self.statuses[key] = outcome.status
            self.status_by_match[match_key(normalized.method, normalized.path_template)] = outcome.status
            store.set_endpoint_status(
                self.conn, endpoint_id, outcome.status, response.status if response else None
            )
            store.link_scan_endpoint(
                self.conn,
                self.scan_id,
                endpoint_id,
                outcome.status,
                self.classifications.get(key, "unknown"),
                outcome.response.status if outcome.response is not None else None,
            )
            store.add_observation(
                self.conn,
                scan_id=self.scan_id,
                endpoint_id=endpoint_id,
                url=url,
                method=normalized.method,
                status_code=response.status if response else None,
                content_type=response.content_type if response else "",
                content_length=response.body_size if response else None,
                elapsed_ms=response.elapsed_ms if response else None,
                headers=response.headers if response else {},
                snippet=(response.text[:2000] if response else ""),
                error=outcome.error,
            )
            if response is not None:
                self.responses = getattr(self, "responses", {})
                self.responses[key] = (response, outcome.soft_404_match)
            if index % 20 == 0:
                self.conn.commit()
                self.summary.endpoints_validated = validator.stats.validated
                self._progress()
        reconciled = self._reconcile_validation_with_samples()
        self.conn.commit()
        self.summary.endpoints_validated = validator.stats.validated
        if reconciled:
            self.event(
                "validation.crawl_evidence",
                f"{reconciled} endpoint(s) did not answer the neutralised replay but did answer "
                "the target's own link; recorded as live from crawl evidence",
            )
        self.event(
            "validation.done",
            f"Validated {validator.stats.validated} endpoints "
            f"({validator.stats.live} live, {validator.stats.errors} errors, {validator.stats.skipped} skipped)",
        )
        self._apply_post_validation_classification()
        self._progress()

    def _apply_post_validation_classification(self) -> None:
        """Apply final classification based on live validation results and API-likeness."""
        shadow_keys: List[str] = []
        candidate_keys: List[str] = []
        discovered_keys: List[str] = []
        documented_keys: List[str] = []
        zombie_keys: List[str] = []

        for key, (normalized, sources) in self.grouped.items():
            endpoint_id = self.endpoint_ids[key]
            m_key = match_key(normalized.method, normalized.path_template)
            status = self.statuses.get(key, "unvalidated")
            resp_tuple = getattr(self, "responses", {}).get(key)
            response = resp_tuple[0] if resp_tuple else None
            soft_404 = resp_tuple[1] if resp_tuple else False
            status_code = response.status if response else None

            # Determine API-likeness
            is_api = api_likeness(normalized, response=response, sources=sources)

            # Is the endpoint live?
            # 2xx, 401, 403, 405 (and not a soft-404 catch-all)
            is_live = not soft_404 and (
                status in ("live", "auth_required", "redirected")
                or (status_code is not None and (200 <= status_code < 300 or status_code in (401, 403, 405)))
            )
            is_dead = (status == "not_found") or (status_code in (404, 410))

            is_in_baseline = bool(self.baseline and m_key in self.baseline.endpoints)

            if is_in_baseline:
                if is_dead:
                    cls = "zombie"
                    zombie_keys.append(m_key)
                else:
                    cls = "documented"
                    documented_keys.append(m_key)
            else:
                # Not in baseline
                if is_api and is_live:
                    if self.baseline_origin == "none":
                        cls = "discovered"
                        discovered_keys.append(m_key)
                    else:
                        cls = "shadow"
                        shadow_keys.append(m_key)
                else:
                    # Unconfirmed, 404/410, timeout, or non-API
                    cls = "candidate"
                    candidate_keys.append(m_key)

            self.classifications[key] = cls
            self.reconciliation.classifications[m_key] = cls
            store.set_endpoint_classification(self.conn, endpoint_id, cls)
            store.update_scan_endpoint_classification(self.conn, self.scan_id, endpoint_id, cls)

        self.reconciliation.shadow_keys = sorted(set(shadow_keys))
        self.reconciliation.documented_keys = sorted(set(documented_keys))
        self.reconciliation.zombies = [
            (normalized.method, normalized.path_template)
            for key, (normalized, _) in self.grouped.items()
            if self.classifications.get(key) == "zombie"
        ]
        self.facts.zombies = list(self.reconciliation.zombies)
        self.facts.legacy = legacy_version_hint(documented_keys, shadow_keys)
        self.summary.shadow_endpoints = len(shadow_keys)
        self.summary.zombies = len(self.reconciliation.zombies)
        self.summary.candidate_endpoints = len(candidate_keys)
        self.summary.discovered_endpoints = len(discovered_keys)
        self.summary.baseline_origin = self.baseline_origin
        self.conn.commit()
        self.event(
            "classification.finalized",
            f"Final classification: {len(shadow_keys)} shadow, {len(candidate_keys)} candidate, "
            f"{len(discovered_keys)} discovered, {len(documented_keys)} documented, {len(zombie_keys)} zombie (baseline: {self.baseline_origin})",
        )

    def _reconcile_validation_with_samples(self) -> int:
        """Mark endpoints live when the target itself served them to the crawler.

        Validation replays a URL with its parameters neutralised (`?file=1`), which many
        applications answer with 404 even though the endpoint is real. The crawler, by
        contrast, fetched the URL the application linked to. Recording that as `live` with
        the reason attached keeps the inventory honest in both directions: an endpoint is
        not called dead just because a synthetic probe missed, and an endpoint is not
        called live without evidence.
        """
        samples = getattr(self.crawl_outcome, "page_samples", None) or []
        if not samples:
            return 0
        best: Dict[str, int] = {}
        for url, status, _headers, _body in samples:
            key = self.key_for_url(url)
            if key is None:
                continue
            best[key] = max(best.get(key, 0), int(status or 0))
        changed = 0
        for key, status in best.items():
            if status < 200 or status >= 400:
                continue
            endpoint_id = self.endpoint_ids.get(key)
            if endpoint_id is None:
                continue
            if self.statuses.get(key, "") in {"live", "auth_required"}:
                continue
            self.conn.execute(
                "UPDATE scan_endpoints SET validation_status = 'live', response_status = ? "
                "WHERE scan_id = ? AND endpoint_id = ?",
                (status, self.scan_id, endpoint_id),
            )
            self.statuses[key] = "live"
            changed += 1
        return changed

    # -- analysis --------------------------------------------------------
    def _rule_input(self, key: str, response, soft_match: bool) -> RuleInput:
        normalized, sources = self.grouped[key]
        classification = self.classifications.get(key, "unknown")
        documented = classification == "documented"
        protected = bool(self.baseline and self.baseline.is_protected(normalized.method, normalized.path_template))
        return RuleInput(
            endpoint_method=normalized.method,
            endpoint_path=normalized.path_template,
            endpoint_url=response.url,
            classification=classification,
            status_code=response.status,
            headers=dict(response.headers),
            body_text=response.text[:300_000],
            content_type=response.content_type,
            discovered_from=[source.source_type for source in sources],
            target_scheme=normalized.scheme,
            documented=documented,
            baseline_protected=protected,
            soft_404_match=soft_match,
            path_has_auth_hint=_AUTH_HINT.search(normalized.path_template) is not None,
            sample_path=_observed_path(sources),
        )

    def _store_hit(self, hit: RuleHit, key: str, endpoint_id: Optional[str]) -> None:
        problems = lint_wording(hit.status, hit.rationale, hit.limitations)
        if problems:
            self.event("finding.wording_rejected", f"{hit.rule_id}: {'; '.join(problems)[:200]}", "warning")
            return
        score = risk_score(hit.severity, hit.confidence, hit.exposure)
        if key in self.grouped and self.classifications.get(key) == "candidate":
            score = min(score, 25.0)
        fingerprint = f"{hit.rule_id}|{key}"
        inserted = store.add_finding(
            self.conn,
            org_id=self.org_id,
            target_id=self.target_id,
            scan_id=self.scan_id,
            endpoint_id=endpoint_id,
            hit=hit,
            risk=score,
            fingerprint=fingerprint,
        )
        if inserted:
            self.summary.findings += 1
            self.summary.findings_by_severity[hit.severity] = self.summary.findings_by_severity.get(hit.severity, 0) + 1

    def _analyze_crawl_samples(self) -> None:
        """Run the endpoint rules over the responses the target itself linked to.

        Validation replays every parameter with a neutral value, which is the right call for
        a scanner that must not fire attack payloads. The consequence is that a rule which
        depends on what came back (reflection, echoed error text) can only see the neutral
        response. The crawler therefore keeps a bounded sample of the real responses it
        fetched, and analysis evaluates both. Findings are fingerprinted on
        ``rule_id|endpoint``, so a rule that fires on both inputs is stored once.
        """
        outcome = self.crawl_outcome
        samples = getattr(outcome, "page_samples", None) or []
        if not samples:
            return
        analysed = 0
        extra_rules = bool(self.config.get("extra_rules", False))
        for url, status, headers, body in samples[:MAX_ANALYSED_SAMPLES]:
            self._check_deadline()
            key = self.key_for_url(url)
            if key is None or key not in self.grouped:
                continue
            # A catch-all (soft-404) target answers 200 for nearly anything, so a sample
            # from one proves nothing for rules that key off a success status. Exactly one
            # URL is excluded here — the probe that established the catch-all. A page the
            # target itself linked to is a response the application chose to serve.
            if self.facts.soft_404_detected and _same_url(url, self.facts.soft_404_sample):
                continue
            sample = _SampleResponse(url=url, status=status, headers=headers, text=body)
            for hit in evaluate_endpoint(self._rule_input(key, sample, False), extra_rules=extra_rules):
                self._store_hit(hit, key, self.endpoint_ids.get(key))
            analysed += 1
        self.event(
            "analysis.crawl_samples",
            f"Analysed {analysed} of {len(samples)} crawl-time response(s) in addition to the validation replay",
        )

    def key_for_url(self, url: str) -> Optional[str]:
        """Map a fetched URL back to the endpoint key the rules are keyed by.

        Endpoints are grouped by ``NormalizedEndpoint.fingerprint``
        (``method|host|path_template|query_template``), which is what dedupes equivalent
        URLs — the same path reached with different parameter values is one endpoint.
        """
        try:
            candidate = normalize_endpoint(
                DiscoveredEndpoint(
                    method="GET",
                    path=urlsplit(url).path or "/",
                    query=urlsplit(url).query,
                    source_type="crawl",
                    source_url=url,
                    location=url,
                    snippet="",
                    extractor="crawl",
                    confidence=0.5,
                    base_url=f"{urlsplit(url).scheme}://{urlsplit(url).netloc}",
                ),
                default_base=self.base_url,
            )
        except Exception:  # pragma: no cover - defensive: normalisation is total
            return None
        if candidate is None:
            return None
        return candidate.fingerprint

    def _analyze(self) -> None:
        extra_rules = bool(self.config.get("extra_rules", False))
        responses = getattr(self, "responses", {})
        for key, (response, soft_match) in responses.items():
            self._check_deadline()
            rule_input = self._rule_input(key, response, soft_match)
            for hit in evaluate_endpoint(rule_input, extra_rules=extra_rules):
                self._store_hit(hit, key, self.endpoint_ids.get(key))
        self._analyze_crawl_samples()
        zombies: List[Tuple[str, str]] = []
        for key in self.reconciliation.documented_keys:
            method, _, path = key.partition(" ")
            if self.status_by_match.get(key, "unvalidated") == "not_found":
                zombies.append((method, path))
        self.facts.zombies = zombies[:50]
        self.summary.zombies = len(zombies)
        self.event("reconcile.zombies", f"{len(zombies)} documented operations are no longer reachable")
        scan_hits: List[Tuple[RuleHit, str]] = []
        seed_headers = getattr(self.crawl_outcome, "seed_headers", {}) if self.crawl_outcome else {}
        if extra_rules and seed_headers:
            server = seed_headers.get("server", "")
            powered = seed_headers.get("x-powered-by", "")
            if server or powered:
                scan_hits.append((technology_banner(server, powered, self.base_url + "/"), "banner"))
        if extra_rules and urlsplit(self.base_url).scheme == "http" and self.summary.pages_fetched > 0:
            sample = next(iter(sorted(self.grouped.keys())), "")
            sample_path = self.grouped[sample][0].path_template if sample else "/"
            scan_hits.append((cleartext_http(self.base_url, sample_path), "cleartext"))
        if extra_rules:
            for secret_url, kinds in getattr(self, "secret_hits", [])[:20]:
                scan_hits.append((secret_in_bundle(secret_url, kinds), f"secret|{secret_url}"))
        for map_url in self.facts.source_maps[:20]:
            scan_hits.append((source_map_exposed(map_url), map_url))
        for method, shadow_path, documented_path in self.facts.legacy[:20]:
            scan_hits.append((legacy_api(shadow_path, documented_path, method, self.base_url), shadow_path))
        for method, path in self.facts.zombies[:50]:
            scan_hits.append((zombie_endpoint(method, path, self.base_url), f"{method} {path}"))
        if self.facts.soft_404_detected:
            scan_hits.append((soft_404(self.facts.soft_404_sample), "soft-404"))
        for hit, discriminator in scan_hits:
            self._store_hit(hit, f"scan|{discriminator}", None)
        self.conn.commit()
        self.summary.final_state_note = "completed"  # type: ignore[attr-defined]
        self.event(
            "analysis.done",
            f"{self.summary.findings} findings recorded: " + ", ".join(f"{k}={v}" for k, v in sorted(self.summary.findings_by_severity.items())),
        )
        self._progress()
