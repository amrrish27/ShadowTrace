"""Shared engine data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class DiscoveredEndpoint:
    """A raw extraction result, before normalization and de-duplication."""

    method: str
    path: str
    query: str = ""
    source_type: str = "html"
    source_url: str = ""
    location: str = ""
    snippet: str = ""
    extractor: str = ""
    confidence: float = 0.7
    base_url: str = ""

    def with_base(self, base_url: str) -> "DiscoveredEndpoint":
        if self.base_url or not base_url:
            return self
        return DiscoveredEndpoint(
            method=self.method,
            path=self.path,
            query=self.query,
            source_type=self.source_type,
            source_url=self.source_url,
            location=self.location,
            snippet=self.snippet,
            extractor=self.extractor,
            confidence=self.confidence,
            base_url=base_url,
        )


@dataclass
class ExtractionResult:
    endpoints: List[DiscoveredEndpoint] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    inline_scripts: List[Tuple[str, str]] = field(default_factory=list)  # (location, code)
    links: List[str] = field(default_factory=list)
    specifications: List[Dict[str, object]] = field(default_factory=list)
    source_maps: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    external_references: List[str] = field(default_factory=list)

    def extend(self, other: "ExtractionResult") -> None:
        self.endpoints.extend(other.endpoints)
        self.scripts.extend(other.scripts)
        self.inline_scripts.extend(other.inline_scripts)
        self.links.extend(other.links)
        self.specifications.extend(other.specifications)
        self.source_maps.extend(other.source_maps)
        self.notes.extend(other.notes)
        self.external_references.extend(getattr(other, "external_references", []))


@dataclass(frozen=True)
class DocumentedEndpoint:
    method: str
    path_template: str
    source: str = "baseline"


@dataclass
class RuleInput:
    """Everything a rule may inspect about one endpoint/observation pair."""

    endpoint_method: str
    endpoint_path: str
    endpoint_url: str
    classification: str
    status_code: Optional[int]
    headers: Dict[str, str]
    body_text: str
    content_type: str
    discovered_from: Sequence[str]
    target_scheme: str
    documented: bool = False
    baseline_protected: bool = False
    soft_404_match: bool = False
    # True when the path itself advertises a credential (e.g. /users/me, /session).
    path_has_auth_hint: bool = False
    # The raw path as actually observed (before numeric segments collapsed to {param}).
    # Rules that reason about identifier shape need the real value, not the template.
    sample_path: str = ""


@dataclass(frozen=True)
class RuleHit:
    rule_id: str
    title: str
    severity: str
    confidence: str
    status: str
    exposure: float
    rationale: str
    limitations: str
    remediation: str
    evidence: Dict[str, object]
