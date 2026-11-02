"""Reconciliation of discovered endpoints against the documented baseline.

Classification per endpoint: ``documented`` (in the baseline) or ``shadow`` (not
in the baseline).  Baseline operations that are never observed become ``zombie``
entries (documented but no longer reachable).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .normalizer import normalize_path

DYNAMIC_RE = re.compile(r"\{[A-Za-z0-9_]+\}")


def collapse(path_template: str) -> str:
    """Collapse any ``{...}`` parameter to ``{param}`` for stable matching."""
    return DYNAMIC_RE.sub("{param}", normalize_path(path_template))


def match_key(method: str, path_template: str) -> str:
    return f"{method.upper()} {collapse(path_template)}"


@dataclass
class Baseline:
    source: str
    endpoints: Set[str] = field(default_factory=set)
    protected: Set[str] = field(default_factory=set)
    title: str = ""
    version: str = ""
    endpoint_count: int = 0

    def add(self, method: str, path: str, *, protected: bool = False) -> None:
        key = match_key(method, path)
        self.endpoints.add(key)
        if protected:
            self.protected.add(key)
        self.endpoint_count = len(self.endpoints)

    def is_documented(self, method: str, path_template: str) -> bool:
        return match_key(method, path_template) in self.endpoints

    def is_protected(self, method: str, path_template: str) -> bool:
        return match_key(method, path_template) in self.protected


def build_baseline(document: object, source: str) -> Baseline:
    baseline = Baseline(source=source)
    if not isinstance(document, dict):
        return baseline
    baseline.title = str(document.get("info", {}).get("title", ""))[:120] if isinstance(document.get("info"), dict) else ""
    baseline.version = str(document.get("info", {}).get("version", ""))[:40] if isinstance(document.get("info"), dict) else ""
    global_security = bool(document.get("security"))
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return baseline
    for path, operations in list(paths.items())[:1000]:
        if not isinstance(path, str) or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            upper = str(method).upper()
            if upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}:
                continue
            protected = global_security
            if isinstance(operation, dict):
                if operation.get("security") is not None:
                    protected = bool(operation.get("security"))
            baseline.add(upper, path, protected=protected)
    return baseline


@dataclass
class ReconciliationResult:
    classifications: Dict[str, str] = field(default_factory=dict)
    shadow_keys: List[str] = field(default_factory=list)
    documented_keys: List[str] = field(default_factory=list)
    zombies: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def shadow_count(self) -> int:
        return len(self.shadow_keys)

    @property
    def documented_count(self) -> int:
        return len(self.documented_keys)

    @property
    def zombie_count(self) -> int:
        return len(self.zombies)


def reconcile(
    discovered: Iterable[Tuple[str, str]],
    baseline: Optional[Baseline],
    *,
    seen_paths: Sequence[str] = (),
) -> ReconciliationResult:
    """Classify each ``(method, path_template)``; compute zombies when a baseline exists."""
    result = ReconciliationResult()
    observed: Set[str] = set()
    for method, path_template in discovered:
        key = match_key(method, path_template)
        observed.add(key)
        if baseline is None:
            result.classifications[match_key(method, path_template)] = "unknown"
            continue
        if baseline.is_documented(method, path_template):
            result.classifications[key] = "documented"
            result.documented_keys.append(key)
        else:
            result.classifications[key] = "shadow"
            result.shadow_keys.append(key)
    if baseline is not None:
        for documented in sorted(baseline.endpoints - observed):
            if documented not in result.zombies:
                method, _, path = documented.partition(" ")
                result.zombies.append((method, path))
    result.shadow_keys = sorted(set(result.shadow_keys))
    result.documented_keys = sorted(set(result.documented_keys))
    return result


def legacy_version_hint(documented: Iterable[str], shadow: Iterable[str]) -> List[Tuple[str, str, str]]:
    """Find shadow paths that mirror a documented path under an older version prefix."""
    version_re = re.compile(r"/v(\d+)(?=/)")
    documented_set = set(documented)
    documented_versions: Dict[str, Set[str]] = {}
    for key in documented_set:
        method, _, path = key.partition(" ")
        match = version_re.search(path)
        if match:
            documented_versions.setdefault(method, set()).add(match.group(0))
    findings: List[Tuple[str, str, str]] = []
    for key in shadow:
        method, _, path = key.partition(" ")
        match = version_re.search(path)
        if not match:
            continue
        for documented_version in documented_versions.get(method, set()):
            if documented_version == match.group(0):
                continue
            mirrored = path.replace(match.group(0), documented_version, 1)
            if f"{method} {mirrored}" in documented_set:
                findings.append((method, path, mirrored))
    return findings


def compare_scans(
    previous: Dict[str, Tuple[str, str, Optional[int]]],
    current: Dict[str, Tuple[str, str, Optional[int]]],
) -> Dict[str, List[Dict[str, object]]]:
    """Scan comparison: new, removed and changed endpoints between two scans."""
    new: List[Dict[str, object]] = [
        {"fingerprint": k, "method": v[0], "path": v[1], "status": v[2]} for k, v in current.items() if k not in previous
    ]
    removed: List[Dict[str, object]] = [
        {"fingerprint": k, "method": v[0], "path": v[1], "status": v[2]} for k, v in previous.items() if k not in current
    ]
    changed: List[Dict[str, object]] = [
        {"fingerprint": k, "method": v[0], "path": v[1], "status": v[2], "previous_status": previous[k][2]}
        for k, v in current.items()
        if k in previous and previous[k][2] != v[2]
    ]
    return {"new": new, "removed": removed, "changed": changed}
