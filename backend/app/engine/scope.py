"""Server-side scope policy. Out-of-scope URLs are observations, never requests."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence, Tuple

from .urlguard import CanonicalURL, canonicalize


@dataclass(frozen=True)
class ScopePolicy:
    hosts: Tuple[str, ...]
    ports: Tuple[int, ...] = (80, 443)
    path_prefixes: Tuple[str, ...] = ()
    wildcard_subdomains: Tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def build(
        cls,
        host: str,
        ports: Sequence[int],
        path_prefixes: Sequence[str] = (),
        wildcard_parents: Sequence[str] = (),
    ) -> "ScopePolicy":
        normalized_host = host.strip().lower().rstrip(".")
        return cls(
            hosts=(normalized_host,),
            ports=tuple(sorted({int(p) for p in ports})),
            path_prefixes=tuple(p.rstrip("/") or "/" for p in path_prefixes),
            wildcard_subdomains=tuple(p.strip().lower().rstrip(".") for p in wildcard_parents),
        )

    def host_in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        if host in self.hosts:
            return True
        for parent in self.wildcard_subdomains:
            if host != parent and host.endswith("." + parent):
                return True
        return False

    def port_in_scope(self, port: int) -> bool:
        return port in self.ports

    def path_in_scope(self, path: str) -> bool:
        if not self.path_prefixes:
            return True
        normalized = path or "/"
        for prefix in self.path_prefixes:
            if prefix == "/":
                return True
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        return False

    def check(self, url: CanonicalURL) -> Tuple[bool, str]:
        if not self.host_in_scope(url.host):
            return False, "host_out_of_scope"
        if not self.port_in_scope(url.port):
            return False, "port_out_of_scope"
        if not self.path_in_scope(url.path):
            return False, "path_out_of_scope"
        return True, ""


def is_in_scope(policy: ScopePolicy, url: str) -> bool:
    try:
        return policy.check(canonicalize(url))[0]
    except Exception:
        return False


def filter_in_scope(policy: ScopePolicy, urls: Iterable[str]) -> list[str]:
    kept = []
    for url in urls:
        if is_in_scope(policy, url):
            kept.append(url)
    return kept
