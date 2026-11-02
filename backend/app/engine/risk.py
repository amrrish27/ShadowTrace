"""Documented risk scoring.

``risk_score`` is monotonic in severity and in confidence, and bounded to 0..100.
The severity bands do not overlap, so a higher severity can never score below a
lower one (property-tested with Hypothesis).
"""
from __future__ import annotations

from typing import Final

SEVERITY_BASE: Final = {"critical": 80.0, "high": 60.0, "medium": 40.0, "low": 20.0, "info": 2.0}
CONFIDENCE_WEIGHT: Final = {"confirmed": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
SEVERITY_ORDER: Final = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER: Final = ["low", "medium", "high", "confirmed"]

SEVERITY_BONUS = 12.0
EXPOSURE_BONUS = 4.0


def risk_score(severity: str, confidence: str, exposure: float) -> float:
    if severity not in SEVERITY_BASE:
        raise ValueError(f"unknown severity {severity!r}")
    if confidence not in CONFIDENCE_WEIGHT:
        raise ValueError(f"unknown confidence {confidence!r}")
    bounded_exposure = min(1.0, max(0.0, float(exposure)))
    base = SEVERITY_BASE[severity]
    score = base + SEVERITY_BONUS * CONFIDENCE_WEIGHT[confidence] + EXPOSURE_BONUS * bounded_exposure
    return round(min(100.0, max(0.0, score)), 2)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)


def confidence_rank(confidence: str) -> int:
    return CONFIDENCE_ORDER.index(confidence)


def exposure_factor(*, unauthenticated: bool, in_scope: bool = True, sensitive_path: bool = False) -> float:
    value = 0.2
    if unauthenticated:
        value += 0.5
    if sensitive_path:
        value += 0.2
    if not in_scope:
        value -= 0.2
    return round(min(1.0, max(0.0, value)), 2)
