"""Safe validation of discovered endpoints.

Only GET, HEAD and OPTIONS are ever sent.  The validator enforces budgets, backs
off on 429/5xx responses, opens a circuit breaker after repeated failures, and
detects soft-404 catch-alls so that an SPA shell is not reported as a live API.
"""
from __future__ import annotations

import difflib
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from .safe_http import (
    BlockedRequest,
    BudgetExceeded,
    ResponseData,
    ResponseTimeout,
    ResponseTooLarge,
    SafeHttpClient,
    ScanCancelled,
    ScanError,
    TargetRequestError,
)

ALLOWED_VALIDATION_METHODS = {"GET", "HEAD", "OPTIONS"}
MAX_CONSECUTIVE_ERRORS = 5
_SIGNATURE_STRIP = re.compile(r"\d+")


def _signature(response: ResponseData, limit: int = 400) -> str:
    text = response.text[:limit]
    collapsed = _SIGNATURE_STRIP.sub("0", " ".join(text.split()).lower())
    return collapsed[:limit]


@dataclass
class Soft404Probe:
    client: SafeHttpClient
    base_url: str
    sample_status: Optional[int] = None
    sample_signature: str = ""
    sample_url: str = ""
    sample_length: int = 0

    def detect(self) -> None:
        token = secrets.token_hex(6)
        url = f"{self.base_url.rstrip('/')}/st-nonexistent-{token}"
        try:
            response = self.client.request("GET", url)
        except ScanError:
            self.sample_status = None
            return
        self.sample_status = response.status
        self.sample_signature = _signature(response)
        self.sample_url = url
        self.sample_length = response.body_size

    @property
    def detected(self) -> bool:
        return self.sample_status is not None and 200 <= self.sample_status < 300

    def matches(self, response: ResponseData) -> bool:
        if not self.detected or not (200 <= response.status < 300):
            return False
        candidate = _signature(response)
        if not candidate or not self.sample_signature:
            return False
        # Size gate first: a materially different document cannot be the shell.
        if self.sample_length:
            delta = abs(response.body_size - self.sample_length) / float(self.sample_length)
            if delta > 0.25:
                return False
        ratio = difflib.SequenceMatcher(None, candidate, self.sample_signature).ratio()
        return ratio >= 0.9


@dataclass
class ValidationOutcome:
    status: str
    response: Optional[ResponseData] = None
    soft_404_match: bool = False
    error: Optional[str] = None
    error_category: Optional[str] = None


@dataclass
class ValidationStats:
    validated: int = 0
    live: int = 0
    errors: int = 0
    skipped: int = 0
    blocked: int = 0
    circuit_open: bool = False
    outcomes: List[ValidationOutcome] = field(default_factory=list)


class Validator:
    def __init__(
        self,
        client: SafeHttpClient,
        *,
        soft404: Optional[Soft404Probe] = None,
        backoff_seconds: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.client = client
        self.soft404 = soft404
        self.backoff_seconds = backoff_seconds
        self.sleep = sleep
        self.consecutive_errors = 0
        self.stats = ValidationStats()

    def _record(self, outcome: ValidationOutcome) -> ValidationOutcome:
        self.stats.outcomes.append(outcome)
        return outcome

    def validate(self, method: str, url: str) -> ValidationOutcome:
        method = method.upper()
        if method not in ALLOWED_VALIDATION_METHODS:
            self.stats.skipped += 1
            return self._record(
                ValidationOutcome(status="unvalidated", error="method_not_allowed_for_safe_validation")
            )
        if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
            self.stats.skipped += 1
            self.stats.circuit_open = True
            return self._record(ValidationOutcome(status="skipped_budget", error="circuit_breaker_open"))
        try:
            response = self.client.request(method, url)
        except BudgetExceeded:
            self.stats.skipped += 1
            return self._record(ValidationOutcome(status="skipped_budget", error="request_budget_exhausted"))
        except BlockedRequest as exc:
            self.stats.blocked += 1
            return self._record(
                ValidationOutcome(status="blocked", error="policy_blocked", error_category=exc.category)
            )
        except ScanCancelled:
            raise
        except ResponseTimeout as exc:
            self._error()
            return self._record(ValidationOutcome(status="error", error=exc.message, error_category="timeout"))
        except (ResponseTooLarge, TargetRequestError) as exc:
            self._error()
            return self._record(ValidationOutcome(status="error", error=exc.message, error_category="target_error"))
        except ScanError as exc:
            self._error()
            return self._record(ValidationOutcome(status="error", error=exc.message, error_category=exc.category))

        self.stats.validated += 1
        soft_match = bool(self.soft404 and self.soft404.matches(response))
        if 200 <= response.status < 300 and not soft_match:
            status = "live"
            self.stats.live += 1
            self.consecutive_errors = 0
        elif response.status in (401, 403):
            status = "auth_required"
            self.consecutive_errors = 0
        elif response.status in (404, 410) or soft_match:
            status = "not_found"
            self.consecutive_errors = 0
        elif 300 <= response.status < 400:
            status = "redirected"
            self.consecutive_errors = 0
        elif response.status == 429 or response.status >= 500:
            status = "error"
            self._error()
            if self.backoff_seconds:
                self.sleep(min(self.backoff_seconds * (2 ** min(self.consecutive_errors, 4)), 5.0))
        else:
            status = "live" if response.status == 204 else "error"
        return self._record(
            ValidationOutcome(status=status, response=response, soft_404_match=soft_match)
        )

    def _error(self) -> None:
        self.consecutive_errors += 1
        self.stats.errors += 1
