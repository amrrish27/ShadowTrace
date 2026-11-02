"""Strict request/response schemas (extra fields are rejected everywhere)."""
from __future__ import annotations

import re
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

ROLES = Literal["admin", "analyst", "viewer"]
TRIAGE_STATES = Literal["open", "accepted_risk", "false_positive", "fixed"]

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$")
_URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-\[\]:]{1,253}(/[^\s]{0,2000})?$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, strict=False)


class CredentialModel(BaseModel):
    """A request body that carries a password.

    ``str_strip_whitespace`` is OFF here on purpose. The bootstrap path and ``app.cli`` hash
    the configured password verbatim (``config._env_raw``, and ``cli._supplied`` documents
    that leading or trailing spaces are legitimate). Stripping it in the request model made
    such a password impossible to authenticate with -- and impossible to change, because
    ``current_password`` was stripped too.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False, strict=False)


class LoginRequest(CredentialModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("invalid email address")
        return value


class ChangePasswordRequest(CredentialModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class AcceptInviteRequest(CredentialModel):
    token: str = Field(min_length=20, max_length=200)
    name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)


class InviteRequest(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    role: ROLES

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("invalid email address")
        return value


class UserUpdateRequest(StrictModel):
    role: Optional[ROLES] = None
    is_active: Optional[bool] = None


class TargetCreateRequest(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    base_url: str = Field(min_length=8, max_length=2048)
    authorization_mode: Literal["ownership", "admin", "lab_allowlist"] = "ownership"
    attestation: str = Field(min_length=20, max_length=2000)
    justification: Optional[str] = Field(default=None, max_length=2000)
    ports: List[int] = Field(default_factory=lambda: [80, 443], max_length=8)
    path_prefixes: List[str] = Field(default_factory=list, max_length=20)

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not _URL_RE.match(value):
            raise ValueError("base_url must be an absolute http(s) URL")
        return value.rstrip("/")

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: List[int]) -> List[int]:
        cleaned = sorted({int(port) for port in value})
        if not cleaned or any(port < 1 or port > 65535 for port in cleaned):
            raise ValueError("ports must be valid TCP ports")
        if len(cleaned) > 4:
            raise ValueError("at most four ports may be authorized")
        return cleaned

    @field_validator("path_prefixes")
    @classmethod
    def _prefixes(cls, value: List[str]) -> List[str]:
        cleaned = []
        for prefix in value:
            if not prefix.startswith("/") or len(prefix) > 200 or ".." in prefix:
                raise ValueError("path prefixes must start with / and must not contain ..")
            cleaned.append(prefix.rstrip("/") or "/")
        return cleaned[:20]


class TargetUpdateRequest(StrictModel):
    """Partial edit of an authorized target. Every supplied field is re-validated."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=120)
    base_url: Optional[str] = Field(default=None, min_length=8, max_length=2048)
    ports: Optional[List[int]] = Field(default=None, max_length=8)
    path_prefixes: Optional[List[str]] = Field(default=None, max_length=20)
    authorization_mode: Optional[Literal["ownership", "admin", "lab_allowlist"]] = None
    justification: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            if not _URL_RE.match(value):
                raise ValueError("base_url must be an absolute http(s) URL")
            return value.rstrip("/")
        return value

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: Optional[List[int]]) -> Optional[List[int]]:
        if value is None:
            return None
        cleaned = sorted({int(port) for port in value})
        if not cleaned or any(port < 1 or port > 65535 for port in cleaned) or len(cleaned) > 4:
            raise ValueError("ports must be one to four valid TCP ports")
        return cleaned

    @field_validator("path_prefixes")
    @classmethod
    def _prefixes(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        for prefix in value:
            if not prefix.startswith("/") or len(prefix) > 200 or ".." in prefix:
                raise ValueError("path prefixes must start with / and must not contain ..")
        return value


class ApproveTargetRequest(StrictModel):
    justification: str = Field(min_length=20, max_length=2000)


class BaselineRequest(StrictModel):
    source: Literal["url", "upload"]
    url: Optional[str] = Field(default=None, max_length=2048)
    content: Optional[str] = Field(default=None, max_length=4_000_000)

    @field_validator("url")
    @classmethod
    def _url(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _URL_RE.match(value):
            raise ValueError("url must be an absolute http(s) URL")
        return value


class ScanCreateRequest(StrictModel):
    target_id: str = Field(min_length=8, max_length=64)
    include_crawler: bool = True
    include_source_maps: bool = True
    include_specs: bool = True
    active_validation: bool = True
    max_pages: int = Field(default=12, ge=1, le=200)
    max_scripts: int = Field(default=20, ge=0, le=100)
    max_requests: int = Field(default=300, ge=10, le=2000)
    max_seconds: int = Field(default=300, ge=10, le=900)
    baseline_id: Optional[str] = Field(default=None, max_length=64)
    har_import_id: Optional[str] = Field(default=None, max_length=64)
    attestation: str = Field(min_length=10, max_length=500)
    seeds: List[str] = Field(default_factory=list, max_length=10)


class LabTargetRequest(StrictModel):
    """Create (or adopt) the bundled lab target. The host/port come from deployment config."""

    name: Optional[str] = Field(default=None, max_length=120)
    attestation: Optional[str] = Field(default=None, max_length=2000)


class LabScanRequest(StrictModel):
    """Scan the bundled lab. Every limit is clamped again server-side by the scanner."""

    idempotency_key: str = Field(min_length=8, max_length=64)
    profile: Literal["quick", "standard", "deep"] = "standard"
    max_pages: int = Field(default=20, ge=1, le=200)
    max_scripts: int = Field(default=20, ge=0, le=100)
    max_requests: int = Field(default=400, ge=10, le=2000)
    max_seconds: int = Field(default=300, ge=10, le=900)
    attestation: Optional[str] = Field(default=None, max_length=500)


class TriageRequest(StrictModel):
    status: TRIAGE_STATES
    reason: str = Field(min_length=3, max_length=1000)


class Pagination(BaseModel):
    page: int = Field(default=1, ge=1, le=10_000)
    page_size: int = Field(default=25, ge=1, le=100)
