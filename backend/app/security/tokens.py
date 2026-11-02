"""Opaque token generation and storage hashing.

Session, invitation and verification tokens are random 256-bit values.  Only a
SHA-256 hash is stored, so a database leak does not yield usable tokens.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_equal(left_hash: str, right_hash: str) -> bool:
    return hmac.compare_digest(left_hash, right_hash)


def verification_token() -> str:
    """Per-target DNS/filesystem ownership-proof token (public by design)."""
    return "shadowtrace-verify-" + secrets.token_hex(16)
