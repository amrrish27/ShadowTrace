"""Password hashing (argon2id) and password policy."""
from __future__ import annotations

import hmac
import secrets
import string
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from argon2.low_level import Type

MIN_PASSWORD_LENGTH: Final = 12
MAX_PASSWORD_LENGTH: Final = 256

_WEAK_PASSWORDS = {
    "password1234",
    "passwordpassword",
    "letmein12345",
    "changeme1234",
    "administrator",
    "qwertyuiop12",
    "shadowtrace1",
    "123456789012",
}

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Verified against the dummy hash on unknown accounts so that login timing and
# messages are identical for existing and non-existing users (SSEC-AUTH-07).
_DUMMY_HASH = _hasher.hash("shadowtrace-dummy-password-value")


class WeakPassword(ValueError):
    pass


def validate_password(password: str, *, email: str = "", name: str = "") -> None:
    if not isinstance(password, str):
        raise WeakPassword("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPassword(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPassword("password must be shorter than 256 characters")
    lowered = password.lower()
    if lowered in _WEAK_PASSWORDS:
        raise WeakPassword("password is too common")
    if email and lowered == email.lower():
        raise WeakPassword("password must not equal the email address")
    if name and lowered == name.lower():
        raise WeakPassword("password must not equal the display name")
    classes = sum(
        [
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(c in string.punctuation for c in password),
        ]
    )
    if classes < 3:
        raise WeakPassword("password must mix at least three of: lower, upper, digit, symbol")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant-work verification; unknown users verify against a dummy hash."""
    if not password:
        return False
    candidate_hash = password_hash or _DUMMY_HASH
    try:
        return _hasher.verify(candidate_hash, password) and password_hash is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8", "ignore"), right.encode("utf-8", "ignore"))


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))
