"""Password and opaque session helpers for the authentication API."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

PASSWORD_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    return PASSWORD_HASHER.hash(password)


def verify_password(encoded_hash: str | None, password: str) -> bool:
    if not encoded_hash:
        return False
    try:
        return PASSWORD_HASHER.verify(encoded_hash, password)
    except (InvalidHashError, VerificationError):
        return False


def new_session_token() -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("utf-8")).hexdigest()


def session_expiry(ttl_minutes: int, now: datetime | None = None) -> datetime:
    if ttl_minutes < 1 or ttl_minutes > 10080:
        raise ValueError("SESSION_TTL_MINUTES must be between 1 and 10080")
    return (now or datetime.now(UTC)) + timedelta(minutes=ttl_minutes)


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
