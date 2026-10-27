"""TOTP primitives for MFA. No logging or secret provisioning is performed here."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import time


def generate_totp_secret(length: int = 20) -> bytes:
    """Generate a cryptographically random TOTP secret."""
    if length < 16 or length > 64:
        raise ValueError("TOTP secret length must be between 16 and 64 bytes")
    return secrets.token_bytes(length)


def totp_code(
    secret: bytes,
    at_time: float | None = None,
    *,
    period: int = 30,
    digits: int = 6,
) -> str:
    """Generate a TOTP code for a specific time (injectable for tests)."""
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise ValueError("TOTP secret must contain at least 16 bytes")
    if period <= 0:
        raise ValueError("TOTP period must be positive")
    if digits < 6 or digits > 8:
        raise ValueError("TOTP digits must be between 6 and 8")

    timestamp = time.time() if at_time is None else at_time
    if timestamp < 0:
        raise ValueError("TOTP timestamp cannot be negative")

    counter = int(timestamp) // period
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary_code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary_code % (10 ** digits)).zfill(digits)


def verify_totp(
    secret: bytes,
    supplied_code: str,
    at_time: float | None = None,
    *,
    period: int = 30,
    digits: int = 6,
    window: int = 1,
) -> bool:
    """Verify a numeric TOTP code, allowing a bounded clock-skew window."""
    if not isinstance(supplied_code, str):
        return False
    if len(supplied_code) != digits or not supplied_code.isascii() or not supplied_code.isdigit():
        return False
    if window < 0 or window > 2:
        raise ValueError("TOTP window must be between 0 and 2")

    timestamp = time.time() if at_time is None else at_time
    if timestamp < 0 or period <= 0:
        return False

    current_counter = int(timestamp) // period
    for offset in range(-window, window + 1):
        counter = current_counter + offset
        if counter < 0:
            continue
        candidate = totp_code(secret, counter * period, period=period, digits=digits)
        if hmac.compare_digest(candidate, supplied_code):
            return True
    return False
