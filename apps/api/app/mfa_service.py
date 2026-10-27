"""Provider-neutral TOTP enrollment and verification services.

Provisioning material is returned only to the caller performing enrollment.
Callers must never log the returned URI or the underlying TOTP secret.
"""

from __future__ import annotations

import base64
import hmac
from urllib.parse import quote, urlencode

from app.secret_store import SecretStore
from app.totp import generate_totp_secret, totp_code, verify_totp


DEFAULT_ISSUER = "FinSight AI"


def create_totp_provisioning(
    *,
    account_name: str,
    issuer: str = DEFAULT_ISSUER,
    store: SecretStore,
) -> tuple[str, str]:
    """Store a new TOTP seed and return (opaque reference, provisioning URI).

    The caller must persist only the reference. The URI contains the seed and
    must be shown only in the authenticated, one-time enrollment response.
    """
    account_name = account_name.strip()
    issuer = issuer.strip()

    if not account_name or not issuer:
        raise ValueError("Account name and issuer are required")

    secret = generate_totp_secret()
    reference = store.put(secret)

    try:
        encoded_secret = base64.b32encode(secret).decode("ascii").rstrip("=")
        label = f"{issuer}:{account_name}"
        query = urlencode(
            {
                "secret": encoded_secret,
                "issuer": issuer,
                "algorithm": "SHA1",
                "digits": 6,
                "period": 30,
            }
        )
        uri = f"otpauth://totp/{quote(label, safe='')}?{query}"
        return reference, uri
    except Exception:
        store.delete(reference)
        raise


def verify_totp_code(
    *,
    store: SecretStore,
    secret_ref: str,
    supplied_code: str,
    at_time: float | None = None,
) -> bool:
    """Verify a TOTP code without returning or exposing the underlying seed."""
    secret = store.get(secret_ref)
    return verify_totp(secret, supplied_code, at_time=at_time)


def current_totp_step(at_time: float | None = None, *, period: int = 30) -> int:
    """Return the current TOTP time-step index."""
    if period <= 0:
        raise ValueError("TOTP period must be positive")

    import time

    timestamp = time.time() if at_time is None else at_time
    if timestamp < 0:
        raise ValueError("TOTP timestamp cannot be negative")

    return int(timestamp) // period


def matching_totp_step(
    *,
    secret: bytes,
    supplied_code: str,
    at_time: float | None = None,
    period: int = 30,
    digits: int = 6,
    window: int = 1,
) -> int | None:
    """Return the matching counter for replay protection, or None."""
    if not isinstance(supplied_code, str):
        return None
    if len(supplied_code) != digits or not supplied_code.isascii() or not supplied_code.isdigit():
        return None
    if period <= 0 or window < 0 or window > 2:
        raise ValueError("Invalid TOTP verification configuration")

    import time

    timestamp = time.time() if at_time is None else at_time
    if timestamp < 0:
        return None

    counter = int(timestamp) // period
    for offset in range(-window, window + 1):
        step = counter + offset
        if step < 0:
            continue
        candidate = totp_code(secret, step * period, period=period, digits=digits)
        if hmac.compare_digest(candidate, supplied_code):
            return step

    return None
