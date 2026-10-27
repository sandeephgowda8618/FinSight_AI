"""PostgreSQL-backed login throttling with secret-keyed identifiers."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class ThrottleConfig:
    secret: bytes
    max_failures: int
    window_seconds: int
    block_seconds: int


def load_throttle_config() -> ThrottleConfig:
    """Load validated throttle settings; never use a weak fallback secret."""
    secret = os.environ.get("AUTH_THROTTLE_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise ValueError("AUTH_THROTTLE_SECRET must contain at least 32 bytes")

    try:
        max_failures = int(os.environ.get("AUTH_LOGIN_MAX_FAILURES", "5"))
        window_seconds = int(os.environ.get("AUTH_LOGIN_WINDOW_SECONDS", "900"))
        block_seconds = int(os.environ.get("AUTH_LOGIN_BLOCK_SECONDS", "900"))
    except ValueError as exc:
        raise ValueError("Login throttle configuration is invalid") from exc

    if not 1 <= max_failures <= 100:
        raise ValueError("AUTH_LOGIN_MAX_FAILURES must be between 1 and 100")
    if not 1 <= window_seconds <= 86400:
        raise ValueError("AUTH_LOGIN_WINDOW_SECONDS must be between 1 and 86400")
    if not 1 <= block_seconds <= 86400:
        raise ValueError("AUTH_LOGIN_BLOCK_SECONDS must be between 1 and 86400")

    return ThrottleConfig(
        secret=secret.encode("utf-8"),
        max_failures=max_failures,
        window_seconds=window_seconds,
        block_seconds=block_seconds,
    )


def make_throttle_key(secret: bytes, scope_type: str, value: str) -> str:
    """Return a stable HMAC-SHA256 identifier without storing the raw value."""
    if scope_type not in {"account", "ip"}:
        raise ValueError("Unsupported throttle scope")
    if not value:
        raise ValueError("Throttle key value cannot be empty")

    message = f"finsight-login:{scope_type}:{value}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def is_blocked(
    conn: Any,
    *,
    scope_type: str,
    key_hash: str,
    now: datetime | None = None,
) -> bool:
    current_time = now or datetime.now(UTC)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT blocked_until > %s
            FROM auth_login_throttle
            WHERE scope_type = %s AND key_hash = %s
            """,
            (current_time, scope_type, key_hash),
        )
        row = cur.fetchone()
    # Accept the timestamp result used by the database query, and Boolean
    # results from adapters that evaluate the comparison in SQL.
    if not row or row[0] is None:
        return False
    value = row[0]
    if isinstance(value, bool):
        return value
    return value > current_time


def record_failure(
    conn: Any,
    *,
    scope_type: str,
    key_hash: str,
    config: ThrottleConfig,
    now: datetime | None = None,
) -> datetime | None:
    """Atomically increment a bucket and return its active block expiry, if any."""
    current_time = now or datetime.now(UTC)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO auth_login_throttle (
                scope_type, key_hash, failed_attempts,
                window_started_at, blocked_until, updated_at
            )
            VALUES (
                %s, %s, 1, %s,
                CASE
                    WHEN %s <= 1
                    THEN %s + make_interval(secs => %s)
                    ELSE NULL
                END,
                %s
            )
            ON CONFLICT (scope_type, key_hash) DO UPDATE SET
                failed_attempts = CASE
                    WHEN auth_login_throttle.window_started_at
                         <= %s - make_interval(secs => %s)
                    THEN 1
                    ELSE auth_login_throttle.failed_attempts + 1
                END,
                window_started_at = CASE
                    WHEN auth_login_throttle.window_started_at
                         <= %s - make_interval(secs => %s)
                    THEN %s
                    ELSE auth_login_throttle.window_started_at
                END,
                blocked_until = CASE
                    WHEN CASE
                        WHEN auth_login_throttle.window_started_at
                             <= %s - make_interval(secs => %s)
                        THEN 1
                        ELSE auth_login_throttle.failed_attempts + 1
                    END >= %s
                    THEN %s + make_interval(secs => %s)
                    WHEN auth_login_throttle.blocked_until > %s
                    THEN auth_login_throttle.blocked_until
                    ELSE NULL
                END,
                updated_at = %s
            RETURNING blocked_until
            """,
            (
                scope_type, key_hash, current_time,
                config.max_failures, current_time, config.block_seconds,
                current_time,
                current_time, config.window_seconds,
                current_time, config.window_seconds, current_time,
                current_time, config.window_seconds, config.max_failures,
                current_time, config.block_seconds, current_time,
                current_time,
            ),
        )
        row = cur.fetchone()

    if row and row[0] and row[0] > current_time:
        return row[0]
    return None


def reset_bucket(conn: Any, *, scope_type: str, key_hash: str) -> None:
    """Clear a successful login's corresponding failure counter."""
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM auth_login_throttle WHERE scope_type = %s AND key_hash = %s",
            (scope_type, key_hash),
        )
