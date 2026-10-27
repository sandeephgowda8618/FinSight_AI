"""Reusable, redacted audit persistence for authentication security events."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

_ALLOWED_OUTCOMES = frozenset({"success", "failure", "denied"})
_SECRET_KEY = re.compile(
    r"(password|passwd|token|cookie|authorization|api[_-]?key|secret|credential)",
    re.IGNORECASE,
)


def _redact(value: Any) -> Any:
    """Return JSON-safe audit details without values under secret-like keys."""
    if isinstance(value, dict):
        return {
            str(key): (
                "[REDACTED]" if _SECRET_KEY.search(str(key)) else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def record_auth_event(
    conn: Any,
    *,
    action_key: str,
    outcome: str,
    actor_user_id: UUID | None,
    details: dict[str, Any] | None = None,
    correlation_id: UUID | None = None,
    occurred_at: datetime | None = None,
) -> None:
    """Persist one authentication audit event on the caller's transaction.

    Persistence errors intentionally propagate to the caller. The caller must
    roll back and apply the documented fail-closed policy; events are never
    reported as recorded when this insert fails.
    """
    if outcome not in _ALLOWED_OUTCOMES:
        raise ValueError("Unsupported audit outcome")
    if not action_key or len(action_key) > 120:
        raise ValueError("action_key must contain 1 to 120 characters")

    redacted_details = _redact(details or {})
    payload = json.dumps(redacted_details, separators=(",", ":"), sort_keys=True)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO audit_events (
                workspace_id,
                actor_user_id,
                action_key,
                resource_type,
                resource_id,
                outcome,
                correlation_id,
                details_redacted,
                occurred_at
            )
            VALUES (NULL, %s, %s, 'authentication', NULL, %s, %s, %s::jsonb, %s)
            """,
            (
                actor_user_id,
                action_key,
                outcome,
                correlation_id,
                payload,
                occurred_at or datetime.now(UTC),
            ),
        )
