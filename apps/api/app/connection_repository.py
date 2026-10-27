"""Connection repository enforcing strict user ownership and Release 1 read-only boundaries.

TC_AUTHSEC_004 / FR-P1-15: Connection Ownership.
A user cannot use, view, or mutate another user's linked connection credentials.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from app.database import connect


class TradeCapabilityProhibitedError(ValueError):
    """Raised when an operation attempts to create or enable trade capability in Release 1."""


def create_user_connection(
    *,
    user_id: UUID,
    connection_name: str,
    connection_type: str = "market_data",
    is_trade_capable: bool = False,
    secret_ref: str | None = None,
) -> dict[str, Any]:
    """FN-CONN-001: Create and store user-owned data connection metadata with Release 1 read-only constraint."""
    if is_trade_capable:
        raise TradeCapabilityProhibitedError(
            "Trade-capable connections are prohibited in Release 1 (read-only research platform)"
        )

    connection_name = connection_name.strip()
    if not connection_name or len(connection_name) > 160:
        raise ValueError("Connection name must be between 1 and 160 characters")

    valid_types = {"market_data", "structured_data", "financial_feed"}
    if connection_type not in valid_types:
        raise ValueError(f"Invalid connection type; must be one of {valid_types}")

    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            INSERT INTO user_connections (
                user_id, connection_name, connection_type, is_trade_capable,
                connection_status, secret_ref
            )
            VALUES (%s, %s, %s, FALSE, 'active', %s)
            RETURNING connection_id, user_id, connection_name, connection_type,
                      is_trade_capable, connection_status, created_at, updated_at
            """,
            (user_id, connection_name, connection_type, secret_ref),
        )
        row = cur.fetchone()
        assert row is not None
        return dict(row)


def list_user_connections(*, user_id: UUID) -> list[dict[str, Any]]:
    """FN-CONN-002: List connections strictly owned by the authenticated user."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT connection_id, connection_name, connection_type,
                   is_trade_capable, connection_status, created_at, updated_at
            FROM user_connections
            WHERE user_id = %s
              AND connection_status <> 'revoked'
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_user_connection(*, user_id: UUID, connection_id: UUID) -> dict[str, Any] | None:
    """FN-CONN-003: Retrieve single connection verifying strict user ownership."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT connection_id, connection_name, connection_type,
                   is_trade_capable, connection_status, created_at, updated_at
            FROM user_connections
            WHERE connection_id = %s
              AND user_id = %s
              AND connection_status <> 'revoked'
            """,
            (connection_id, user_id),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def delete_user_connection(*, user_id: UUID, connection_id: UUID) -> bool:
    """FN-CONN-004: Revoke/delete connection verifying user ownership."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE user_connections
            SET connection_status = 'revoked', updated_at = now()
            WHERE connection_id = %s
              AND user_id = %s
              AND connection_status <> 'revoked'
            RETURNING connection_id
            """,
            (connection_id, user_id),
        )
        return cur.fetchone() is not None

