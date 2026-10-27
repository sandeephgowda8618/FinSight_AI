"""Database-backed TOTP factor operations.

The database stores only opaque secret references. Callers must not log
provisioning URIs, TOTP seeds, challenge tokens, or submitted codes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from app.database import connect
from app.mfa_service import matching_totp_step
from app.secret_store import SecretNotFoundError, SecretStore


class MFAFactorError(RuntimeError):
    """Base class for safe MFA factor operation failures."""


class MFAFactorNotFoundError(MFAFactorError):
    """The requested factor is unavailable."""


class MFAInvalidCodeError(MFAFactorError):
    """The submitted TOTP code is invalid or already used."""


def create_pending_totp_factor(
    *,
    user_id: UUID,
    account_name: str,
    store: SecretStore,
    label: str | None = None,
) -> tuple[UUID, str]:
    """Create a pending TOTP factor; return its ID and one-time URI."""
    from app.mfa_service import create_totp_provisioning

    secret_ref, provisioning_uri = create_totp_provisioning(
        account_name=account_name,
        store=store,
    )

    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mfa_factors
                    (user_id, factor_type, label, secret_ref, factor_status)
                VALUES (%s, 'totp', %s, %s, 'pending')
                RETURNING mfa_factor_id
                """,
                (user_id, label, secret_ref),
            )
            factor_id = cur.fetchone()[0]
    except Exception:
        try:
            store.delete(secret_ref)
        except Exception:
            pass
        raise

    return factor_id, provisioning_uri


def activate_totp_factor(
    *,
    user_id: UUID,
    factor_id: UUID,
    supplied_code: str,
    store: SecretStore,
    at_time: float | None = None,
) -> None:
    """Activate a pending factor only when its TOTP code is valid."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT mfa_factor_id, secret_ref
            FROM mfa_factors
            WHERE mfa_factor_id = %s
              AND user_id = %s
              AND factor_type = 'totp'
              AND factor_status = 'pending'
            FOR UPDATE
            """,
            (factor_id, user_id),
        )
        factor = cur.fetchone()

        if not factor or not factor["secret_ref"]:
            raise MFAFactorNotFoundError("Pending MFA factor not found")

        secret = store.get(factor["secret_ref"])
        step = matching_totp_step(
            secret=secret,
            supplied_code=supplied_code,
            at_time=at_time,
        )
        if step is None:
            raise MFAInvalidCodeError("Invalid verification code")

        now = datetime.now(UTC)
        cur.execute(
            """
            INSERT INTO mfa_totp_replay_guard
                (mfa_factor_id, last_accepted_step, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (mfa_factor_id) DO UPDATE
            SET last_accepted_step = EXCLUDED.last_accepted_step,
                updated_at = EXCLUDED.updated_at
            WHERE mfa_totp_replay_guard.last_accepted_step
                  < EXCLUDED.last_accepted_step
            RETURNING mfa_factor_id
            """,
            (factor_id, step, now),
        )
        if cur.fetchone() is None:
            raise MFAInvalidCodeError("Invalid verification code")

        cur.execute(
            """
            UPDATE mfa_factors
            SET factor_status = 'active',
                enrolled_at = %s,
                last_used_at = %s
            WHERE mfa_factor_id = %s
              AND user_id = %s
              AND factor_status = 'pending'
            RETURNING mfa_factor_id
            """,
            (now, now, factor_id, user_id),
        )
        if cur.fetchone() is None:
            raise MFAFactorNotFoundError("Pending MFA factor not found")


def verify_active_totp_factor(
    *,
    user_id: UUID,
    factor_id: UUID,
    supplied_code: str,
    store: SecretStore,
    at_time: float | None = None,
) -> bool:
    """Verify an active factor and atomically prevent time-step replay."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT mfa_factor_id, secret_ref
            FROM mfa_factors
            WHERE mfa_factor_id = %s
              AND user_id = %s
              AND factor_type = 'totp'
              AND factor_status = 'active'
            """,
            (factor_id, user_id),
        )
        factor = cur.fetchone()

        if not factor or not factor["secret_ref"]:
            raise MFAFactorNotFoundError("Active MFA factor not found")

        secret = store.get(factor["secret_ref"])
        step = matching_totp_step(
            secret=secret,
            supplied_code=supplied_code,
            at_time=at_time,
        )
        if step is None:
            return False

        now = datetime.now(UTC)
        cur.execute(
            """
            INSERT INTO mfa_totp_replay_guard
                (mfa_factor_id, last_accepted_step, updated_at)
            VALUES (%s, %s, %s)
            ON CONFLICT (mfa_factor_id) DO UPDATE
            SET last_accepted_step = EXCLUDED.last_accepted_step,
                updated_at = EXCLUDED.updated_at
            WHERE mfa_totp_replay_guard.last_accepted_step
                  < EXCLUDED.last_accepted_step
            RETURNING mfa_factor_id
            """,
            (factor_id, step, now),
        )
        if cur.fetchone() is None:
            return False

        cur.execute(
            """
            UPDATE mfa_factors
            SET last_used_at = %s
            WHERE mfa_factor_id = %s
              AND user_id = %s
              AND factor_status = 'active'
            """,
            (now, factor_id, user_id),
        )
        return cur.rowcount == 1


def revoke_totp_factor(
    *, user_id: UUID, factor_id: UUID, store: SecretStore
) -> bool:
    """Revoke an owned factor, then delete its secret with retryable cleanup."""
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT secret_ref, factor_status
            FROM mfa_factors
            WHERE mfa_factor_id = %s
              AND user_id = %s
              AND factor_type = 'totp'
            FOR UPDATE
            """,
            (factor_id, user_id),
        )
        row = cur.fetchone()
        if row is None:
            return False

        secret_ref, factor_status = row
        if factor_status != "revoked":
            cur.execute(
                """
                UPDATE mfa_factors
                SET factor_status = 'revoked'
                WHERE mfa_factor_id = %s AND user_id = %s
                """,
                (factor_id, user_id),
            )

        cur.execute(
            "DELETE FROM mfa_totp_replay_guard WHERE mfa_factor_id = %s",
            (factor_id,),
        )

    # The database transaction has committed; authentication is blocked now.
    if secret_ref:
        try:
            store.delete(secret_ref)
        except SecretNotFoundError:
            # Already absent: cleanup is complete.
            pass

        # Keep the reference if deletion raised another error so cleanup can
        # be retried by repeating the authenticated DELETE request.
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE mfa_factors
                SET secret_ref = NULL
                WHERE mfa_factor_id = %s
                  AND user_id = %s
                  AND factor_type = 'totp'
                  AND factor_status = 'revoked'
                  AND secret_ref = %s
                """,
                (factor_id, user_id, secret_ref),
            )

    return True


def list_totp_factors(*, user_id: UUID) -> list[dict[str, Any]]:
    """List factor metadata only; never return secret references."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT mfa_factor_id, label, factor_status, enrolled_at,
                   last_used_at, created_at
            FROM mfa_factors
            WHERE user_id = %s AND factor_type = 'totp'
            ORDER BY created_at DESC
            """,
            (user_id,),
        )
        return list(cur.fetchall())
