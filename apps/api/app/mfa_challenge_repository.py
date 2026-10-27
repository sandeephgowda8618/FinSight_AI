"""Atomic, single-use MFA login challenges with TOTP replay protection."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from psycopg.rows import dict_row

from app.audit import record_auth_event
from app.database import connect
from app.mfa_service import matching_totp_step
from app.secret_store import SecretStore


CHALLENGE_TTL_SECONDS = 300
MAX_CHALLENGE_ATTEMPTS = 5


class MFAChallengeError(RuntimeError):
    """Base class for safe MFA challenge failures."""


class MFAChallengeInvalidError(MFAChallengeError):
    """Challenge is invalid, expired, consumed, or exhausted."""


def _challenge_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue_mfa_challenge(
    *,
    user_id: UUID,
    correlation_id: UUID | None = None,
) -> tuple[str, datetime]:
    """Persist only the challenge-token hash and return the token once."""
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    expires_at = now + timedelta(seconds=CHALLENGE_TTL_SECONDS)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mfa_login_challenges
                (user_id, challenge_token_hash, expires_at)
            VALUES (%s, %s, %s)
            """,
            (user_id, _challenge_digest(token), expires_at),
        )
        record_auth_event(
            conn,
            action_key="auth.mfa_challenge",
            outcome="success",
            actor_user_id=user_id,
            details={"reason": "challenge_issued"},
            correlation_id=correlation_id,
            occurred_at=now,
        )

    return token, expires_at


def verify_mfa_challenge(
    *,
    challenge_token: str,
    supplied_code: str,
    store: SecretStore,
    correlation_id: UUID | None = None,
    at_time: float | None = None,
) -> UUID:
    """Verify a challenge and TOTP step atomically, returning the user ID."""
    now = datetime.now(UTC)
    invalid = False
    verified_user_id: UUID | None = None

    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT challenge_id, user_id, expires_at, attempt_count, consumed_at
            FROM mfa_login_challenges
            WHERE challenge_token_hash = %s
            FOR UPDATE
            """,
            (_challenge_digest(challenge_token),),
        )
        challenge = cur.fetchone()

        if (
            not challenge
            or challenge["consumed_at"] is not None
            or challenge["expires_at"] <= now
            or challenge["attempt_count"] >= MAX_CHALLENGE_ATTEMPTS
        ):
            raise MFAChallengeInvalidError("Invalid MFA challenge")

        cur.execute(
            """
            SELECT mfa_factor_id, secret_ref
            FROM mfa_factors
            WHERE user_id = %s
              AND factor_type = 'totp'
              AND factor_status = 'active'
            ORDER BY created_at DESC
            LIMIT 1
            FOR UPDATE
            """,
            (challenge["user_id"],),
        )
        factor = cur.fetchone()

        if not factor or not factor["secret_ref"]:
            raise MFAChallengeInvalidError("Invalid MFA challenge")

        # Secret-store errors deliberately propagate. No session should be
        # created if the configured store cannot provide the factor secret.
        secret = store.get(factor["secret_ref"])
        step = matching_totp_step(
            secret=secret,
            supplied_code=supplied_code,
            at_time=at_time,
        )

        if step is None:
            invalid = True
            reason = "invalid_code"
        else:
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
                (factor["mfa_factor_id"], step, now),
            )

            if cur.fetchone() is None:
                invalid = True
                reason = "replayed_code"

        if invalid:
            cur.execute(
                """
                UPDATE mfa_login_challenges
                SET attempt_count = LEAST(attempt_count + 1, %s)
                WHERE challenge_id = %s
                """,
                (MAX_CHALLENGE_ATTEMPTS, challenge["challenge_id"]),
            )
            record_auth_event(
                conn,
                action_key="auth.mfa_challenge",
                outcome="failure",
                actor_user_id=challenge["user_id"],
                details={"reason": reason},
                correlation_id=correlation_id,
                occurred_at=now,
            )
        else:
            cur.execute(
                """
                UPDATE mfa_factors
                SET last_used_at = %s
                WHERE mfa_factor_id = %s
                  AND user_id = %s
                  AND factor_status = 'active'
                RETURNING mfa_factor_id
                """,
                (now, factor["mfa_factor_id"], challenge["user_id"]),
            )

            if cur.fetchone() is None:
                raise MFAChallengeInvalidError("Invalid MFA challenge")

            cur.execute(
                """
                UPDATE mfa_login_challenges
                SET consumed_at = %s
                WHERE challenge_id = %s
                  AND consumed_at IS NULL
                RETURNING user_id
                """,
                (now, challenge["challenge_id"]),
            )
            consumed = cur.fetchone()

            if consumed is None:
                raise MFAChallengeInvalidError("Invalid MFA challenge")

            verified_user_id = challenge["user_id"]
            record_auth_event(
                conn,
                action_key="auth.mfa_challenge",
                outcome="success",
                actor_user_id=verified_user_id,
                details={"reason": "challenge_verified"},
                correlation_id=correlation_id,
                occurred_at=now,
            )

    # Raise only after the invalid attempt count and audit event have committed.
    if invalid or verified_user_id is None:
        raise MFAChallengeInvalidError("Invalid MFA challenge")

    return verified_user_id
