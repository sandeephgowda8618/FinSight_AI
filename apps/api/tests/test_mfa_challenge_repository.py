from datetime import UTC, datetime, timedelta
import time
from uuid import uuid4

import pytest

from app.auth import hash_password
from app.database import connect
from app.mfa_challenge_repository import (
    MFAChallengeInvalidError,
    issue_mfa_challenge,
    verify_mfa_challenge,
)
from app.mfa_repository import activate_totp_factor, create_pending_totp_factor
from app.secret_store import FakeSecretStore
from app.totp import totp_code


@pytest.fixture
def challenge_identity():
    email = f"mfa-challenge-{uuid4().hex}@example.com"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users
                (email, display_name, password_hash, account_status)
            VALUES (%s, %s, %s, 'active')
            RETURNING user_id
            """,
            (email, "MFA Challenge Test", hash_password("Mfa-Test-Password-2026!")),
        )
        user_id = cur.fetchone()[0]

    store = FakeSecretStore()
    enrollment_time = int(time.time()) - 60
    factor_id, _ = create_pending_totp_factor(
        user_id=user_id,
        account_name=email,
        store=store,
        label="Challenge test factor",
    )
    secret = store.get("fake://mfa/000001")
    enrollment_code = totp_code(secret, at_time=enrollment_time)
    activate_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=enrollment_code,
        store=store,
        at_time=enrollment_time,
    )

    try:
        yield user_id, store, secret
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, now()),
                    revoke_reason = COALESCE(revoke_reason, 'test_cleanup')
                WHERE user_id = %s
                """,
                (user_id,),
            )
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


def test_challenge_token_is_hashed_and_success_consumes_challenge(challenge_identity):
    user_id, store, secret = challenge_identity
    token, expires_at = issue_mfa_challenge(user_id=user_id)

    assert expires_at > datetime.now(UTC)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT challenge_token_hash, consumed_at
            FROM mfa_login_challenges
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        stored_hash, consumed_at = cur.fetchone()

    import hashlib
    assert stored_hash == hashlib.sha256(token.encode()).hexdigest()
    assert stored_hash != token
    assert consumed_at is None

    # Use a later TOTP step than enrollment, avoiding replay of its code.
    verify_time = int(time.time())
    code = totp_code(secret, at_time=verify_time)
    if code == totp_code(secret, at_time=verify_time - 30):
        verify_time += 30
        code = totp_code(secret, at_time=verify_time)

    assert verify_mfa_challenge(
        challenge_token=token,
        supplied_code=code,
        store=store,
        at_time=verify_time,
    ) == user_id

    with pytest.raises(MFAChallengeInvalidError):
        verify_mfa_challenge(
            challenge_token=token,
            supplied_code=code,
            store=store,
            at_time=verify_time + 30,
        )


def test_invalid_code_attempt_is_committed(challenge_identity):
    user_id, store, _ = challenge_identity
    token, _ = issue_mfa_challenge(user_id=user_id)

    with pytest.raises(MFAChallengeInvalidError):
        verify_mfa_challenge(
            challenge_token=token,
            supplied_code="not-a-code",
            store=store,
        )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT attempt_count
            FROM mfa_login_challenges
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        assert cur.fetchone()[0] == 1


def test_replayed_totp_code_increments_attempt_count(challenge_identity):
    user_id, store, secret = challenge_identity
    token, _ = issue_mfa_challenge(user_id=user_id)

    # Enrollment consumed the code from the earlier time step. Reusing it
    # must be rejected by the replay guard.
    replay_time = int(time.time()) - 60
    replay_code = totp_code(secret, at_time=replay_time)

    with pytest.raises(MFAChallengeInvalidError):
        verify_mfa_challenge(
            challenge_token=token,
            supplied_code=replay_code,
            store=store,
            at_time=replay_time,
        )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT attempt_count
            FROM mfa_login_challenges
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        assert cur.fetchone()[0] == 1


def test_expired_challenge_is_rejected(challenge_identity):
    user_id, store, secret = challenge_identity
    token, _ = issue_mfa_challenge(user_id=user_id)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            UPDATE mfa_login_challenges
            SET expires_at = %s
            WHERE user_id = %s
            """,
            (datetime.now(UTC) - timedelta(seconds=1), user_id),
        )

    with pytest.raises(MFAChallengeInvalidError):
        verify_mfa_challenge(
            challenge_token=token,
            supplied_code=totp_code(secret),
            store=store,
        )


def test_challenge_locks_after_five_invalid_attempts(challenge_identity):
    user_id, store, _ = challenge_identity
    token, _ = issue_mfa_challenge(user_id=user_id)

    for _ in range(5):
        with pytest.raises(MFAChallengeInvalidError):
            verify_mfa_challenge(
                challenge_token=token,
                supplied_code="not-a-code",
                store=store,
            )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT attempt_count
            FROM mfa_login_challenges
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id,),
        )
        assert cur.fetchone()[0] == 5

    with pytest.raises(MFAChallengeInvalidError):
        verify_mfa_challenge(
            challenge_token=token,
            supplied_code="not-a-code",
            store=store,
        )
