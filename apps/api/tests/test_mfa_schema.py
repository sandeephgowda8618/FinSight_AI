from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

from app.database import connect


def create_test_user() -> str:
    email = f"mfa-schema-{uuid4().hex}@example.test"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (email, password_hash, display_name, account_status)
            VALUES (%s, %s, %s, 'active')
            RETURNING user_id
            """,
            (email, "synthetic-test-hash", "MFA Schema Test"),
        )
        return str(cur.fetchone()[0])


def test_mfa_factor_defaults_to_pending():
    user_id = create_test_user()
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mfa_factors (user_id, factor_type)
                VALUES (%s, 'totp')
                RETURNING factor_status, factor_type
                """,
                (user_id,),
            )
            assert cur.fetchone() == ("pending", "totp")
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


@pytest.mark.parametrize("factor_type", ["totp", "webauthn", "recovery_code"])
def test_mfa_factor_accepts_canonical_factor_types(factor_type):
    user_id = create_test_user()
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mfa_factors (user_id, factor_type)
                VALUES (%s, %s)
                RETURNING factor_type
                """,
                (user_id, factor_type),
            )
            assert cur.fetchone()[0] == factor_type
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


@pytest.mark.parametrize("factor_status", ["pending", "active", "revoked"])
def test_mfa_factor_accepts_canonical_statuses(factor_status):
    user_id = create_test_user()
    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mfa_factors (user_id, factor_type, factor_status)
                VALUES (%s, 'totp', %s)
                RETURNING factor_status
                """,
                (user_id, factor_status),
            )
            assert cur.fetchone()[0] == factor_status
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


@pytest.mark.parametrize(
    ("factor_type", "factor_status"),
    [
        ("sms", "pending"),
        ("totp", "enabled"),
    ],
)
def test_mfa_factor_rejects_noncanonical_values(factor_type, factor_status):
    user_id = create_test_user()
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO mfa_factors (user_id, factor_type, factor_status)
                    VALUES (%s, %s, %s)
                    """,
                    (user_id, factor_type, factor_status),
                )
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


def test_mfa_factor_requires_existing_user():
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO mfa_factors (user_id, factor_type)
                VALUES (%s, 'totp')
                """,
                (str(uuid4()),),
            )


def test_mfa_factor_cascades_when_user_is_hard_deleted_without_audit_history():
    user_id = create_test_user()
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO mfa_factors (user_id, factor_type, secret_ref)
            VALUES (%s, 'totp', 'fake://schema-test/opaque-reference')
            """,
            (user_id,),
        )
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        cur.execute(
            "SELECT count(*) FROM mfa_factors WHERE user_id = %s",
            (user_id,),
        )
        assert cur.fetchone()[0] == 0
