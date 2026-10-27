from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

from app.auth import hash_password
from app.database import connect


def test_audit_events_are_immutable_and_user_history_is_preserved():
    email = f"audit-immutable-{uuid4().hex}@example.test"
    password = "Synthetic-Audit-Immutability-Test-Password"
    action_key = "test.audit_immutability"
    resource_id = str(uuid4())

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (email, password_hash, display_name, account_status)
            VALUES (%s, %s, %s, 'active')
            RETURNING user_id
            """,
            (email, hash_password(password), "Audit Immutability Test"),
        )
        user_id = cur.fetchone()[0]

        cur.execute(
            """
            INSERT INTO audit_events
                (actor_user_id, action_key, resource_type, resource_id,
                 outcome, details_redacted)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            RETURNING audit_event_id
            """,
            (
                user_id,
                action_key,
                "test",
                resource_id,
                "success",
                '{"test_record": true}',
            ),
        )
        audit_event_id = cur.fetchone()[0]

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        with connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

    with pytest.raises(psycopg.Error) as update_error:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE audit_events SET outcome = 'denied' WHERE audit_event_id = %s",
                (audit_event_id,),
            )
    assert update_error.value.sqlstate == "55000"

    with pytest.raises(psycopg.Error) as delete_error:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM audit_events WHERE audit_event_id = %s",
                (audit_event_id,),
            )
    assert delete_error.value.sqlstate == "55000"

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
        cur.execute(
            """
            SELECT actor_user_id, action_key, outcome
            FROM audit_events
            WHERE audit_event_id = %s
            """,
            (audit_event_id,),
        )
        event = cur.fetchone()

    assert event == (user_id, action_key, "success")
