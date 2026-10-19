from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

from app.auth import new_session_token, session_expiry
from app.database import connect


def test_identity_schema_rejects_duplicate_email_and_cascades_sessions():
    email = f"constraint-{uuid4().hex}@example.com"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, password_hash, display_name) VALUES (%s, %s, %s) RETURNING user_id",
            (email, "synthetic-hash", "Synthetic Constraint Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with pytest.raises(psycopg.errors.UniqueViolation):
            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (email, password_hash, display_name) VALUES (%s, %s, %s)",
                    (email.upper(), "synthetic-hash", "Duplicate Synthetic Test"),
                )

        _, digest = new_session_token()
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO auth_sessions (user_id, refresh_token_hash, expires_at) VALUES (%s, %s, %s)",
                (user_id, digest, session_expiry(5)),
            )
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            cur.execute("SELECT count(*) FROM auth_sessions WHERE user_id = %s", (user_id,))
            assert cur.fetchone()[0] == 0
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
