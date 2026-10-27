from __future__ import annotations

from datetime import UTC, datetime
import time
from uuid import UUID, uuid4

from fastapi.testclient import TestClient

from app.auth import hash_password
from app.throttle import make_throttle_key
from app.database import connect
from app.main import app


def test_successful_login_is_audited_without_secrets(monkeypatch):
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "integration-test-secret-material-32-bytes")
    email = f"{uuid4().hex}@example.com"
    password = "Synthetic-FIN14-Password-Only"
    correlation = None

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active') RETURNING user_id""",
            (email, hash_password(password), "FIN14 Audit Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/login", json={"email": email, "password": password}
            )
        assert response.status_code == 200

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT action_key, outcome, actor_user_id, details_redacted::text
                   FROM audit_events
                   WHERE action_key = 'auth.login' AND actor_user_id = %s
                   ORDER BY occurred_at DESC LIMIT 1""",
                (user_id,),
            )
            event = cur.fetchone()

        assert event is not None
        assert event[0] == "auth.login"
        assert event[1] == "success"
        assert event[2] == user_id
        assert password not in event[3]
        assert response.cookies.get("finsight_session") not in event[3]
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()), "
                "revoke_reason = COALESCE(revoke_reason, 'test_cleanup') "
                "WHERE user_id = %s",
                (user_id,),
            )
            cur.execute(
                "UPDATE users SET account_status = 'deleted', deleted_at = COALESCE(deleted_at, now()) "
                "WHERE user_id = %s",
                (user_id,),
            )


def test_failed_login_is_audited_and_repeated_failures_are_blocked(monkeypatch):
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "integration-test-secret-material-32-bytes")
    monkeypatch.setenv("AUTH_LOGIN_MAX_FAILURES", "2")
    monkeypatch.setenv("AUTH_LOGIN_WINDOW_SECONDS", "600")
    monkeypatch.setenv("AUTH_LOGIN_BLOCK_SECONDS", "60")

    email = f"{uuid4().hex}@example.com"
    password = "Synthetic-FIN14-Password-Only"
    test_started_at = datetime.now(UTC)
    ip_key = make_throttle_key(
        b"integration-test-secret-material-32-bytes",
        "ip",
        "testclient",
    )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM auth_login_throttle WHERE scope_type = 'ip' AND key_hash = %s",
            (ip_key,),
        )
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active') RETURNING user_id""",
            (email, hash_password(password), "FIN14 Throttle Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with TestClient(app) as client:
            first = client.post(
                "/auth/login", json={"email": email, "password": "wrong-password"}
            )
            second = client.post(
                "/auth/login", json={"email": email, "password": "wrong-password"}
            )
            blocked = client.post(
                "/auth/login", json={"email": email, "password": password}
            )

        assert first.status_code == 401
        assert second.status_code == 401
        assert blocked.status_code == 401
        assert first.json() == second.json() == blocked.json()

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT outcome, actor_user_id, details_redacted::text
                   FROM audit_events
                   WHERE action_key = 'auth.login'
                     AND details_redacted->>'reason' IN (
                         'invalid_credentials', 'throttled'
                     )
                   ORDER BY occurred_at DESC LIMIT 3"""
            )
            events = cur.fetchall()

        assert len(events) == 3
        assert sum(event[0] == "failure" for event in events) == 2
        assert sum(event[0] == "denied" for event in events) == 1
        assert all(
            "wrong-password" not in event[2]
            for event in events
        )
        assert any(event[1] == user_id for event in events)
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM auth_login_throttle WHERE scope_type = 'ip' AND key_hash = %s",
                (ip_key,),
            )
            cur.execute(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()), "
                "revoke_reason = COALESCE(revoke_reason, 'test_cleanup') "
                "WHERE user_id = %s",
                (user_id,),
            )
            cur.execute(
                "UPDATE users SET account_status = 'deleted', deleted_at = COALESCE(deleted_at, now()) "
                "WHERE user_id = %s",
                (user_id,),
            )


def test_logout_is_audited_without_recording_session_token(monkeypatch):
    monkeypatch.setenv(
        "AUTH_THROTTLE_SECRET",
        "integration-test-secret-material-32-bytes",
    )
    email = f"{uuid4().hex}@example.com"
    password = "Synthetic-FIN14-Logout-Password"

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active') RETURNING user_id""",
            (email, hash_password(password), "FIN14 Logout Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with TestClient(app) as client:
            login = client.post(
                "/auth/login",
                json={"email": email, "password": password},
            )
            assert login.status_code == 200
            session_token = login.cookies.get("finsight_session")
            assert session_token

            logout = client.post(
                "/auth/logout",
                cookies={"finsight_session": session_token},
            )
            assert logout.status_code == 204

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT outcome, actor_user_id, details_redacted::text
                   FROM audit_events
                   WHERE action_key = 'auth.logout'
                     AND actor_user_id = %s
                   ORDER BY occurred_at DESC LIMIT 1""",
                (user_id,),
            )
            event = cur.fetchone()

        assert event is not None
        assert event[0] == "success"
        assert event[1] == user_id
        assert session_token not in event[2]
        assert password not in event[2]
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()), "
                "revoke_reason = COALESCE(revoke_reason, 'test_cleanup') "
                "WHERE user_id = %s",
                (user_id,),
            )
            cur.execute(
                "UPDATE users SET account_status = 'deleted', deleted_at = COALESCE(deleted_at, now()) "
                "WHERE user_id = %s",
                (user_id,),
            )


def test_auth_correlation_id_is_returned_and_audited(monkeypatch):
    monkeypatch.setenv(
        "AUTH_THROTTLE_SECRET",
        "integration-test-secret-material-32-bytes",
    )
    email = f"{uuid4().hex}@example.com"
    password = "Synthetic-FIN14-Correlation-Password"
    correlation_id = uuid4()

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active') RETURNING user_id""",
            (email, hash_password(password), "FIN14 Correlation Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with TestClient(app) as client:
            response = client.post(
                "/auth/login",
                json={"email": email, "password": password},
                headers={"X-Correlation-ID": str(correlation_id)},
            )

        assert response.status_code == 200
        assert response.headers.get("X-Correlation-ID") == str(correlation_id)

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT correlation_id
                   FROM audit_events
                   WHERE action_key = 'auth.login'
                     AND actor_user_id = %s
                     AND outcome = 'success'
                   ORDER BY occurred_at DESC LIMIT 1""",
                (user_id,),
            )
            event = cur.fetchone()

        assert event is not None
        assert event[0] == correlation_id
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, now()), "
                "revoke_reason = COALESCE(revoke_reason, 'test_cleanup') "
                "WHERE user_id = %s",
                (user_id,),
            )
            cur.execute(
                "UPDATE users SET account_status = 'deleted', deleted_at = COALESCE(deleted_at, now()) "
                "WHERE user_id = %s",
                (user_id,),
            )


def test_invalid_auth_correlation_id_is_rejected(monkeypatch):
    monkeypatch.setenv(
        "AUTH_THROTTLE_SECRET",
        "integration-test-secret-material-32-bytes",
    )

    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            json={"email": "correlation-test@example.com", "password": "not-used"},
            headers={"X-Correlation-ID": "not-a-uuid"},
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid X-Correlation-ID"}


def test_failed_login_returns_the_audited_correlation_id(monkeypatch):
    monkeypatch.setenv(
        "AUTH_THROTTLE_SECRET",
        "integration-test-secret-material-32-bytes",
    )
    correlation_id = uuid4()

    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            json={
                "email": f"{uuid4().hex}@example.com",
                "password": "Synthetic-Invalid-Password",
            },
            headers={"X-Correlation-ID": str(correlation_id)},
        )

    assert response.status_code == 401
    assert response.headers.get("X-Correlation-ID") == str(correlation_id)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT correlation_id
               FROM audit_events
               WHERE action_key = 'auth.login'
                 AND outcome = 'failure'
                 AND correlation_id = %s
               ORDER BY occurred_at DESC LIMIT 1""",
            (correlation_id,),
        )
        event = cur.fetchone()

    assert event is not None
    assert event[0] == correlation_id


def test_generated_auth_correlation_id_matches_audit_record(monkeypatch):
    monkeypatch.setenv(
        "AUTH_THROTTLE_SECRET",
        "integration-test-secret-material-32-bytes",
    )
    email = f"{uuid4().hex}@example.com"

    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            json={"email": email, "password": "Synthetic-Invalid-Password"},
        )

    assert response.status_code == 401
    correlation_id = response.headers.get("X-Correlation-ID")
    assert correlation_id is not None
    parsed_correlation_id = UUID(correlation_id)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT correlation_id
               FROM audit_events
               WHERE action_key = 'auth.login'
                 AND outcome = 'failure'
                 AND correlation_id = %s""",
            (parsed_correlation_id,),
        )
        event = cur.fetchone()

    assert event is not None
    assert event[0] == parsed_correlation_id


def test_throttle_expires_and_correct_login_succeeds_after_retry(monkeypatch):
    secret = "integration-test-secret-material-32-bytes"
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", secret)
    monkeypatch.setenv("AUTH_LOGIN_MAX_FAILURES", "1")
    monkeypatch.setenv("AUTH_LOGIN_WINDOW_SECONDS", "60")
    monkeypatch.setenv("AUTH_LOGIN_BLOCK_SECONDS", "1")

    email = f"{uuid4().hex}@example.com"
    password = "Synthetic-FIN14-Expiry-Retry-Password"
    failed_correlation = uuid4()
    blocked_correlation = uuid4()
    retry_correlation = uuid4()
    account_key = make_throttle_key(secret.encode("utf-8"), "account", email.lower())
    ip_key = make_throttle_key(secret.encode("utf-8"), "ip", "testclient")

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """DELETE FROM auth_login_throttle
               WHERE key_hash IN (%s, %s)""",
            (account_key, ip_key),
        )
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active') RETURNING user_id""",
            (email, hash_password(password), "FIN14 Throttle Expiry Test"),
        )
        user_id = cur.fetchone()[0]

    try:
        with TestClient(app) as client:
            failed = client.post(
                "/auth/login",
                json={"email": email, "password": "wrong-password"},
                headers={"X-Correlation-ID": str(failed_correlation)},
            )
            assert failed.status_code == 401

            blocked = client.post(
                "/auth/login",
                json={"email": email, "password": password},
                headers={"X-Correlation-ID": str(blocked_correlation)},
            )
            assert blocked.status_code == 401
            assert blocked.json() == failed.json()

            time.sleep(1.15)

            retry = client.post(
                "/auth/login",
                json={"email": email, "password": password},
                headers={"X-Correlation-ID": str(retry_correlation)},
            )
            assert retry.status_code == 200
            assert retry.json()["user_id"] == str(user_id)
            assert retry.headers["X-Correlation-ID"] == str(retry_correlation)

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT correlation_id, outcome
                   FROM audit_events
                   WHERE correlation_id = ANY(%s)
                   ORDER BY occurred_at""",
                ([failed_correlation, blocked_correlation, retry_correlation],),
            )
            outcomes = {row[0]: row[1] for row in cur.fetchall()}

        assert outcomes.get(failed_correlation) == "failure"
        assert outcomes.get(blocked_correlation) == "denied"
        assert outcomes.get(retry_correlation) == "success"
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM auth_login_throttle WHERE key_hash IN (%s, %s)",
                (account_key, ip_key),
            )
            cur.execute(
                """UPDATE auth_sessions
                   SET revoked_at = COALESCE(revoked_at, now()),
                       revoke_reason = COALESCE(revoke_reason, 'test_cleanup')
                   WHERE user_id = %s""",
                (user_id,),
            )
            cur.execute(
                """UPDATE users
                   SET account_status = 'deleted',
                       deleted_at = COALESCE(deleted_at, now())
                   WHERE user_id = %s""",
                (user_id,),
            )
