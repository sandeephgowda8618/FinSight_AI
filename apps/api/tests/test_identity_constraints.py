from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.auth import new_session_token, session_expiry
from app.database import connect
from app.main import SESSION_COOKIE, app, require_permission


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


def test_platform_permission_is_resolved_from_database_role_and_session():
    admin_email = f"platform-admin-{uuid4().hex}@example.test"
    user_email = f"unprivileged-{uuid4().hex}@example.test"
    tokens = []
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT role_id FROM roles WHERE role_key = 'platform_admin' AND scope = 'platform'")
        admin_role_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO users (email, display_name, platform_role_id) VALUES (%s, %s, %s) RETURNING user_id",
            (admin_email, "Synthetic Platform Admin", admin_role_id),
        )
        admin_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO users (email, display_name) VALUES (%s, %s) RETURNING user_id",
            (user_email, "Synthetic Standard User"),
        )
        user_id = cur.fetchone()[0]
        for owner_id in (admin_id, user_id):
            token, digest = new_session_token()
            tokens.append(token)
            cur.execute(
                "INSERT INTO auth_sessions (user_id, refresh_token_hash, expires_at) VALUES (%s, %s, %s)",
                (owner_id, digest, session_expiry(5)),
            )

    try:
        with TestClient(app) as client:
            anonymous = client.get("/api/v1/admin/authorization/capabilities")
            assert anonymous.status_code == 401
            assert anonymous.json() == {"detail": "Authentication required"}

            invalid_session = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: "invalid-session-token"},
            )
            assert invalid_session.status_code == 401

            allowed = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: tokens[0]},
            )
            #₹ The request_id header is optional, but if supplied it must be validated and preserved as the correlation_id.
            correlated = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: tokens[0]},
                headers={"request_id": "client-correlation-123"},
            )
            assert correlated.status_code == 200
            correlated_body = correlated.json()
            assert correlated_body["request_id"].startswith("req_")
            assert correlated_body["request_id"] != "client-correlation-123"
            assert correlated_body["correlation_id"] == "client-correlation-123"

            malformed = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: tokens[0]},
                headers={"request_id": "x" * 129},
            )
            assert malformed.status_code == 400

            # The platform-admin user should be allowed to inspect the authorization policy.
            assert allowed.status_code == 200
            body = allowed.json()
            assert body["data"]["subject"]["user_id"] == str(admin_id)
            assert body["data"]["subject"]["platform_role_code"] == "platform_admin"
            assert body["data"]["effective_permissions"] == ["platform.admin"]
            assert body["data"]["capabilities"] == ["inspect_authorization_policy"]
            assert body["data"]["policy_version"] == "sprint-1-platform-rbac-v1"
            assert body["request_id"].startswith("req_")
            assert body["correlation_id"] == body["request_id"]

            denied = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: tokens[1]},
                headers={"X-Role": "platform_admin"},
            )
            assert denied.status_code == 403
            assert denied.json() == {"detail": "Permission denied"}
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id IN (%s, %s)", (admin_id, user_id))



def test_permission_grant_revocation_takes_effect_on_next_request():
    suffix = uuid4().hex
    role_key = f"test-admin-{suffix}"
    email = f"permission-revocation-{suffix}@example.test"
    user_id = None
    role_id = None
    permission_id = None

    try:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO roles (role_key, display_name, scope, description)
                VALUES (%s, %s, 'platform', %s)
                RETURNING role_id
                """,
                (role_key, "Synthetic Permission Revocation Role", "Test-only role"),
            )
            role_id = cur.fetchone()[0]

            cur.execute(
                "SELECT permission_id FROM permissions WHERE permission_key = %s",
                ("platform.admin",),
            )
            row = cur.fetchone()
            assert row is not None, "platform.admin permission must exist"
            permission_id = row[0]

            cur.execute(
                "INSERT INTO role_permissions (role_id, permission_id) VALUES (%s, %s)",
                (role_id, permission_id),
            )
            cur.execute(
                """
                INSERT INTO users (email, display_name, platform_role_id)
                VALUES (%s, %s, %s)
                RETURNING user_id
                """,
                (email, "Synthetic Permission Revocation User", role_id),
            )
            user_id = cur.fetchone()[0]

            token, digest = new_session_token()
            cur.execute(
                """
                INSERT INTO auth_sessions (user_id, refresh_token_hash, expires_at)
                VALUES (%s, %s, %s)
                """,
                (user_id, digest, session_expiry(5)),
            )

        with TestClient(app) as client:
            first_response = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: token},
            )
            assert first_response.status_code == 200
            assert first_response.json()["data"]["effective_permissions"] == [
                "platform.admin"
            ]

            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM role_permissions WHERE role_id = %s AND permission_id = %s",
                    (role_id, permission_id),
                )

            next_response = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: token},
            )
            assert next_response.status_code == 403
            assert next_response.json() == {"detail": "Permission denied"}

    finally:
        with connect() as conn, conn.cursor() as cur:
            if user_id is not None:
                cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            if role_id is not None:
                cur.execute("DELETE FROM roles WHERE role_id = %s", (role_id,))

def test_platform_role_assignment_rejects_workspace_scoped_roles():
    email = f"wrong-scope-{uuid4().hex}@example.test"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO roles (role_key, display_name, scope) VALUES (%s, %s, 'workspace') RETURNING role_id",
            (f"ws-{uuid4().hex[:12]}", "Synthetic Workspace Role"),
        )
        workspace_role_id = cur.fetchone()[0]
        cur.execute(
            "INSERT INTO users (email, display_name) VALUES (%s, 'Synthetic Scope User') RETURNING user_id",
            (email,),
        )
        user_id = cur.fetchone()[0]
    try:
        with pytest.raises(psycopg.errors.CheckViolation):
            with connect() as conn, conn.cursor() as cur:
                cur.execute("UPDATE users SET platform_role_id = %s WHERE user_id = %s", (workspace_role_id, user_id))
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
            cur.execute("DELETE FROM roles WHERE role_id = %s", (workspace_role_id,))




def test_platform_role_revocation_takes_effect_on_next_request():
    email = f"revoked-platform-admin-{uuid4().hex}@example.test"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT role_id FROM roles WHERE role_key = 'platform_admin' AND scope = 'platform'"
        )
        row = cur.fetchone()
        assert row is not None, "Platform-admin role must exist"
        admin_role_id = row[0]
        cur.execute(
            "INSERT INTO users (email, display_name, platform_role_id) "
            "VALUES (%s, %s, %s) RETURNING user_id",
            (email, "Synthetic Revocation Test", admin_role_id),
        )
        user_id = cur.fetchone()[0]
        token, digest = new_session_token()
        cur.execute(
            "INSERT INTO auth_sessions (user_id, refresh_token_hash, expires_at) "
            "VALUES (%s, %s, %s)",
            (user_id, digest, session_expiry(5)),
        )

    try:
        with TestClient(app) as client:
            first_response = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: token},
            )
            assert first_response.status_code == 200
            assert first_response.json()["data"]["effective_permissions"] == [
                "platform.admin"
            ]

            # Revoke this test user's role without changing shared role permissions.
            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET platform_role_id = NULL WHERE user_id = %s",
                    (user_id,),
                )

            next_response = client.get(
                "/api/v1/admin/authorization/capabilities",
                cookies={SESSION_COOKIE: token},
            )
            assert next_response.status_code == 403
            assert next_response.json() == {"detail": "Permission denied"}
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))


# def test_capabilities_request_id_is_canonical_and_correlation_is_preserved():
#     with connect() as conn, conn.cursor() as cur:
#         cur.execute(
#         """
#         SELECT u.user_id, s.refresh_token_hash
#         FROM users u
#         JOIN roles r ON r.role_id = u.platform_role_id
#         JOIN role_permissions rp ON rp.role_id = r.role_id
#         JOIN permissions p ON p.permission_id = rp.permission_id
#         JOIN auth_sessions s ON s.user_id = u.user_id
#         WHERE r.role_key = 'platform_admin'
#         AND p.permission_key = 'platform.admin'
#         AND s.revoked_at IS NULL
#         AND s.expires_at > now()
#         LIMIT 1
#         """
#         )
#     row = cur.fetchone()

#     if row is None:
#         pytest.skip("No active platform-admin test session is available")

#     # The database stores only the token digest, so use a dedicated test
#     # session instead of attempting to recover an existing session token.
#     pytest.skip("Use the dedicated-session integration fixture for this assertion")

# def test_capabilities_rejects_malformed_request_id():
#     # Authentication runs before the endpoint validates its header.
#     # An unauthenticated request must not be mistaken for a header-validation test.
#     response = TestClient(app).get(
#     "/api/v1/admin/authorization/capabilities",
#     headers={"request_id": "x" * 129},
#     )
#     assert response.status_code == 401