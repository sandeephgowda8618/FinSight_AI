from __future__ import annotations

import secrets
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from app.auth import hash_password, token_digest, verify_password
from app.throttle import make_throttle_key
from app.database import connect
from app.main import SESSION_COOKIE, app

TEST_PASSWORD = secrets.token_urlsafe(32)


@pytest.fixture
def identity():
    email = f"{uuid4().hex}@example.com"
    encoded = hash_password(TEST_PASSWORD)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, password_hash, display_name, account_status) VALUES (%s, %s, %s, 'active') RETURNING user_id",
            (email, encoded, "Synthetic Analyst"),
        )
        user_id = cur.fetchone()[0]
    try:
        yield user_id, email, encoded
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


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_MINUTES", "60")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("WEB_ORIGIN", "http://localhost:3000")
    throttle_secret = "test-only-secret-material-at-least-32-bytes"
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", throttle_secret)
    ip_key = make_throttle_key(
        throttle_secret.encode("utf-8"), "ip", "testclient"
    )

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "DELETE FROM auth_login_throttle WHERE scope_type = 'ip' AND key_hash = %s",
            (ip_key,),
        )

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM auth_login_throttle WHERE scope_type = 'ip' AND key_hash = %s",
                (ip_key,),
            )


def test_password_hash_is_argon2_and_never_plaintext():
    encoded = hash_password(TEST_PASSWORD)
    assert encoded.startswith("$argon2id$")
    assert encoded != TEST_PASSWORD
    assert verify_password(encoded, TEST_PASSWORD)
    assert not verify_password(encoded, "wrong")


def test_login_creates_protected_hashed_expiring_session(client, identity, caplog, capsys):
    user_id, email, encoded = identity
    response = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert response.status_code == 200
    assert response.json() == {"user_id": str(user_id), "email": email, "display_name": "Synthetic Analyst"}
    assert TEST_PASSWORD not in response.text and encoded not in response.text
    cookie = response.cookies.get(SESSION_COOKIE)
    assert cookie
    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie and "samesite=lax" in set_cookie and "path=/" in set_cookie
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("SELECT refresh_token_hash, expires_at, revoked_at FROM auth_sessions WHERE user_id = %s", (user_id,))
        stored = cur.fetchone()
    assert stored["refresh_token_hash"] == token_digest(cookie)
    assert stored["refresh_token_hash"] != cookie
    assert stored["expires_at"] is not None and stored["revoked_at"] is None
    protected = client.get("/auth/me", cookies={SESSION_COOKIE: cookie})
    assert protected.status_code == 200 and protected.json()["user_id"] == str(user_id)
    captured = capsys.readouterr()
    assert TEST_PASSWORD not in caplog.text + captured.out + captured.err
    assert cookie not in caplog.text + captured.out + captured.err


def test_invalid_credentials_have_same_generic_response(client, identity):
    _, email, _ = identity
    known = client.post("/auth/login", json={"email": email, "password": "wrong-password"})
    absent = client.post("/auth/login", json={"email": "absent@example.com", "password": "wrong-password"})
    assert (known.status_code, known.json()) == (absent.status_code, absent.json())
    assert known.status_code == 401 and known.json() == {"detail": "Email or password is incorrect."}
    assert SESSION_COOKIE not in known.cookies and SESSION_COOKIE not in absent.cookies


def test_logout_revokes_session_and_replay_fails(client, identity):
    _, email, _ = identity
    login = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    cookie = login.cookies.get(SESSION_COOKIE)
    assert cookie
    logout = client.post("/auth/logout", cookies={SESSION_COOKIE: cookie})
    assert logout.status_code == 204
    replay = client.get("/auth/me", cookies={SESSION_COOKIE: cookie})
    assert replay.status_code == 401
    with connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT revoked_at FROM auth_sessions WHERE refresh_token_hash = %s", (token_digest(cookie),))
        assert cur.fetchone()[0] is not None


def test_logout_without_session_is_idempotent(client):
    response = client.post("/auth/logout")

    assert response.status_code == 204
    assert response.headers["set-cookie"].startswith(f"{SESSION_COOKIE}=")


def test_expired_session_is_rejected(client, identity):
    user_id, email, _ = identity
    login = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    cookie = login.cookies.get(SESSION_COOKIE)
    assert cookie
    with connect() as conn, conn.cursor() as cur:
        cur.execute("UPDATE auth_sessions SET last_seen_at = now() - interval '61 minutes' WHERE user_id = %s", (user_id,))
    assert client.get("/auth/me", cookies={SESSION_COOKIE: cookie}).status_code == 401


def test_public_registration_is_not_available(client):
    response = client.post("/auth/register", json={"email": "public@example.com", "password": TEST_PASSWORD})
    assert response.status_code == 404


def test_auth_mutation_rejects_foreign_origin(client):
    response = client.post(
        "/auth/logout", headers={"Origin": "https://attacker.invalid"},
    )
    assert response.status_code == 403


def test_secure_cookie_can_be_required_by_deployment(client, identity, monkeypatch):
    _, email, _ = identity
    monkeypatch.setenv("COOKIE_SECURE", "true")
    response = client.post("/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert response.status_code == 200
    assert "secure" in response.headers["set-cookie"].lower()

# FIN-14 active-session management regression tests

def test_list_active_sessions_shows_current_session(client, identity):
    email = identity[1]
    login = client.post(
        "/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    assert login.status_code == 200
    cookie = login.cookies.get(SESSION_COOKIE)
    assert cookie

    response = client.get(
        "/auth/sessions", cookies={SESSION_COOKIE: cookie}
    )
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 1
    assert sessions[0]["is_current"] is True
    assert sessions[0]["session_id"]
    assert sessions[0]["expires_at"]


def test_list_active_sessions_requires_authentication(client):
    response = client.get("/auth/sessions")
    assert response.status_code == 401


def test_terminate_own_session_revokes_it(client, identity):
    email = identity[1]
    login = client.post(
        "/auth/login", json={"email": email, "password": TEST_PASSWORD}
    )
    assert login.status_code == 200
    cookie = login.cookies.get(SESSION_COOKIE)
    assert cookie

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT session_id FROM auth_sessions WHERE refresh_token_hash = %s",
            (token_digest(cookie),),
        )
        row = cur.fetchone()
    assert row is not None
    session_id = row[0]

    response = client.delete(
        f"/auth/sessions/{session_id}",
        cookies={SESSION_COOKIE: cookie},
        headers={"Origin": "http://localhost:3000"},
    )
    assert response.status_code == 204

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT revoked_at, revoke_reason FROM auth_sessions WHERE session_id = %s",
            (session_id,),
        )
        revoked_at, reason = cur.fetchone()
    assert revoked_at is not None
    assert reason == "user_terminated"

    replay = client.get("/auth/me", cookies={SESSION_COOKIE: cookie})
    assert replay.status_code == 401


def test_user_cannot_terminate_another_users_session(client, identity):
    owner_user_id, owner_email, _ = identity
    other_email = f"{uuid4().hex}@example.com"
    other_user_id = None
    other_cookie = None

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users
                   (email, password_hash, display_name, account_status)
               VALUES (%s, %s, %s, 'active')
               RETURNING user_id""",
            (other_email, hash_password(TEST_PASSWORD), "Other Analyst"),
        )
        other_user_id = cur.fetchone()[0]

    try:
        owner_login = client.post(
            "/auth/login",
            json={"email": owner_email, "password": TEST_PASSWORD},
        )
        other_login = client.post(
            "/auth/login",
            json={"email": other_email, "password": TEST_PASSWORD},
        )
        assert owner_login.status_code == 200
        assert other_login.status_code == 200

        owner_cookie = owner_login.cookies.get(SESSION_COOKIE)
        other_cookie = other_login.cookies.get(SESSION_COOKIE)
        assert owner_cookie and other_cookie

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT session_id FROM auth_sessions WHERE refresh_token_hash = %s",
                (token_digest(other_cookie),),
            )
            row = cur.fetchone()
        assert row is not None
        other_session_id = row[0]

        response = client.delete(
            f"/auth/sessions/{other_session_id}",
            cookies={SESSION_COOKIE: owner_cookie},
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 404

        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT revoked_at FROM auth_sessions WHERE session_id = %s",
                (other_session_id,),
            )
            assert cur.fetchone()[0] is None
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """UPDATE auth_sessions
                   SET revoked_at = COALESCE(revoked_at, now()),
                       revoke_reason = COALESCE(revoke_reason, 'test_cleanup')
                   WHERE user_id = %s""",
                (other_user_id,),
            )
            cur.execute(
                """UPDATE users
                   SET account_status = 'deleted',
                       deleted_at = COALESCE(deleted_at, now())
                   WHERE user_id = %s""",
                (other_user_id,),
            )

# FIN-14 MFA endpoint integration tests

@pytest.fixture
def mfa_identity(identity, monkeypatch):
    import time

    from app.mfa_repository import (
        activate_totp_factor,
        create_pending_totp_factor,
    )
    from app.secret_store import FakeSecretStore
    from app.totp import totp_code

    user_id, email, _ = identity
    store = FakeSecretStore()
    monkeypatch.setattr(app.state, "mfa_secret_store", store, raising=False)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET mfa_required = TRUE WHERE user_id = %s",
            (user_id,),
        )

    factor_id, _provisioning_uri = create_pending_totp_factor(
        user_id=user_id,
        account_name=email,
        store=store,
        label="Endpoint integration test",
    )

    # Activate with a prior time step so the login code is not a replay.
    enrollment_time = int(time.time()) - 60
    activate_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=totp_code(
            store.get("fake://mfa/000001"),
            at_time=enrollment_time,
        ),
        store=store,
        at_time=enrollment_time,
    )

    return user_id, email, store.get("fake://mfa/000001")


def test_mfa_login_returns_challenge_without_session_cookie(
    client, mfa_identity
):
    _, email, _ = mfa_identity

    response = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert body["challenge_token"]
    assert body["expires_at"]
    assert SESSION_COOKIE not in response.cookies


def test_mfa_required_login_without_active_factor_is_denied(client, identity):
    user_id, email, _ = identity
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "UPDATE users SET mfa_required = TRUE WHERE user_id = %s",
            (user_id,),
        )

    response = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )

    assert response.status_code == 401
    assert SESSION_COOKIE not in response.cookies


def test_valid_totp_verification_creates_session(client, mfa_identity):
    import time

    from app.totp import totp_code

    user_id, email, secret = mfa_identity
    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert login_response.status_code == 200
    challenge = login_response.json()["challenge_token"]

    verify_response = client.post(
        "/auth/mfa/verify",
        json={
            "challenge_token": challenge,
            "code": totp_code(secret, at_time=int(time.time())),
        },
    )

    assert verify_response.status_code == 200
    cookie = verify_response.cookies.get(SESSION_COOKIE)
    assert cookie
    assert verify_response.json()["user_id"] == str(user_id)
    assert client.get("/auth/me").status_code == 200


def test_invalid_totp_does_not_create_session(client, mfa_identity):
    _, email, _ = mfa_identity
    login_response = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    challenge = login_response.json()["challenge_token"]

    verify_response = client.post(
        "/auth/mfa/verify",
        json={"challenge_token": challenge, "code": "not-a-code"},
    )

    assert verify_response.status_code == 401
    assert SESSION_COOKIE not in verify_response.cookies


def test_mfa_challenge_cannot_be_reused(client, mfa_identity):
    import time

    from app.totp import totp_code

    _, email, secret = mfa_identity
    code = totp_code(secret, at_time=int(time.time()))

    first_login = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    first_challenge = first_login.json()["challenge_token"]

    first_verify = client.post(
        "/auth/mfa/verify",
        json={"challenge_token": first_challenge, "code": code},
    )
    assert first_verify.status_code == 200

    replay = client.post(
        "/auth/mfa/verify",
        json={"challenge_token": first_challenge, "code": code},
    )
    assert replay.status_code == 401
    assert SESSION_COOKIE not in replay.cookies


def test_mfa_enrollment_route_requires_authentication(client):
    response = client.post(
        "/auth/mfa/enroll",
        json={"label": "Test authenticator"},
    )
    assert response.status_code == 401


def test_mfa_enrollment_rejects_foreign_origin(client, identity):
    _, email, _ = identity
    login = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert login.status_code == 200

    response = client.post(
        "/auth/mfa/enroll",
        json={"label": "Test authenticator"},
        headers={"Origin": "https://attacker.invalid"},
    )
    assert response.status_code == 403


def test_mfa_management_routes_enroll_activate_list_and_revoke(
    client, identity, monkeypatch
):
    import time

    from app.secret_store import FakeSecretStore
    from app.totp import totp_code

    _, email, _ = identity
    store = FakeSecretStore()
    monkeypatch.setattr(app.state, "mfa_secret_store", store, raising=False)

    login = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert login.status_code == 200

    # Enroll a pending factor through the HTTP API.
    enrollment = client.post(
        "/auth/mfa/enroll",
        json={"label": "Integration test authenticator"},
    )
    assert enrollment.status_code == 201
    enrolled = enrollment.json()
    assert enrolled["factor_status"] == "pending"
    assert enrolled["factor_id"]
    assert enrolled["provisioning_uri"].startswith("otpauth://totp/")
    assert "secret_ref" not in enrolled

    factor_id = enrolled["factor_id"]
    secret = store.get("fake://mfa/000001")

    # Activate the factor with a valid TOTP code.
    activation = client.post(
        "/auth/mfa/activate",
        json={
            "factor_id": factor_id,
            "code": totp_code(secret, at_time=int(time.time())),
        },
    )
    assert activation.status_code == 200
    assert activation.json() == {
        "factor_id": factor_id,
        "factor_status": "active",
    }

    # Listing returns metadata, never the TOTP secret or its storage reference.
    listing = client.get("/auth/mfa/factors")
    assert listing.status_code == 200
    factors = listing.json()
    assert len(factors) == 1
    assert factors[0]["mfa_factor_id"] == factor_id
    assert factors[0]["factor_status"] == "active"
    assert "secret_ref" not in factors[0]
    assert "secret" not in factors[0]

    # Revocation succeeds and is reflected in subsequent listings.
    revocation = client.delete(f"/auth/mfa/factors/{factor_id}")
    assert revocation.status_code == 204

    after_revoke = client.get("/auth/mfa/factors")
    assert after_revoke.status_code == 200
    assert after_revoke.json()[0]["factor_status"] == "revoked"


def test_mfa_activation_rejects_invalid_code(client, identity, monkeypatch):
    from app.secret_store import FakeSecretStore

    _, email, _ = identity
    monkeypatch.setattr(
        app.state, "mfa_secret_store", FakeSecretStore(), raising=False
    )

    login = client.post(
        "/auth/login",
        json={"email": email, "password": TEST_PASSWORD},
    )
    assert login.status_code == 200

    enrollment = client.post(
        "/auth/mfa/enroll",
        json={"label": "Invalid-code test"},
    )
    assert enrollment.status_code == 201

    activation = client.post(
        "/auth/mfa/activate",
        json={
            "factor_id": enrollment.json()["factor_id"],
            "code": "not-a-code",
        },
    )
    assert activation.status_code == 400

    factors = client.get("/auth/mfa/factors")
    assert factors.status_code == 200
    assert factors.json()[0]["factor_status"] == "pending"


def test_mfa_factor_listing_requires_authentication(client):
    response = client.get("/auth/mfa/factors")
    assert response.status_code == 401

def test_user_cannot_revoke_another_users_mfa_factor(
    client, identity, monkeypatch
):
    from app.secret_store import FakeSecretStore

    owner_user_id, owner_email, _ = identity
    other_email = f"mfa-other-{uuid4().hex}@example.com"
    other_user_id = None

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users
                (email, password_hash, display_name, account_status)
            VALUES (%s, %s, %s, 'active')
            RETURNING user_id
            """,
            (other_email, hash_password(TEST_PASSWORD), "Other MFA User"),
        )
        other_user_id = cur.fetchone()[0]

    store = FakeSecretStore()
    monkeypatch.setattr(app.state, "mfa_secret_store", store, raising=False)

    try:
        owner_login = client.post(
            "/auth/login",
            json={"email": owner_email, "password": TEST_PASSWORD},
        )
        assert owner_login.status_code == 200
        owner_cookie = owner_login.cookies.get(SESSION_COOKIE)
        assert owner_cookie

        enrollment = client.post(
            "/auth/mfa/enroll",
            json={"label": "Owner-only factor"},
            cookies={SESSION_COOKIE: owner_cookie},
        )
        assert enrollment.status_code == 201
        factor_id = enrollment.json()["factor_id"]

        other_login = client.post(
            "/auth/login",
            json={"email": other_email, "password": TEST_PASSWORD},
        )
        assert other_login.status_code == 200
        other_cookie = other_login.cookies.get(SESSION_COOKIE)
        assert other_cookie

        response = client.delete(
            f"/auth/mfa/factors/{factor_id}",
            cookies={SESSION_COOKIE: other_cookie},
            headers={"Origin": "http://localhost:3000"},
        )
        assert response.status_code == 404

        # The owner's factor and secret must remain intact.
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT factor_status, secret_ref
                FROM mfa_factors
                WHERE mfa_factor_id = %s AND user_id = %s
                """,
                (factor_id, owner_user_id),
            )
            factor_status, secret_ref = cur.fetchone()

        assert factor_status == "pending"
        assert secret_ref
        assert store.get(secret_ref)

    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, now()),
                    revoke_reason = COALESCE(revoke_reason, 'test_cleanup')
                WHERE user_id = %s
                """,
                (other_user_id,),
            )
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (other_user_id,),
            )
