from __future__ import annotations

import secrets
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from psycopg.rows import dict_row

from app.auth import hash_password, token_digest, verify_password
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
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("SESSION_TTL_MINUTES", "60")
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("WEB_ORIGIN", "http://localhost:3000")
    with TestClient(app) as test_client:
        yield test_client


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
