from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth import hash_password, new_session_token, session_expiry, token_digest, verify_password
from app.main import _secure_cookie, _ttl_minutes, app


def test_password_helpers_accept_only_the_original_password():
    encoded = hash_password("synthetic-password")

    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "synthetic-password")
    assert not verify_password(encoded, "different-password")
    assert not verify_password("not-an-argon2-hash", "synthetic-password")
    assert not verify_password(None, "synthetic-password")


def test_session_expiry_uses_utc_and_requested_ttl():
    now = datetime(2026, 1, 1, tzinfo=UTC)

    assert session_expiry(15, now) == now + timedelta(minutes=15)


@pytest.mark.parametrize("ttl", [0, -1, 10081])
def test_session_expiry_rejects_out_of_range_ttl(ttl: int):
    with pytest.raises(ValueError, match="SESSION_TTL_MINUTES"):
        session_expiry(ttl)


@pytest.mark.parametrize("configured, expected", [("60", 60), ("1", 1), ("10080", 10080)])
def test_ttl_configuration_accepts_only_supported_values(monkeypatch, configured: str, expected: int):
    monkeypatch.setenv("SESSION_TTL_MINUTES", configured)

    assert _ttl_minutes() == expected


@pytest.mark.parametrize("configured", ["0", "10081", "not-a-number"])
def test_ttl_configuration_fails_closed(monkeypatch, configured: str):
    monkeypatch.setenv("SESSION_TTL_MINUTES", configured)

    with pytest.raises(HTTPException) as error:
        _ttl_minutes()

    assert error.value.status_code == 500
    assert error.value.detail == "Session configuration is invalid"


def test_session_tokens_are_opaque_and_only_digest_is_stable():
    token, digest = new_session_token()
    another_token, another_digest = new_session_token()

    assert token != another_token
    assert digest == token_digest(token)
    assert digest != token
    assert digest != another_digest


def test_login_maps_database_outage_to_controlled_error(monkeypatch):
    import app.main as main

    def unavailable_database():
        import psycopg

        raise psycopg.OperationalError("synthetic database detail")

    monkeypatch.setattr(main, "connect", unavailable_database)
    response = TestClient(app).post(
        "/auth/login",
        json={"email": "synthetic@example.com", "password": "synthetic-password"},
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert "synthetic database detail" not in response.text


def test_protected_route_rejects_missing_session_before_database_access(monkeypatch):
    import app.main as main

    def unexpected_database_access():
        raise AssertionError("database must not be accessed without a session cookie")

    monkeypatch.setattr(main, "connect", unexpected_database_access)
    response = TestClient(app).get("/auth/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}


@pytest.mark.parametrize(
    ("user", "expected_status"),
    [({"permissions": ["platform.admin"]}, 200), ({"permissions": []}, 403), ({}, 403)],
)
def test_permission_dependency_allows_only_explicit_permission(user, expected_status):
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    import app.main as main

    protected_app = FastAPI()
    protected_app.dependency_overrides[main.get_current_user] = lambda: user
    protected_app.add_api_route(
        "/platform-admin",
        lambda _authorized=Depends(main.require_permission("platform.admin")): {"allowed": True},
    )

    response = TestClient(protected_app).get("/platform-admin")
    assert response.status_code == expected_status
    if expected_status == 403:
        assert response.json() == {"detail": "Permission denied"}


def test_permission_dependency_ignores_client_supplied_role_header():
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient

    import app.main as main

    protected_app = FastAPI()
    protected_app.dependency_overrides[main.get_current_user] = lambda: {"permissions": []}
    protected_app.add_api_route(
        "/platform-admin",
        lambda _authorized=Depends(main.require_permission("platform.admin")): {"allowed": True},
    )

    response = TestClient(protected_app).get("/platform-admin", headers={"X-Role": "platform_admin"})
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("get", "/auth/me", {"cookies": {"finsight_session": "synthetic-token"}}),
        ("post", "/auth/logout", {"cookies": {"finsight_session": "synthetic-token"}}),
        ("get",
            "/api/v1/admin/authorization/capabilities",
            {"cookies": {"finsight_session": "synthetic-token"}},
        ),
    ],
)
def test_session_database_outages_return_controlled_error(monkeypatch, method, path, kwargs):
    import app.main as main
    import psycopg

    def unavailable_database():
        raise psycopg.OperationalError("synthetic database detail")

    monkeypatch.setattr(main, "connect", unavailable_database)
    response = getattr(TestClient(app), method)(path, **kwargs)

    assert response.status_code == 503
    assert response.json() == {"detail": "Authentication service unavailable"}
    assert "synthetic database detail" not in response.text


def test_database_configuration_is_required(monkeypatch):
    import app.database as database

    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="DATABASE_URL is required"):
        database.connect()


def test_login_rejects_invalid_input_before_database_access():
    response = TestClient(app).post(
        "/auth/login",
        json={"email": "not-an-email", "password": ""},
    )

    assert response.status_code == 422
    assert "synthetic database detail" not in response.text


@pytest.mark.parametrize("configured", ["1", "true", "yes"])
def test_secure_cookie_accepts_explicit_secure_values(monkeypatch, configured: str):
    monkeypatch.setenv("COOKIE_SECURE", configured)

    assert _secure_cookie()


@pytest.mark.parametrize("configured", ["0", "false", "no", "invalid"])
def test_secure_cookie_treats_other_explicit_values_as_insecure(monkeypatch, configured: str):
    monkeypatch.setenv("COOKIE_SECURE", configured)

    assert not _secure_cookie()


@pytest.mark.parametrize(("app_env", "expected"), [("production", True), ("development", False), ("test", False)])
def test_secure_cookie_defaults_by_environment(monkeypatch, app_env: str, expected: bool):
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    monkeypatch.setenv("APP_ENV", app_env)

    assert _secure_cookie() is expected
