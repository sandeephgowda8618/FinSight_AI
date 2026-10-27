from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.audit import record_auth_event


class FakeCursor:
    def __init__(self):
        self.calls = []

    def execute(self, query, params):
        self.calls.append((query, params))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self):
        self.cursor_instance = FakeCursor()

    def cursor(self):
        return self.cursor_instance


def test_auth_audit_uses_canonical_columns_and_parameterized_sql():
    conn = FakeConnection()
    actor_id = uuid4()
    occurred_at = datetime(2026, 10, 21, tzinfo=UTC)

    record_auth_event(
        conn,
        action_key="auth.login",
        outcome="success",
        actor_user_id=actor_id,
        occurred_at=occurred_at,
        details={"method": "password"},
    )

    assert len(conn.cursor_instance.calls) == 1
    query, params = conn.cursor_instance.calls[0]

    assert "INSERT INTO audit_events" in query
    for column in (
        "workspace_id",
        "actor_user_id",
        "action_key",
        "resource_type",
        "resource_id",
        "outcome",
        "correlation_id",
        "details_redacted",
        "occurred_at",
    ):
        assert column in query

    assert actor_id in params
    assert "auth.login" in params
    assert "success" in params
    assert occurred_at in params
    assert "password" not in query.lower()


def test_unknown_account_failure_can_be_audited_without_an_actor():
    conn = FakeConnection()

    record_auth_event(
        conn,
        action_key="auth.login",
        outcome="failure",
        actor_user_id=None,
        details={"reason": "invalid_credentials"},
    )

    _, params = conn.cursor_instance.calls[0]
    assert None in params
    assert "invalid_credentials" in str(params)


@pytest.mark.parametrize(
    "secret",
    [
        "raw-password-value",
        "raw-session-token-value",
        "raw-api-key-value",
        "cookie-secret-value",
    ],
)
def test_auth_audit_redacts_secret_values(secret):
    conn = FakeConnection()

    record_auth_event(
        conn,
        action_key="auth.login",
        outcome="failure",
        actor_user_id=None,
        details={
            "reason": "invalid_credentials",
            "password": secret,
            "session_token": secret,
            "api_key": secret,
            "cookie": secret,
        },
    )

    query, params = conn.cursor_instance.calls[0]
    persisted_values = f"{query} {params}"

    assert secret not in persisted_values
    assert "invalid_credentials" in persisted_values


def test_auth_audit_rejects_unknown_outcome_before_database_write():
    conn = FakeConnection()

    with pytest.raises(ValueError, match="outcome"):
        record_auth_event(
            conn,
            action_key="auth.login",
            outcome="maybe",
            actor_user_id=None,
        )

    assert conn.cursor_instance.calls == []
