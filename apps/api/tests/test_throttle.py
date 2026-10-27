from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.throttle import (
    ThrottleConfig,
    is_blocked,
    load_throttle_config,
    make_throttle_key,
)


def test_throttle_config_requires_a_strong_secret(monkeypatch):
    monkeypatch.delenv("AUTH_THROTTLE_SECRET", raising=False)

    with pytest.raises(ValueError, match="AUTH_THROTTLE_SECRET"):
        load_throttle_config()

    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "short-secret")
    with pytest.raises(ValueError, match="AUTH_THROTTLE_SECRET"):
        load_throttle_config()


def test_throttle_config_accepts_valid_settings(monkeypatch):
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "x" * 32)
    monkeypatch.setenv("AUTH_LOGIN_MAX_FAILURES", "4")
    monkeypatch.setenv("AUTH_LOGIN_WINDOW_SECONDS", "600")
    monkeypatch.setenv("AUTH_LOGIN_BLOCK_SECONDS", "300")

    config = load_throttle_config()

    assert config.max_failures == 4
    assert config.window_seconds == 600
    assert config.block_seconds == 300


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AUTH_LOGIN_MAX_FAILURES", "0"),
        ("AUTH_LOGIN_MAX_FAILURES", "101"),
        ("AUTH_LOGIN_WINDOW_SECONDS", "0"),
        ("AUTH_LOGIN_WINDOW_SECONDS", "86401"),
        ("AUTH_LOGIN_BLOCK_SECONDS", "0"),
        ("AUTH_LOGIN_BLOCK_SECONDS", "86401"),
        ("AUTH_LOGIN_MAX_FAILURES", "not-a-number"),
    ],
)
def test_throttle_config_rejects_invalid_limits(monkeypatch, name, value):
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "x" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError):
        load_throttle_config()


def test_throttle_keys_are_stable_and_scope_separated():
    secret = b"test-only-secret-material-at-least-32-bytes"
    first = make_throttle_key(secret, "account", "analyst@example.test")

    assert first == make_throttle_key(secret, "account", "analyst@example.test")
    assert first != make_throttle_key(secret, "ip", "analyst@example.test")
    assert first != make_throttle_key(b"different-secret-material-32-bytes", "account", "analyst@example.test")
    assert "analyst@example.test" not in first


def test_throttle_key_rejects_unknown_scope():
    with pytest.raises(ValueError, match="scope"):
        make_throttle_key(b"x" * 32, "email", "analyst@example.test")


class FakeCursor:
    def __init__(self, row):
        self.row = row
        self.calls = []

    def execute(self, query, params):
        self.calls.append((query, params))

    def fetchone(self):
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class FakeConnection:
    def __init__(self, row):
        self.cursor_instance = FakeCursor(row)

    def cursor(self):
        return self.cursor_instance


def test_is_blocked_returns_true_only_for_future_expiry():
    now = datetime(2026, 10, 21, tzinfo=UTC)
    conn = FakeConnection((now + timedelta(minutes=5),))

    assert is_blocked(
        conn, scope_type="account", key_hash="a" * 64, now=now
    )
    query, params = conn.cursor_instance.calls[0]
    assert "auth_login_throttle" in query
    assert params == (now, "account", "a" * 64)


def test_is_blocked_returns_false_for_expired_or_missing_bucket():
    now = datetime(2026, 10, 21, tzinfo=UTC)

    assert not is_blocked(
        FakeConnection((now - timedelta(seconds=1),)),
        scope_type="ip",
        key_hash="b" * 64,
        now=now,
    )
    assert not is_blocked(
        FakeConnection(None),
        scope_type="ip",
        key_hash="b" * 64,
        now=now,
    )


def test_throttle_config_defaults_are_documented_values(monkeypatch):
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "x" * 32)
    for name in (
        "AUTH_LOGIN_MAX_FAILURES",
        "AUTH_LOGIN_WINDOW_SECONDS",
        "AUTH_LOGIN_BLOCK_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)

    config = load_throttle_config()
    assert config == ThrottleConfig(
        secret=b"x" * 32,
        max_failures=5,
        window_seconds=900,
        block_seconds=900,
    )


def test_record_failure_blocks_on_first_failure_when_threshold_is_one():
    from uuid import uuid4

    from app.database import connect
    from app.throttle import record_failure

    secret = b"test-only-secret-material-at-least-32-bytes"
    key = make_throttle_key(secret, "account", uuid4().hex)
    now = datetime.now(UTC)
    config = ThrottleConfig(
        secret=secret,
        max_failures=1,
        window_seconds=60,
        block_seconds=30,
    )

    try:
        with connect() as conn:
            blocked_until = record_failure(
                conn,
                scope_type="account",
                key_hash=key,
                config=config,
                now=now,
            )
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT failed_attempts, blocked_until
                       FROM auth_login_throttle
                       WHERE scope_type = 'account' AND key_hash = %s""",
                    (key,),
                )
                row = cur.fetchone()

        assert blocked_until is not None
        assert blocked_until > now
        assert row[0] == 1
        assert row[1] is not None and row[1] > now
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM auth_login_throttle WHERE scope_type = 'account' AND key_hash = %s",
                (key,),
            )
