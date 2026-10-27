from __future__ import annotations

import base64
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from app.auth import hash_password
from app.connection_repository import (
    TradeCapabilityProhibitedError,
    create_user_connection,
    delete_user_connection,
    get_user_connection,
    list_user_connections,
)
from app.database import connect
from app.main import SESSION_COOKIE, app
from app.mfa_repository import activate_totp_factor, create_pending_totp_factor
from app.secret_store import FakeSecretStore
from app.totp import generate_totp_secret, totp_code


@pytest.fixture(autouse=True)
def configure_auth_environment(monkeypatch):
    """Set required test environment variables."""
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "fake")
    monkeypatch.setenv("AUTH_THROTTLE_SECRET", "test-fin16-boundary-throttle-secret-32-bytes")
    monkeypatch.setenv("WEB_ORIGIN", "http://localhost:3000")
    monkeypatch.setenv("SESSION_TTL_MINUTES", "60")
    monkeypatch.setenv("COOKIE_SECURE", "false")


@pytest.fixture
def test_users():
    """Create two distinct synthetic test users (User A and User B)."""
    user_a_email = f"user_a_{uuid4().hex[:8]}@example.com"
    user_b_email = f"user_b_{uuid4().hex[:8]}@example.com"
    password = "Synthetic-Password-FIN16"

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, 'User A', 'active') RETURNING user_id""",
            (user_a_email, hash_password(password)),
        )
        user_a_id = cur.fetchone()[0]

        cur.execute(
            """INSERT INTO users (email, password_hash, display_name, account_status)
               VALUES (%s, %s, 'User B', 'active') RETURNING user_id""",
            (user_b_email, hash_password(password)),
        )
        user_b_id = cur.fetchone()[0]

    yield {
        "user_a": {"id": user_a_id, "email": user_a_email, "password": password},
        "user_b": {"id": user_b_id, "email": user_b_email, "password": password},
    }

    with connect() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM user_connections WHERE user_id IN (%s, %s)", (user_a_id, user_b_id))
        cur.execute("DELETE FROM mfa_factors WHERE user_id IN (%s, %s)", (user_a_id, user_b_id))
        cur.execute("DELETE FROM auth_sessions WHERE user_id IN (%s, %s)", (user_a_id, user_b_id))
        cur.execute(
            """UPDATE users
               SET account_status = 'deleted', deleted_at = now()
               WHERE user_id IN (%s, %s)""",
            (user_a_id, user_b_id),
        )


def test_user_cannot_access_or_mutate_another_users_connection(test_users):
    """TC_AUTHSEC_004: Enforce connection ownership. User B cannot see or delete User A's connection."""
    user_a = test_users["user_a"]
    user_b = test_users["user_b"]

    conn_a = create_user_connection(
        user_id=user_a["id"],
        connection_name="Alpha Market Feed",
        connection_type="market_data",
    )

    # 1. User A can retrieve own connection
    retrieved = get_user_connection(user_id=user_a["id"], connection_id=conn_a["connection_id"])
    assert retrieved is not None
    assert retrieved["connection_name"] == "Alpha Market Feed"

    # 2. User B cannot retrieve User A's connection
    cross_retrieved = get_user_connection(user_id=user_b["id"], connection_id=conn_a["connection_id"])
    assert cross_retrieved is None

    # 3. User B's listing does not include User A's connection
    user_b_list = list_user_connections(user_id=user_b["id"])
    assert all(c["connection_id"] != conn_a["connection_id"] for c in user_b_list)

    # 4. User B cannot delete User A's connection
    deleted = delete_user_connection(user_id=user_b["id"], connection_id=conn_a["connection_id"])
    assert deleted is False

    # 5. Connection remains active for User A
    still_active = get_user_connection(user_id=user_a["id"], connection_id=conn_a["connection_id"])
    assert still_active is not None


def test_trade_capable_connection_rejected_at_repository_and_db_levels(test_users):
    """TC_AUTHSEC_004 / TC_BOUNDARY_001: Release 1 rejects trade-capable connections at app & schema levels."""
    user_a = test_users["user_a"]

    # 1. Repository-level rejection
    with pytest.raises(TradeCapabilityProhibitedError, match="Trade-capable connections are prohibited"):
        create_user_connection(
            user_id=user_a["id"],
            connection_name="Broker Direct Execution",
            is_trade_capable=True,
        )

    # 2. Direct database constraint check (chk_release1_read_only_no_trade)
    with connect() as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.Error) as exc_info:
            cur.execute(
                """
                INSERT INTO user_connections (user_id, connection_name, is_trade_capable)
                VALUES (%s, 'Direct SQL Attempt', TRUE)
                """,
                (user_a["id"],),
            )
        assert "chk_release1_read_only_no_trade" in str(exc_info.value) or "check constraint" in str(exc_info.value).lower()


def test_connection_endpoints_enforce_ownership_via_api(test_users):
    """TC_AUTHSEC_004: HTTP API enforces connection ownership using authenticated session."""
    user_a = test_users["user_a"]
    user_b = test_users["user_b"]

    with TestClient(app) as client:
        # Sign in User A
        res_a = client.post("/auth/login", json={"email": user_a["email"], "password": user_a["password"]})
        assert res_a.status_code == 200
        cookie_a = res_a.cookies.get(SESSION_COOKIE)

        # Sign in User B
        res_b = client.post("/auth/login", json={"email": user_b["email"], "password": user_b["password"]})
        assert res_b.status_code == 200
        cookie_b = res_b.cookies.get(SESSION_COOKIE)

        # User A creates a connection
        create_res = client.post(
            "/api/v1/connections",
            json={"connection_name": "API Feed A", "connection_type": "market_data"},
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000"},
        )
        assert create_res.status_code == 201
        conn_id = create_res.json()["connection_id"]

        # User A can inspect own connection
        get_res_a = client.get(f"/api/v1/connections/{conn_id}", cookies={SESSION_COOKIE: cookie_a})
        assert get_res_a.status_code == 200
        assert get_res_a.json()["connection_name"] == "API Feed A"

        # User B cannot access User A's connection (returns 404, never leaks data)
        get_res_b = client.get(f"/api/v1/connections/{conn_id}", cookies={SESSION_COOKIE: cookie_b})
        assert get_res_b.status_code == 404

        # User B cannot delete User A's connection
        del_res_b = client.delete(
            f"/api/v1/connections/{conn_id}",
            cookies={SESSION_COOKIE: cookie_b},
            headers={"Origin": "http://localhost:3000"},
        )
        assert del_res_b.status_code == 404

        # User A can delete own connection
        del_res_a = client.delete(
            f"/api/v1/connections/{conn_id}",
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000"},
        )
        assert del_res_a.status_code == 204


def test_api_rejects_trade_capable_connection_request(test_users):
    """TC_BOUNDARY_001: API rejects any attempt to register a trade-capable connection in Release 1."""
    user_a = test_users["user_a"]

    with TestClient(app) as client:
        res_a = client.post("/auth/login", json={"email": user_a["email"], "password": user_a["password"]})
        cookie_a = res_a.cookies.get(SESSION_COOKIE)

        res = client.post(
            "/api/v1/connections",
            json={
                "connection_name": "Interactive Brokers Live",
                "connection_type": "market_data",
                "is_trade_capable": True,
            },
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000"},
        )
        assert res.status_code == 403
        assert "Release 1" in res.json()["detail"] or "prohibited" in res.json()["detail"]


def test_sensitive_action_requires_step_up_when_mfa_is_active(test_users):
    """FR-P1-13: Sensitive action requires step-up authentication when MFA is active."""
    user_a = test_users["user_a"]
    store = FakeSecretStore()

    with TestClient(app) as client:
        app.state.mfa_secret_store = store
        res_a = client.post("/auth/login", json={"email": user_a["email"], "password": user_a["password"]})
        assert res_a.status_code == 200
        cookie_a = res_a.cookies.get(SESSION_COOKIE)

        # Set up active TOTP factor for User A
        factor_id, _ = create_pending_totp_factor(
            user_id=user_a["id"],
            account_name=user_a["email"],
            store=store,
            label="Personal Authenticator",
        )
        with connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT secret_ref FROM mfa_factors WHERE mfa_factor_id = %s", (factor_id,))
            secret_ref = cur.fetchone()[0]
        seed = store.get(secret_ref)
        code = totp_code(seed)
        activate_totp_factor(user_id=user_a["id"], factor_id=factor_id, supplied_code=code, store=store)

        # 1. Attempt connection creation without step-up header -> 403 Forbidden
        denied_res = client.post(
            "/api/v1/connections",
            json={"connection_name": "Secured Feed", "connection_type": "market_data"},
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000"},
        )
        assert denied_res.status_code == 403
        assert "Step-up authentication required" in denied_res.json()["detail"]

        # 2. Attempt with invalid step-up code -> 403 Forbidden
        invalid_res = client.post(
            "/api/v1/connections",
            json={"connection_name": "Secured Feed", "connection_type": "market_data"},
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000", "X-Step-Up-Code": "000000"},
        )
        assert invalid_res.status_code == 403
        assert "Invalid step-up" in invalid_res.json()["detail"]

        # 3. Attempt with valid step-up code (next valid time-step to respect replay guard) -> 201 Created
        import time
        valid_step_up_code = totp_code(seed, at_time=time.time() + 30)
        success_res = client.post(
            "/api/v1/connections",
            json={"connection_name": "Secured Feed", "connection_type": "market_data"},
            cookies={SESSION_COOKIE: cookie_a},
            headers={"Origin": "http://localhost:3000", "X-Step-Up-Code": valid_step_up_code},
        )
        assert success_res.status_code == 201
        assert success_res.json()["connection_name"] == "Secured Feed"


def test_release_1_excludes_trading_and_order_execution_endpoints():
    """TC_BOUNDARY_001: The system strictly prohibits live broker order execution routes in Release 1."""
    with TestClient(app) as client:
        # Direct order submission
        res1 = client.post("/api/v1/trading/orders", json={"symbol": "AAPL", "quantity": 10})
        assert res1.status_code == 403
        assert "Release 1 boundary" in res1.json()["detail"]

        res2 = client.post("/api/v1/orders", json={"symbol": "MSFT", "quantity": 5})
        assert res2.status_code == 403
        assert "Release 1 boundary" in res2.json()["detail"]

        res3 = client.post("/orders", json={"symbol": "GOOGL", "quantity": 20})
        assert res3.status_code == 403
        assert "Release 1 boundary" in res3.json()["detail"]


def test_database_excludes_optional_trading_schema():
    """TC_BOUNDARY_001: Optional trading schema tables from schema_optional_trading.sql are absent in Release 1."""
    trading_tables = [
        "trading_orders",
        "order_fills",
        "broker_connections",
        "trading_positions",
        "execution_reports",
        "order_routes",
        "trading_risk_checks",
    ]

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = ANY(%s)
            """,
            (trading_tables,),
        )
        found = cur.fetchall()
        assert len(found) == 0, f"Release 2 optional trading tables found in Release 1 database: {found}"
