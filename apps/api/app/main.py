"""FinSight AI API with PostgreSQL-backed browser sessions."""

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID, uuid4

from app.audit import record_auth_event
from app.throttle import (
    is_blocked,
    load_throttle_config,
    make_throttle_key,
    record_failure,
    reset_bucket,
)

import psycopg
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from psycopg.rows import dict_row

from app.auth import hash_password, new_session_token, session_expiry, token_digest, verify_password
from app.database import connect
from app.secret_store import (
    SecretStore,
    SecretStoreConfigurationError,
    SecretStoreError,
    secret_store_from_environment,
)
from app.mfa_challenge_repository import (
    MFAChallengeInvalidError,
    issue_mfa_challenge,
    verify_mfa_challenge,
)
from app.mfa_repository import (
    MFAFactorNotFoundError,
    MFAInvalidCodeError,
    activate_totp_factor,
    create_pending_totp_factor,
    list_totp_factors,
    revoke_totp_factor,
    verify_active_totp_factor,
)
from app.connection_repository import (
    TradeCapabilityProhibitedError,
    create_user_connection,
    delete_user_connection,
    get_user_connection,
    list_user_connections,
)

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

app = FastAPI(title="FinSight AI API", version="0.2.0")


def _get_mfa_secret_store(request: Request) -> SecretStore:
    """Return the app-scoped secret store; never silently change backends."""
    store = getattr(request.app.state, "mfa_secret_store", None)
    if store is None:
        store = secret_store_from_environment()
        request.app.state.mfa_secret_store = store
    return store




@app.middleware("http")
async def auth_correlation_middleware(request: Request, call_next):
    """Return a correlation ID on authentication responses, including errors."""
    if (
        request.url.path not in {"/auth/login", "/auth/logout"}
        and not request.url.path.startswith("/auth/sessions")
        and not request.url.path.startswith("/auth/mfa")
    ):
        return await call_next(request)

    supplied = request.headers.get("X-Correlation-ID", "").strip()
    try:
        correlation_id = UUID(supplied) if supplied else uuid4()
    except ValueError:
        from starlette.responses import JSONResponse

        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid X-Correlation-ID"},
        )

    request.state.auth_correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = str(correlation_id)
    return response


web_origin = os.environ.get("WEB_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[web_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-Correlation-ID"],
)

SESSION_COOKIE = "finsight_session"
GENERIC_LOGIN_ERROR = "Email or password is incorrect."
DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=1024)


class UserView(BaseModel):
    user_id: UUID
    email: str
    display_name: str



class MFAVerifyRequest(BaseModel):
    challenge_token: str = Field(min_length=32, max_length=256)
    code: str = Field(min_length=1, max_length=32)


class MFAEnrollRequest(BaseModel):
    label: str | None = Field(default=None, max_length=120)


class MFAActivateRequest(BaseModel):
    factor_id: UUID
    code: str = Field(min_length=1, max_length=32)


def _ttl_minutes() -> int:
    try:
        value = int(os.environ.get("SESSION_TTL_MINUTES", "60"))
        session_expiry(value)
        return value
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Session configuration is invalid") from exc


def _secure_cookie() -> bool:
    configured = os.environ.get("COOKIE_SECURE")
    if configured is not None:
        return configured.lower() in {"1", "true", "yes"}
    return os.environ.get("APP_ENV", "development").lower() == "production"


def _check_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin != web_origin:
        raise HTTPException(status_code=403, detail="Request origin is not allowed")


def _auth_correlation_id(request: Request) -> UUID:
    """Reuse the middleware's correlation ID, or create one if needed."""
    existing = getattr(request.state, "auth_correlation_id", None)
    if existing is not None:
        return existing

    supplied = request.headers.get("X-Correlation-ID", "").strip()
    if supplied:
        try:
            correlation_id = UUID(supplied)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail="Invalid X-Correlation-ID",
            ) from exc
    else:
        correlation_id = uuid4()

    request.state.auth_correlation_id = correlation_id
    return correlation_id


def get_current_user(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict[str, Any]:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT u.user_id, u.email, u.display_name, r.role_key,
                          COALESCE(array_agg(DISTINCT p.permission_key)
                                   FILTER (WHERE p.permission_key IS NOT NULL), ARRAY[]::varchar[]) AS permissions
                   FROM auth_sessions s JOIN users u ON u.user_id = s.user_id
                   LEFT JOIN roles r ON r.role_id = u.platform_role_id AND r.scope = 'platform'
                   LEFT JOIN role_permissions rp ON rp.role_id = r.role_id
                   LEFT JOIN permissions p ON p.permission_id = rp.permission_id
                   WHERE s.refresh_token_hash = %s AND s.revoked_at IS NULL
                     AND s.expires_at > %s AND u.account_status = 'active'
                     AND s.last_seen_at > %s - make_interval(mins => %s)
                     AND u.deleted_at IS NULL
                   GROUP BY u.user_id, u.email, u.display_name, r.role_key""",
                (token_digest(session_token), datetime.now(UTC), datetime.now(UTC), _ttl_minutes()),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=401, detail="Authentication required")
            cur.execute(
                "UPDATE auth_sessions SET last_seen_at = %s WHERE refresh_token_hash = %s",
                (datetime.now(UTC), token_digest(session_token)),
            )
            return user
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from exc


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]


def require_permission(permission_key: str):
    """Build a deny-by-default backend permission dependency."""
    def dependency(user: CurrentUser) -> dict[str, Any]:
        if permission_key not in user.get("permissions", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )
        return user

    return dependency


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response):
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)
    response.headers["X-Correlation-ID"] = str(correlation_id)
    email = payload.email.strip().lower()

    try:
        config = load_throttle_config()
    except ValueError as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    client_ip = request.client.host if request.client else "unknown"
    account_key = make_throttle_key(config.secret, "account", email)
    ip_key = make_throttle_key(config.secret, "ip", client_ip)
    login_succeeded = False
    user = None
    session_token = None
    mfa_required = False
    mfa_challenge_allowed = False

    try:
        with connect() as conn:
            account_blocked = is_blocked(
                conn, scope_type="account", key_hash=account_key
            )
            ip_blocked = is_blocked(
                conn, scope_type="ip", key_hash=ip_key
            )

            if account_blocked or ip_blocked:
                record_auth_event(
                    conn,
                    action_key="auth.login",
                    outcome="denied",
                    actor_user_id=None,
                    details={"reason": "throttled"},
                    correlation_id=correlation_id,
                )
            else:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        """SELECT user_id, email, display_name, password_hash,
                                  mfa_required
                           FROM users
                           WHERE lower(email) = %s
                             AND account_status = 'active'
                             AND deleted_at IS NULL""",
                        (email,),
                    )
                    user = cur.fetchone()

                password_hash = (
                    user["password_hash"]
                    if user and user["password_hash"]
                    else DUMMY_PASSWORD_HASH
                )
                password_valid = verify_password(
                    password_hash, payload.password
                )
                login_succeeded = bool(
                    user and user["password_hash"] and password_valid
                )

                if not login_succeeded:
                    record_failure(
                        conn,
                        scope_type="account",
                        key_hash=account_key,
                        config=config,
                    )
                    record_failure(
                        conn,
                        scope_type="ip",
                        key_hash=ip_key,
                        config=config,
                    )
                    record_auth_event(
                        conn,
                        action_key="auth.login",
                        outcome="failure",
                        actor_user_id=user["user_id"] if user else None,
                        details={"reason": "invalid_credentials"},
                        correlation_id=correlation_id,
                    )
                else:
                    reset_bucket(
                        conn,
                        scope_type="account",
                        key_hash=account_key,
                    )
                    mfa_required = bool(user["mfa_required"])

                    if mfa_required:
                        with conn.cursor() as cur:
                            cur.execute(
                                """SELECT 1
                                   FROM mfa_factors
                                   WHERE user_id = %s
                                     AND factor_type = 'totp'
                                     AND factor_status = 'active'
                                   LIMIT 1""",
                                (user["user_id"],),
                            )
                            has_active_factor = cur.fetchone() is not None

                        if not has_active_factor:
                            record_auth_event(
                                conn,
                                action_key="auth.login",
                                outcome="denied",
                                actor_user_id=user["user_id"],
                                details={"reason": "mfa_factor_unavailable"},
                                correlation_id=correlation_id,
                            )
                        else:
                            mfa_challenge_allowed = True
                    else:
                        session_token, digest = new_session_token()
                        expires_at = session_expiry(_ttl_minutes())

                        with conn.cursor() as cur:
                            cur.execute(
                                """INSERT INTO auth_sessions
                                       (user_id, refresh_token_hash, expires_at)
                                   VALUES (%s, %s, %s)""",
                                (user["user_id"], digest, expires_at),
                            )
                            now = datetime.now(UTC)
                            cur.execute(
                                """UPDATE users
                                   SET last_login_at = %s, updated_at = %s
                                   WHERE user_id = %s""",
                                (now, now, user["user_id"]),
                            )

                        record_auth_event(
                            conn,
                            action_key="auth.login",
                            outcome="success",
                            actor_user_id=user["user_id"],
                            details={"method": "password"},
                            correlation_id=correlation_id,
                        )

    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    if not login_succeeded:
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    if mfa_required and not mfa_challenge_allowed:
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    if mfa_required:
        try:
            _get_mfa_secret_store(request)
            challenge_token, expires_at = issue_mfa_challenge(
                user_id=user["user_id"],
                correlation_id=correlation_id,
            )
        except (SecretStoreError, SecretStoreConfigurationError) as exc:
            raise HTTPException(
                status_code=503,
                detail="MFA service unavailable",
            ) from exc
        except psycopg.Error as exc:
            raise HTTPException(
                status_code=503,
                detail="Authentication service unavailable",
            ) from exc

        return {
            "mfa_required": True,
            "challenge_token": challenge_token,
            "expires_at": expires_at,
        }

    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        max_age=_ttl_minutes() * 60,
        path="/",
    )
    return UserView(
        user_id=user["user_id"],
        email=user["email"],
        display_name=user["display_name"],
    )


@app.post("/auth/mfa/verify", response_model=UserView)
def verify_mfa_login(
    payload: MFAVerifyRequest,
    request: Request,
    response: Response,
) -> UserView:
    """FN-AUTH-006: Verify MFA challenge code and issue active user session."""
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)
    response.headers["X-Correlation-ID"] = str(correlation_id)

    try:
        store = _get_mfa_secret_store(request)
        user_id = verify_mfa_challenge(
            challenge_token=payload.challenge_token,
            supplied_code=payload.code,
            store=store,
            correlation_id=correlation_id,
        )

        token, digest = new_session_token()
        expires_at = session_expiry(_ttl_minutes())
        now = datetime.now(UTC)

        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT user_id, email, display_name
                   FROM users
                   WHERE user_id = %s
                     AND account_status = 'active'
                     AND deleted_at IS NULL
                     AND mfa_required = TRUE""",
                (user_id,),
            )
            user = cur.fetchone()
            if not user:
                raise HTTPException(
                    status_code=401,
                    detail="MFA verification failed",
                )

            cur.execute(
                """INSERT INTO auth_sessions
                       (user_id, refresh_token_hash, expires_at)
                   VALUES (%s, %s, %s)""",
                (user_id, digest, expires_at),
            )
            cur.execute(
                """UPDATE users
                   SET last_login_at = %s, updated_at = %s
                   WHERE user_id = %s""",
                (now, now, user_id),
            )
            record_auth_event(
                conn,
                action_key="auth.login",
                outcome="success",
                actor_user_id=user_id,
                details={"method": "password_and_totp"},
                correlation_id=correlation_id,
                occurred_at=now,
            )

    except MFAChallengeInvalidError as exc:
        raise HTTPException(
            status_code=401,
            detail="MFA verification failed",
        ) from exc
    except (SecretStoreError, SecretStoreConfigurationError) as exc:
        raise HTTPException(
            status_code=503,
            detail="MFA service unavailable",
        ) from exc
    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
        max_age=_ttl_minutes() * 60,
        path="/",
    )
    return UserView(
        user_id=user["user_id"],
        email=user["email"],
        display_name=user["display_name"],
    )



@app.post("/auth/mfa/enroll", status_code=201)
def enroll_mfa_factor(
    payload: MFAEnrollRequest,
    request: Request,
    user: CurrentUser,
) -> dict[str, Any]:
    """FN-AUTH-004: Initiate TOTP MFA factor enrollment for authenticated user."""
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)

    try:
        store = _get_mfa_secret_store(request)
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT email, mfa_required
                   FROM users
                   WHERE user_id = %s
                     AND account_status = 'active'
                     AND deleted_at IS NULL""",
                (user["user_id"],),
            )
            account = cur.fetchone()
            if not account:
                raise HTTPException(status_code=401, detail="Authentication required")

            cur.execute(
                """SELECT 1 FROM mfa_factors
                   WHERE user_id = %s
                     AND factor_type = 'totp'
                     AND factor_status = 'active'
                   LIMIT 1""",
                (user["user_id"],),
            )
            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="An active authenticator already exists",
                )

        factor_id, provisioning_uri = create_pending_totp_factor(
            user_id=user["user_id"],
            account_name=account["email"],
            store=store,
            label=payload.label,
        )
        return {
            "factor_id": str(factor_id),
            "factor_status": "pending",
            "provisioning_uri": provisioning_uri,
            "message": "Scan the URI with your authenticator and activate the factor.",
        }
    except HTTPException:
        raise
    except (SecretStoreError, SecretStoreConfigurationError) as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc


@app.post("/auth/mfa/activate")
def activate_mfa_factor(
    payload: MFAActivateRequest,
    request: Request,
    user: CurrentUser,
) -> dict[str, str]:
    """FN-AUTH-005: Activate a pending TOTP MFA factor using valid verification code."""
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)

    try:
        activate_totp_factor(
            user_id=user["user_id"],
            factor_id=payload.factor_id,
            supplied_code=payload.code,
            store=_get_mfa_secret_store(request),
        )
        return {
            "factor_id": str(payload.factor_id),
            "factor_status": "active",
        }
    except MFAFactorNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Pending MFA factor not found") from exc
    except MFAInvalidCodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid verification code") from exc
    except (SecretStoreError, SecretStoreConfigurationError) as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc


@app.get("/auth/mfa/factors")
def get_mfa_factors(
    request: Request,
    user: CurrentUser,
) -> list[dict[str, Any]]:
    """FN-AUTH-007: List MFA factors for authenticated user."""
    _auth_correlation_id(request)
    try:
        return list_totp_factors(user_id=user["user_id"])
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc


@app.delete("/auth/mfa/factors/{factor_id}", status_code=204)
def delete_mfa_factor(
    factor_id: UUID,
    request: Request,
    user: CurrentUser,
) -> Response:
    """FN-AUTH-008: Revoke an MFA factor and delete its secret reference."""
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)

    try:
        revoked = revoke_totp_factor(
            user_id=user["user_id"],
            factor_id=factor_id,
            store=_get_mfa_secret_store(request),
        )
        if not revoked:
            raise HTTPException(status_code=404, detail="MFA factor not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except HTTPException:
        raise
    except SecretStoreError as exc:
        raise HTTPException(
            status_code=503, detail="MFA service unavailable"
        ) from exc
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="MFA service unavailable") from exc


@app.post("/auth/logout", status_code=204)
def logout(
    request: Request,
    response: Response,
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> Response:
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)
    response.headers['X-Correlation-ID'] = str(correlation_id)

    try:
        with connect() as conn:
            actor_user_id = None

            if session_token:
                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE auth_sessions
                           SET revoked_at = %s, revoke_reason = 'logout'
                           WHERE refresh_token_hash = %s
                             AND revoked_at IS NULL
                           RETURNING user_id""",
                        (datetime.now(UTC), token_digest(session_token)),
                    )
                    row = cur.fetchone()
                    if row:
                        actor_user_id = row[0]

            record_auth_event(
                conn,
                action_key="auth.logout",
                outcome="success" if actor_user_id else "denied",
                actor_user_id=actor_user_id,
                details={"reason": "logout"},
                correlation_id=correlation_id,
            )
    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        httponly=True,
        secure=_secure_cookie(),
        samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


class SessionView(BaseModel):
    session_id: UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    is_current: bool


@app.get("/auth/sessions", response_model=list[SessionView])
def list_active_sessions(
    request: Request,
    user: CurrentUser,
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> list[SessionView]:
    """FN-AUTH-002: List all active sessions for the authenticated user."""
    correlation_id = _auth_correlation_id(request)
    token_hash = token_digest(session_token) if session_token else None
    now = datetime.now(UTC)

    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT session_id, created_at, last_seen_at, expires_at,
                          host(ip_address) AS ip_address, user_agent,
                          (refresh_token_hash = %s) AS is_current
                   FROM auth_sessions
                   WHERE user_id = %s
                     AND revoked_at IS NULL
                     AND expires_at > %s
                     AND last_seen_at > %s - make_interval(mins => %s)
                   ORDER BY created_at DESC""",
                (token_hash, user["user_id"], now, now, _ttl_minutes()),
            )
            rows = cur.fetchall()
    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    return [SessionView(**row) for row in rows]


@app.delete("/auth/sessions/{session_id}", status_code=204)
def terminate_session(
    session_id: UUID,
    request: Request,
    response: Response,
    user: CurrentUser,
) -> Response:
    """FN-AUTH-003: Terminate an active user session and record audit event."""
    _check_origin(request)
    correlation_id = _auth_correlation_id(request)
    response.headers["X-Correlation-ID"] = str(correlation_id)
    now = datetime.now(UTC)
    terminated = False

    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE auth_sessions
                       SET revoked_at = %s, revoke_reason = 'user_terminated'
                       WHERE session_id = %s
                         AND user_id = %s
                         AND revoked_at IS NULL
                         AND expires_at > %s
                       RETURNING session_id""",
                    (now, session_id, user["user_id"], now),
                )
                terminated = cur.fetchone() is not None

            record_auth_event(
                conn,
                action_key="auth.session.terminate",
                outcome="success" if terminated else "denied",
                actor_user_id=user["user_id"],
                details={
                    "session_id": str(session_id),
                    "reason": "user_terminated" if terminated else "not_found_or_inactive",
                },
                correlation_id=correlation_id,
            )
    except psycopg.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Authentication service unavailable",
        ) from exc

    if not terminated:
        raise HTTPException(status_code=404, detail="Active session not found")

    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/auth/me", response_model=UserView)
def who_am_i(user: CurrentUser) -> UserView:
    return UserView(**user)


@app.get("/api/v1/admin/authorization/capabilities")
def platform_admin_capabilities(
    request: Request,
    _authorized: Annotated[dict[str, Any], Depends(require_permission("platform.admin"))],
) -> dict[str, Any]:
    """FN-AUTH-001: Return the authenticated caller's database-backed platform capabilities."""

    supplied_request_id = request.headers.get("request_id", "").strip()
    if supplied_request_id and (
        len(supplied_request_id) > 128
        or any(ord(char) < 32 or ord(char) == 127 for char in supplied_request_id)
    ):
        raise HTTPException(status_code=400, detail="Invalid request_id")

    # Always issue a server-generated canonical request ID.
    request_id = f"req_{secrets.token_urlsafe(12)}"
    correlation_id = supplied_request_id or request_id
    permissions = sorted(set(_authorized.get("permissions", [])))
    capabilities = (
        ["inspect_authorization_policy"]
        if "platform.admin" in permissions
        else []
    )

    return {
        "data": {
            "subject": {
                "user_id": str(_authorized["user_id"]),
                "platform_role_code": _authorized.get("role_key"),
            },
            "effective_permissions": permissions,
            "capabilities": capabilities,
            "policy_version": "sprint-1-platform-rbac-v1",
        },
        "request_id": request_id,
        "correlation_id": correlation_id,
    }


class ConnectionView(BaseModel):
    connection_id: UUID
    connection_name: str
    connection_type: str
    is_trade_capable: bool
    connection_status: str
    created_at: datetime
    updated_at: datetime


class ConnectionCreateRequest(BaseModel):
    connection_name: str = Field(min_length=1, max_length=160)
    connection_type: str = "market_data"
    is_trade_capable: bool = False
    secret_payload: str | None = None


def _verify_step_up_if_required(request: Request, user: CurrentUser, store: SecretStore) -> None:
    """FN-BOUND-001: Enforce step-up authentication for sensitive operations when MFA is active."""
    with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(
            """
            SELECT mfa_factor_id
            FROM mfa_factors
            WHERE user_id = %s
              AND factor_type = 'totp'
              AND factor_status = 'active'
            LIMIT 1
            """,
            (user["user_id"],),
        )
        factor = cur.fetchone()

    if not factor:
        return

    step_up_code = request.headers.get("X-Step-Up-Code", "").strip()
    if not step_up_code:
        raise HTTPException(
            status_code=403,
            detail="Step-up authentication required: valid TOTP code required for sensitive actions.",
        )

    try:
        valid = verify_active_totp_factor(
            user_id=user["user_id"],
            factor_id=factor["mfa_factor_id"],
            supplied_code=step_up_code,
            store=store,
        )
        if not valid:
            raise HTTPException(
                status_code=403,
                detail="Invalid step-up verification code.",
            )
    except (MFAFactorNotFoundError, MFAInvalidCodeError) as exc:
        raise HTTPException(status_code=403, detail="Invalid step-up verification code.") from exc


@app.get("/api/v1/connections", response_model=list[ConnectionView])
def get_connections(
    request: Request,
    user: CurrentUser,
) -> list[ConnectionView]:
    """FN-CONN-002: List data connections owned by authenticated caller."""
    _auth_correlation_id(request)
    try:
        rows = list_user_connections(user_id=user["user_id"])
        return [ConnectionView(**r) for r in rows]
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Connection service unavailable") from exc


@app.post("/api/v1/connections", response_model=ConnectionView, status_code=201)
def create_connection(
    payload: ConnectionCreateRequest,
    request: Request,
    user: CurrentUser,
) -> ConnectionView:
    """FN-CONN-001: Register user-owned connection enforcing Release 1 read-only boundaries."""
    _check_origin(request)
    _auth_correlation_id(request)
    store = _get_mfa_secret_store(request)
    _verify_step_up_if_required(request, user, store)

    if payload.is_trade_capable:
        raise HTTPException(
            status_code=403,
            detail="Trade execution and trade-capable broker connections are prohibited in Release 1.",
        )

    secret_ref = None
    if payload.secret_payload:
        secret_ref = store.put(payload.secret_payload.encode("utf-8"))

    try:
        record = create_user_connection(
            user_id=user["user_id"],
            connection_name=payload.connection_name,
            connection_type=payload.connection_type,
            is_trade_capable=False,
            secret_ref=secret_ref,
        )
        return ConnectionView(**record)
    except TradeCapabilityProhibitedError as exc:
        if secret_ref:
            store.delete(secret_ref)
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        if secret_ref:
            store.delete(secret_ref)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except psycopg.Error as exc:
        if secret_ref:
            store.delete(secret_ref)
        raise HTTPException(status_code=503, detail="Connection service unavailable") from exc


@app.get("/api/v1/connections/{connection_id}", response_model=ConnectionView)
def get_connection(
    connection_id: UUID,
    request: Request,
    user: CurrentUser,
) -> ConnectionView:
    """FN-CONN-003: Inspect single connection verifying strict caller ownership."""
    _auth_correlation_id(request)
    try:
        record = get_user_connection(user_id=user["user_id"], connection_id=connection_id)
        if not record:
            raise HTTPException(status_code=404, detail="Connection not found")
        return ConnectionView(**record)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Connection service unavailable") from exc


@app.delete("/api/v1/connections/{connection_id}", status_code=204)
def delete_connection(
    connection_id: UUID,
    request: Request,
    user: CurrentUser,
) -> Response:
    """FN-CONN-004: Revoke user-owned connection verifying ownership."""
    _check_origin(request)
    _auth_correlation_id(request)
    store = _get_mfa_secret_store(request)
    _verify_step_up_if_required(request, user, store)

    try:
        deleted = delete_user_connection(user_id=user["user_id"], connection_id=connection_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Connection not found")
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Connection service unavailable") from exc


@app.api_route(
    "/api/v1/trading/orders{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
@app.api_route(
    "/api/v1/orders{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
@app.api_route(
    "/orders{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    include_in_schema=False,
)
def reject_release_1_trading_orders(request: Request) -> None:
    """FN-BOUND-002: Hard barrier blocking live broker order execution in Release 1."""
    raise HTTPException(
        status_code=403,
        detail="Release 1 boundary violation: live broker order execution is prohibited in this read-only release.",
    )
