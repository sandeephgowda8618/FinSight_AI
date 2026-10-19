"""FinSight AI API with PostgreSQL-backed browser sessions."""

from __future__ import annotations

import os
import secrets
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import UUID

import psycopg
from dotenv import load_dotenv
from fastapi import Cookie, Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from psycopg.rows import dict_row

from app.auth import hash_password, new_session_token, session_expiry, token_digest, verify_password
from app.database import connect

load_dotenv(Path(__file__).resolve().parents[3] / ".env")

app = FastAPI(title="FinSight AI API", version="0.2.0")
web_origin = os.environ.get("WEB_ORIGIN", "http://localhost:3000")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[web_origin],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
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


def get_current_user(
    session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None,
) -> dict[str, Any]:
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT u.user_id, u.email, u.display_name
                   FROM auth_sessions s JOIN users u ON u.user_id = s.user_id
                   WHERE s.refresh_token_hash = %s AND s.revoked_at IS NULL
                     AND s.expires_at > %s AND u.account_status = 'active'
                     AND s.last_seen_at > %s - make_interval(mins => %s)
                     AND u.deleted_at IS NULL""",
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


@app.post("/auth/login", response_model=UserView)
def login(payload: LoginRequest, request: Request, response: Response) -> UserView:
    _check_origin(request)
    email = payload.email.strip().lower()
    try:
        with connect() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                """SELECT user_id, email, display_name, password_hash
                   FROM users WHERE lower(email) = %s AND account_status = 'active'
                     AND deleted_at IS NULL""",
                (email,),
            )
            user = cur.fetchone()
            if not user or not user["password_hash"]:
                verify_password(DUMMY_PASSWORD_HASH, payload.password)
                raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
            if not verify_password(user["password_hash"], payload.password):
                raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)
            token, digest = new_session_token()
            expires_at = session_expiry(_ttl_minutes())
            cur.execute(
                """INSERT INTO auth_sessions (user_id, refresh_token_hash, expires_at)
                   VALUES (%s, %s, %s)""",
                (user["user_id"], digest, expires_at),
            )
            cur.execute("UPDATE users SET last_login_at = %s, updated_at = %s WHERE user_id = %s",
                        (datetime.now(UTC), datetime.now(UTC), user["user_id"]))
        response.set_cookie(
            SESSION_COOKIE,
            token,
            httponly=True,
            secure=_secure_cookie(),
            samesite="lax",
            max_age=_ttl_minutes() * 60,
            path="/",
        )
        return UserView(user_id=user["user_id"], email=user["email"], display_name=user["display_name"])
    except psycopg.Error as exc:
        raise HTTPException(status_code=503, detail="Authentication service unavailable") from exc


@app.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response,
           session_token: Annotated[str | None, Cookie(alias=SESSION_COOKIE)] = None) -> Response:
    _check_origin(request)
    if session_token:
        try:
            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """UPDATE auth_sessions SET revoked_at = %s, revoke_reason = 'logout'
                       WHERE refresh_token_hash = %s AND revoked_at IS NULL""",
                    (datetime.now(UTC), token_digest(session_token)),
                )
        except psycopg.Error as exc:
            raise HTTPException(status_code=503, detail="Authentication service unavailable") from exc
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=_secure_cookie(), samesite="lax")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@app.get("/auth/me", response_model=UserView)
def who_am_i(user: CurrentUser) -> UserView:
    return UserView(**user)
