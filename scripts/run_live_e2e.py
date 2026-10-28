"""Run the browser authentication smoke against disposable PostgreSQL and local services."""

from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for(url: str, process: subprocess.Popen[bytes], label: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited before becoming ready (exit {process.returncode})")
        try:
            with urllib.request.urlopen(url, timeout=2):
                return
        except (OSError, urllib.error.URLError):
            time.sleep(0.25)
    raise TimeoutError(f"{label} did not become ready at {url}")


def stop(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    if not os.environ.get("DATABASE_URL"):
        raise SystemExit("DATABASE_URL must point to a disposable PostgreSQL test database")

    sys.path.insert(0, str(ROOT / "apps/api"))
    from app.auth import hash_password
    from app.database import connect

    user_id = None
    email = f"e2e-{uuid4().hex}@example.com"
    password = secrets.token_urlsafe(24)
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO users (email, password_hash, display_name, account_status) "
            "VALUES (%s, %s, %s, 'active') RETURNING user_id",
            (email, hash_password(password), "Synthetic E2E Analyst"),
        )
        user_id = cur.fetchone()[0]

    api_port = free_port()
    web_port = free_port()
    environment = os.environ.copy()
    environment.update({
        "APP_ENV": "test",
        "COOKIE_SECURE": "false",
        "WEB_ORIGIN": f"http://127.0.0.1:{web_port}",
        "E2E_EMAIL": email,
        "E2E_PASSWORD": password,
        "E2E_BASE_URL": f"http://127.0.0.1:{web_port}",
        "NEXT_TELEMETRY_DISABLED": "1",
        "AUTH_THROTTLE_SECRET": os.environ.get(
            "AUTH_THROTTLE_SECRET",
            "ci-synthetic-e2e-throttle-secret-of-32-bytes!",
        ),
        "MFA_SECRET_STORE_BACKEND": "fake",
    })
    api: subprocess.Popen[bytes] | None = None
    web: subprocess.Popen[bytes] | None = None
    try:
        api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", str(ROOT / "apps/api"),
             "--host", "127.0.0.1", "--port", str(api_port)],
            cwd=ROOT,
            env={**environment, "WEB_ORIGIN": f"http://127.0.0.1:{web_port}"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for(f"http://127.0.0.1:{api_port}/openapi.json", api, "FastAPI")

        frontend_dir = os.environ.get("FRONTEND_DIR")
        if frontend_dir:
            frontend_path = Path(frontend_dir).resolve()
            static_assets = frontend_path.parent / "static"
            static_target = frontend_path / ".next/static"
            if static_assets.is_dir() and not static_target.is_dir():
                static_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copytree(static_assets, static_target)
            command = ["node", "server.js"]
            cwd = frontend_path
        else:
            command = ["npm", "run", "dev", "--", "--hostname", "127.0.0.1", "--port", str(web_port)]
            cwd = ROOT / "apps/web"
        web = subprocess.Popen(
            command,
            cwd=cwd,
            env={**environment, "PORT": str(web_port), "HOSTNAME": "127.0.0.1",
                 "API_BASE_URL": f"http://127.0.0.1:{api_port}"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        wait_for(f"http://127.0.0.1:{web_port}/", web, "Next.js")

        return subprocess.run(
            ["npm", "run", "test:e2e"],
            cwd=ROOT / "apps/web",
            env=environment,
            timeout=180,
            check=False,
        ).returncode
    finally:
        stop(web)
        stop(api)
        if user_id is not None:
            with connect() as conn, conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET account_status = 'deleted', deleted_at = now() WHERE user_id = %s",
                    (user_id,),
                )


if __name__ == "__main__":
    raise SystemExit(main())
