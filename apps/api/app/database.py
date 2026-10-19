"""Small synchronous PostgreSQL boundary for the auth endpoints."""

from __future__ import annotations

import os
from pathlib import Path

import psycopg
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[3] / ".env")


def connect() -> psycopg.Connection:
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is required")
    return psycopg.connect(database_url, connect_timeout=3)
