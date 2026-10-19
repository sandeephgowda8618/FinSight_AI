from __future__ import annotations

import sys
import subprocess
from pathlib import Path

import pytest

import app.provision_user as provision_user


def test_provision_user_module_exits_with_usage_error_without_database_access():
    result = subprocess.run(
        [sys.executable, "-m", "app.provision_user"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert "DATABASE_URL" not in result.stderr


def test_provision_user_requires_email_and_display_arguments(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["provision_user"])

    assert provision_user.main() == 2
    assert "Usage:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "email, display_name",
    [
        (" ", "Synthetic Analyst"),
        ("a" * 321, "Synthetic Analyst"),
        ("analyst@example.com", " "),
        ("analyst@example.com", "A" * 161),
    ],
)
def test_provision_user_rejects_invalid_identity_fields(monkeypatch, capsys, email, display_name):
    monkeypatch.setattr(sys, "argv", ["provision_user", email, display_name])
    monkeypatch.setattr(provision_user, "connect", lambda: pytest.fail("database must not be opened"))
    monkeypatch.setattr(provision_user.getpass, "getpass", lambda _prompt: pytest.fail("password must not be requested"))

    assert provision_user.main() == 2
    assert "must fit the identity schema" in capsys.readouterr().err


@pytest.mark.parametrize("passwords", [("", ""), ("synthetic-one", "synthetic-two")])
def test_provision_user_rejects_empty_or_mismatched_passwords(monkeypatch, capsys, passwords):
    monkeypatch.setattr(sys, "argv", ["provision_user", "analyst@example.com", "Synthetic Analyst"])
    values = iter(passwords)
    monkeypatch.setattr(provision_user.getpass, "getpass", lambda _prompt: next(values))
    monkeypatch.setattr(provision_user, "connect", lambda: pytest.fail("invalid password must not change the database"))

    assert provision_user.main() == 2
    output = capsys.readouterr()
    assert "Passwords did not match or were empty." in output.err
    assert all(password not in output.out + output.err for password in passwords if password)


def test_provision_user_hashes_and_upserts_without_printing_password(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["provision_user", " Analyst@Example.com ", " Synthetic Analyst "])
    values = iter(("synthetic-initial-password", "synthetic-initial-password"))
    monkeypatch.setattr(provision_user.getpass, "getpass", lambda _prompt: next(values))

    class Cursor:
        statement = ""
        parameters = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, statement, parameters):
            self.statement = statement
            self.parameters = parameters

    cursor = Cursor()

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def cursor(self):
            return cursor

    monkeypatch.setattr(provision_user, "connect", Connection)

    assert provision_user.main() == 0
    output = capsys.readouterr()
    assert "User provisioned" in output.out
    assert "synthetic-initial-password" not in output.out + output.err
    assert "ON CONFLICT ((lower(email))) DO UPDATE" in cursor.statement
    normalized_email, password_hash, display_name = cursor.parameters
    assert normalized_email == "analyst@example.com"
    assert display_name == "Synthetic Analyst"
    assert password_hash.startswith("$argon2id$")
    assert password_hash != "synthetic-initial-password"
