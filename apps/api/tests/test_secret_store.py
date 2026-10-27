import base64
import os
import stat
from pathlib import Path

import pytest

from app.secret_store import (
    EncryptedFileSecretStore,
    FakeSecretStore,
    SecretNotFoundError,
    SecretStoreConfigurationError,
    SecretStoreError,
    secret_store_from_environment,
)


def test_fake_store_round_trip_and_delete():
    store = FakeSecretStore()
    first = store.put(b"test-secret-one")
    second = store.put(b"test-secret-two")

    assert first == "fake://mfa/000001"
    assert second == "fake://mfa/000002"
    assert store.get(first) == b"test-secret-one"
    assert store.get(second) == b"test-secret-two"

    store.delete(first)
    with pytest.raises(SecretNotFoundError):
        store.get(first)


def test_fake_store_rejects_empty_secret():
    with pytest.raises(ValueError):
        FakeSecretStore().put(b"")


def test_encrypted_file_store_round_trip_and_permissions(tmp_path):
    root = tmp_path / "private-mfa"
    store = EncryptedFileSecretStore(root, b"K" * 32)
    ref = store.put(b"totp-seed-for-test")

    assert store.get(ref) == b"totp-seed-for-test"
    record = root / (ref.rsplit("/", 1)[1] + ".enc")
    assert stat.S_IMODE(record.stat().st_mode) == 0o600
    assert b"totp-seed-for-test" not in record.read_bytes()

    store.delete(ref)
    with pytest.raises(SecretNotFoundError):
        store.get(ref)


def test_encrypted_store_rejects_wrong_key(tmp_path):
    root = tmp_path / "private-mfa"
    writer = EncryptedFileSecretStore(root, b"A" * 32)
    ref = writer.put(b"secret")
    reader = EncryptedFileSecretStore(root, b"B" * 32)

    with pytest.raises(SecretStoreError):
        reader.get(ref)


def test_encrypted_store_rejects_missing_reference(tmp_path):
    store = EncryptedFileSecretStore(tmp_path / "private-mfa", b"K" * 32)
    with pytest.raises(SecretNotFoundError):
        store.get("dev-encrypted://00000000-0000-0000-0000-000000000000")


def test_production_fails_closed(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "dev-encrypted")
    monkeypatch.setenv("MFA_DEV_ENCRYPTION_KEY", base64.b64encode(b"K" * 32).decode())
    monkeypatch.setenv("MFA_SECRET_STORE_PATH", "/tmp/should-not-be-used")

    with pytest.raises(SecretStoreConfigurationError, match="No production"):
        secret_store_from_environment()


def test_test_environment_requires_explicit_fake_backend(monkeypatch):
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.delenv("MFA_SECRET_STORE_BACKEND", raising=False)

    with pytest.raises(SecretStoreConfigurationError):
        secret_store_from_environment()

    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "fake")
    assert isinstance(secret_store_from_environment(), FakeSecretStore)


def test_development_requires_explicit_backend_and_key(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "dev-encrypted")
    monkeypatch.delenv("MFA_DEV_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("MFA_SECRET_STORE_PATH", str(tmp_path / "private-mfa"))

    with pytest.raises(SecretStoreConfigurationError, match="requires an encryption key"):
        secret_store_from_environment()


def test_openbao_store_put_roundtrip_and_delete(monkeypatch):
    """TC_AUTHSEC_003: OpenBao KV v2 secret store adapter handles put, get, and delete."""
    from io import BytesIO
    from urllib.error import HTTPError
    from urllib.request import Request
    from app.secret_store import OpenBaoSecretStore

    store = OpenBaoSecretStore(
        base_url="https://127.0.0.1:8200",
        token="test-vault-token",
        mount="finsight",
    )

    fake_vault: dict[str, bytes] = {}

    def fake_urlopen(req: Request, context=None, timeout=None):
        url = req.full_url
        method = req.get_method()
        token = req.headers.get("X-vault-token") or req.headers.get("X-Vault-Token")
        assert token == "test-vault-token"

        if method == "POST":
            import json
            body = json.loads(req.data.decode("utf-8"))
            seed_b64 = body["data"]["seed"]
            path = url.split("/v1/finsight/data/mfa/")[1]
            fake_vault[path] = base64.b64decode(seed_b64)
            resp_body = json.dumps({"data": {"version": 1}}).encode("utf-8")
            resp = BytesIO(resp_body)
            resp.status = 200
            return resp

        if method == "GET":
            import json
            path = url.split("/v1/finsight/data/mfa/")[1]
            if path not in fake_vault:
                raise HTTPError(url, 404, "Not Found", {}, BytesIO(b'{"errors":[]}'))
            seed_b64 = base64.b64encode(fake_vault[path]).decode("ascii")
            resp_body = json.dumps({"data": {"data": {"seed": seed_b64}}}).encode("utf-8")
            resp = BytesIO(resp_body)
            resp.status = 200
            return resp

        if method == "DELETE":
            path = url.split("/v1/finsight/metadata/mfa/")[1]
            if path not in fake_vault:
                raise HTTPError(url, 404, "Not Found", {}, BytesIO(b'{"errors":[]}'))
            del fake_vault[path]
            resp = BytesIO(b"")
            resp.status = 204
            return resp

        raise AssertionError(f"Unexpected method: {method}")

    monkeypatch.setattr("app.secret_store.urlopen", fake_urlopen)

    # 1. Put
    ref = store.put(b"totp-seed-binary-data")
    assert ref.startswith("openbao://finsight/mfa/")

    # 2. Get
    retrieved = store.get(ref)
    assert retrieved == b"totp-seed-binary-data"

    # 3. Delete
    store.delete(ref)

    # 4. Get after delete raises SecretNotFoundError
    with pytest.raises(SecretNotFoundError):
        store.get(ref)

    # 5. Delete again raises SecretNotFoundError
    with pytest.raises(SecretNotFoundError):
        store.delete(ref)


def test_openbao_store_rejects_empty_secret():
    from app.secret_store import OpenBaoSecretStore
    store = OpenBaoSecretStore("https://127.0.0.1:8200", "token", "finsight")
    with pytest.raises(ValueError, match="Secret must be non-empty bytes"):
        store.put(b"")


def test_openbao_store_rejects_invalid_references():
    from app.secret_store import OpenBaoSecretStore
    store = OpenBaoSecretStore("https://127.0.0.1:8200", "token", "finsight")

    with pytest.raises(SecretNotFoundError):
        store.get("invalid://ref")

    with pytest.raises(SecretNotFoundError):
        store.get("openbao://finsight/mfa/not-a-valid-uuid")


def test_openbao_store_handles_permission_and_network_errors(monkeypatch):
    from io import BytesIO
    from urllib.error import HTTPError, URLError
    from app.secret_store import OpenBaoSecretStore

    store = OpenBaoSecretStore("https://127.0.0.1:8200", "token", "finsight")

    def forbidden_urlopen(req, context=None, timeout=None):
        raise HTTPError(req.full_url, 403, "Permission Denied", {}, BytesIO(b'{"errors":["permission denied"]}'))

    monkeypatch.setattr("app.secret_store.urlopen", forbidden_urlopen)
    with pytest.raises(SecretStoreError, match="permission denied"):
        store.put(b"secret")

    def network_error_urlopen(req, context=None, timeout=None):
        raise URLError("Connection refused")

    monkeypatch.setattr("app.secret_store.urlopen", network_error_urlopen)
    with pytest.raises(SecretStoreError, match="service unavailable"):
        store.get("openbao://finsight/mfa/11111111-1111-1111-1111-111111111111")


def test_openbao_environment_configuration_in_production(monkeypatch):
    from app.secret_store import OpenBaoSecretStore

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "openbao")
    monkeypatch.setenv("OPENBAO_ADDR", "https://127.0.0.1:8200")
    monkeypatch.setenv("OPENBAO_TOKEN", "prod-openbao-token-12345")
    monkeypatch.setenv("OPENBAO_MOUNT", "finsight")

    store = secret_store_from_environment()
    assert isinstance(store, OpenBaoSecretStore)
    assert store._base_url == "https://127.0.0.1:8200"
    assert store._token == "prod-openbao-token-12345"


def test_openbao_environment_configuration_rejects_insecure_production_scheme(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "openbao")
    monkeypatch.setenv("OPENBAO_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("OPENBAO_TOKEN", "prod-token")

    with pytest.raises(SecretStoreConfigurationError, match="HTTPS"):
        secret_store_from_environment()


def test_openbao_environment_configuration_rejects_missing_token(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("MFA_SECRET_STORE_BACKEND", "openbao")
    monkeypatch.setenv("OPENBAO_ADDR", "https://127.0.0.1:8200")
    monkeypatch.delenv("OPENBAO_TOKEN", raising=False)
    monkeypatch.delenv("OPENBAO_TOKEN_PATH", raising=False)

    with pytest.raises(SecretStoreConfigurationError, match="requires OPENBAO_TOKEN"):
        secret_store_from_environment()

