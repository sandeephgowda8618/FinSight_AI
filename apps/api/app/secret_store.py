"""Provider-neutral storage for MFA secrets.

The development adapter is for local development only. Production provider
integration must be selected and implemented separately.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import stat
from pathlib import Path
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SecretStoreError(RuntimeError):
    """Base error for secret-store operations."""


class SecretNotFoundError(SecretStoreError):
    """The requested secret reference does not exist."""


class SecretStoreConfigurationError(SecretStoreError):
    """The configured secret store is missing or unsafe."""


class SecretStore(Protocol):
    """Interface consumed by MFA application services."""

    def put(self, secret: bytes) -> str: ...
    def get(self, ref: str) -> bytes: ...
    def delete(self, ref: str) -> None: ...


class FakeSecretStore:
    """In-memory adapter with predictable references for automated tests."""

    def __init__(self) -> None:
        self._values: dict[str, bytes] = {}
        self._next_id = 1

    def put(self, secret: bytes) -> str:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("Secret must be non-empty bytes")
        ref = f"fake://mfa/{self._next_id:06d}"
        self._next_id += 1
        self._values[ref] = bytes(secret)
        return ref

    def get(self, ref: str) -> bytes:
        try:
            return self._values[ref]
        except KeyError as exc:
            raise SecretNotFoundError("Secret reference not found") from exc

    def delete(self, ref: str) -> None:
        if ref not in self._values:
            raise SecretNotFoundError("Secret reference not found")
        del self._values[ref]


class EncryptedFileSecretStore:
    """Local-only AES-GCM store. The encryption key is never stored here."""

    _PREFIX = "dev-encrypted://"

    def __init__(self, root: Path, key: bytes) -> None:
        if len(key) != 32:
            raise SecretStoreConfigurationError(
                "Development encryption key must be exactly 32 bytes"
            )

        self._root = root.expanduser().resolve()
        self._cipher = AESGCM(key)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)

        mode = stat.S_IMODE(self._root.stat().st_mode)
        if mode & 0o077:
            raise SecretStoreConfigurationError(
                "Secret-store directory permissions must exclude group and other access"
            )

    def _path_for(self, ref: str) -> Path:
        if not ref.startswith(self._PREFIX):
            raise SecretNotFoundError("Secret reference not found")
        identifier = ref.removeprefix(self._PREFIX)
        try:
            if str(uuid4()) == identifier:
                pass
            from uuid import UUID
            UUID(identifier)
        except (ValueError, AttributeError) as exc:
            raise SecretNotFoundError("Secret reference not found") from exc
        return self._root / f"{identifier}.enc"

    def put(self, secret: bytes) -> str:
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("Secret must be non-empty bytes")

        identifier = str(uuid4())
        ref = f"{self._PREFIX}{identifier}"
        nonce = secrets.token_bytes(12)
        ciphertext = nonce + self._cipher.encrypt(nonce, secret, ref.encode("utf-8"))
        path = self._root / f"{identifier}.enc"

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(ciphertext)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return ref

    def get(self, ref: str) -> bytes:
        path = self._path_for(ref)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise SecretNotFoundError("Secret reference not found") from exc

        if len(data) < 13:
            raise SecretStoreError("Stored secret record is invalid")

        try:
            return self._cipher.decrypt(data[:12], data[12:], ref.encode("utf-8"))
        except InvalidTag as exc:
            raise SecretStoreError("Stored secret could not be authenticated") from exc

    def delete(self, ref: str) -> None:
        path = self._path_for(ref)
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise SecretNotFoundError("Secret reference not found") from exc


class OpenBaoSecretStore:
    """FN-SEC-STORE-001: OpenBao KV v2 adapter for MFA secrets."""

    _PREFIX = "openbao://finsight/mfa/"

    def __init__(
        self,
        base_url: str,
        token: str,
        mount: str = "finsight",
        ca_cert_path: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._timeout = timeout
        self._ssl_context = None

        if ca_cert_path:
            ca_path = Path(ca_cert_path).expanduser().resolve()
            if not ca_path.is_file():
                raise SecretStoreConfigurationError(
                    f"OpenBao CA certificate file not found: {ca_cert_path}"
                )
            self._ssl_context = ssl.create_default_context(cafile=str(ca_path))

    def _url_for_data(self, identifier: str) -> str:
        return f"{self._base_url}/v1/{self._mount}/data/mfa/{identifier}"

    def _url_for_metadata(self, identifier: str) -> str:
        return f"{self._base_url}/v1/{self._mount}/metadata/mfa/{identifier}"

    def _parse_ref(self, ref: str) -> str:
        if not ref.startswith(self._PREFIX):
            raise SecretNotFoundError("Secret reference not found")
        identifier = ref.removeprefix(self._PREFIX)
        try:
            UUID(identifier)
        except (ValueError, AttributeError) as exc:
            raise SecretNotFoundError("Secret reference not found") from exc
        return identifier

    def put(self, secret: bytes) -> str:
        """FN-SEC-STORE-001: Write a secret to OpenBao KV v2 and return an opaque reference."""
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("Secret must be non-empty bytes")

        identifier = str(uuid4())
        ref = f"{self._PREFIX}{identifier}"
        url = self._url_for_data(identifier)
        payload = json.dumps(
            {"data": {"seed": base64.b64encode(secret).decode("ascii")}}
        ).encode("utf-8")

        req = Request(
            url,
            data=payload,
            headers={
                "X-Vault-Token": self._token,
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urlopen(req, context=self._ssl_context, timeout=self._timeout) as resp:  # nosec B310
                if resp.status not in (200, 204):
                    raise SecretStoreError(f"OpenBao write failed with status {resp.status}")
        except HTTPError as exc:
            if exc.code == 403:
                raise SecretStoreError("OpenBao permission denied") from exc
            raise SecretStoreError(f"OpenBao error: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SecretStoreError("OpenBao service unavailable") from exc

        return ref

    def get(self, ref: str) -> bytes:
        """FN-SEC-STORE-002: Retrieve and decode a secret from OpenBao KV v2."""
        identifier = self._parse_ref(ref)
        url = self._url_for_data(identifier)

        req = Request(
            url,
            headers={"X-Vault-Token": self._token},
            method="GET",
        )

        try:
            with urlopen(req, context=self._ssl_context, timeout=self._timeout) as resp:  # nosec B310
                data = json.loads(resp.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code == 404:
                raise SecretNotFoundError("Secret reference not found") from exc
            if exc.code == 403:
                raise SecretStoreError("OpenBao permission denied") from exc
            raise SecretStoreError(f"OpenBao error: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SecretStoreError("OpenBao service unavailable") from exc

        try:
            seed_b64 = data["data"]["data"]["seed"]
            return base64.b64decode(seed_b64)
        except (KeyError, TypeError, ValueError) as exc:
            raise SecretStoreError("Stored secret record is invalid") from exc

    def delete(self, ref: str) -> None:
        """FN-SEC-STORE-003: Delete secret metadata and all versions from OpenBao KV v2."""
        identifier = self._parse_ref(ref)
        url = self._url_for_metadata(identifier)

        req = Request(
            url,
            headers={"X-Vault-Token": self._token},
            method="DELETE",
        )

        try:
            with urlopen(req, context=self._ssl_context, timeout=self._timeout) as resp:  # nosec B310
                if resp.status not in (200, 204):
                    raise SecretStoreError(f"OpenBao delete failed with status {resp.status}")
        except HTTPError as exc:
            if exc.code == 404:
                raise SecretNotFoundError("Secret reference not found") from exc
            if exc.code == 403:
                raise SecretStoreError("OpenBao permission denied") from exc
            raise SecretStoreError(f"OpenBao error: HTTP {exc.code}") from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise SecretStoreError("OpenBao service unavailable") from exc


def secret_store_from_environment() -> SecretStore:
    """FN-SEC-STORE-004: Select an explicitly permitted adapter; never fall back silently."""

    app_env = os.environ.get("APP_ENV", "development").strip().lower()
    backend = os.environ.get("MFA_SECRET_STORE_BACKEND", "").strip().lower()

    if backend == "openbao":
        addr = os.environ.get("OPENBAO_ADDR", "https://127.0.0.1:8200").strip()
        if app_env == "production" and not addr.startswith("https://"):
            raise SecretStoreConfigurationError(
                "Production OpenBao requires HTTPS endpoint"
            )

        token = os.environ.get("OPENBAO_TOKEN", "").strip()
        token_path = os.environ.get("OPENBAO_TOKEN_PATH", "").strip()
        if not token and token_path:
            tp = Path(token_path).expanduser().resolve()
            if not tp.is_file():
                raise SecretStoreConfigurationError(
                    f"OpenBao token file not found: {token_path}"
                )
            token = tp.read_text("utf-8").strip()

        if not token:
            raise SecretStoreConfigurationError(
                "OpenBao backend requires OPENBAO_TOKEN or OPENBAO_TOKEN_PATH"
            )

        mount = os.environ.get("OPENBAO_MOUNT", "finsight").strip()
        cacert = os.environ.get("OPENBAO_CACERT", "").strip() or None

        return OpenBaoSecretStore(
            base_url=addr,
            token=token,
            mount=mount,
            ca_cert_path=cacert,
        )

    if app_env == "production":
        raise SecretStoreConfigurationError(
            "No production MFA secret-store provider is configured"
        )

    if app_env == "test":
        if backend != "fake":
            raise SecretStoreConfigurationError(
                "Tests must explicitly select MFA_SECRET_STORE_BACKEND=fake"
            )
        return FakeSecretStore()

    if app_env != "development":
        raise SecretStoreConfigurationError("Unsupported APP_ENV for MFA secret storage")

    if backend != "dev-encrypted":
        raise SecretStoreConfigurationError(
            "Development requires MFA_SECRET_STORE_BACKEND=dev-encrypted"
        )

    encoded_key = os.environ.get("MFA_DEV_ENCRYPTION_KEY", "")
    store_path = os.environ.get("MFA_SECRET_STORE_PATH", "").strip()
    if not encoded_key or not store_path:
        raise SecretStoreConfigurationError(
            "Development secret storage requires an encryption key and storage path"
        )

    try:
        key = base64.b64decode(encoded_key, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SecretStoreConfigurationError(
            "Development encryption key must be valid Base64"
        ) from exc

    if len(key) != 32:
        raise SecretStoreConfigurationError(
            "Development encryption key must decode to exactly 32 bytes"
        )

    return EncryptedFileSecretStore(Path(store_path), key)
