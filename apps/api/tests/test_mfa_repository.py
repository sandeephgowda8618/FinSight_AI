from uuid import uuid4

import pytest

from app.auth import hash_password
from app.database import connect
from app.mfa_repository import (
    MFAFactorNotFoundError,
    MFAInvalidCodeError,
    activate_totp_factor,
    create_pending_totp_factor,
    list_totp_factors,
    revoke_totp_factor,
    verify_active_totp_factor,
)
from app.secret_store import FakeSecretStore
from app.totp import totp_code


@pytest.fixture
def mfa_identity():
    email = f"mfa-repository-{uuid4().hex}@example.com"
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO users
                (email, display_name, password_hash, account_status)
            VALUES (%s, %s, %s, 'active')
            RETURNING user_id
            """,
            (email, "MFA Repository Test", hash_password("Mfa-Test-Password-2026!")),
        )
        user_id = cur.fetchone()[0]

    try:
        yield user_id, email
    finally:
        with connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE auth_sessions
                SET revoked_at = COALESCE(revoked_at, now()),
                    revoke_reason = COALESCE(revoke_reason, 'test_cleanup')
                WHERE user_id = %s
                """,
                (user_id,),
            )
            cur.execute(
                """
                UPDATE users
                SET account_status = 'deleted',
                    deleted_at = COALESCE(deleted_at, now())
                WHERE user_id = %s
                """,
                (user_id,),
            )


def enroll(store, user_id, email):
    factor_id, uri = create_pending_totp_factor(
        user_id=user_id,
        account_name=email,
        label="Test authenticator",
        store=store,
    )
    assert uri.startswith("otpauth://totp/")
    assert "secret=" in uri
    return factor_id, uri


def test_enroll_activate_and_list_factor(mfa_identity):
    user_id, email = mfa_identity
    store = FakeSecretStore()
    now = 1_800_000_000

    factor_id, _ = enroll(store, user_id, email)
    listed = list_totp_factors(user_id=user_id)

    assert len(listed) == 1
    assert listed[0]["factor_status"] == "pending"
    assert "secret_ref" not in listed[0]

    # The provisioning URI contains the seed, so retrieve it through the
    # fake store's public interface using the deterministic first reference.
    secret = store.get("fake://mfa/000001")
    code = totp_code(secret, at_time=now)

    activate_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=code,
        store=store,
        at_time=now,
    )

    listed = list_totp_factors(user_id=user_id)
    assert listed[0]["factor_status"] == "active"
    assert "secret_ref" not in listed[0]


def test_active_factor_rejects_reused_totp_step(mfa_identity):
    user_id, email = mfa_identity
    store = FakeSecretStore()
    now = 1_800_000_000

    factor_id, _ = enroll(store, user_id, email)
    secret = store.get("fake://mfa/000001")
    code = totp_code(secret, at_time=now)

    activate_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=code,
        store=store,
        at_time=now,
    )

    # Activation consumes this time step. The same step must not be accepted
    # again, even though the code is still inside the TOTP clock window.
    assert verify_active_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=code,
        store=store,
        at_time=now,
    ) is False


def test_invalid_activation_code_leaves_factor_pending(mfa_identity):
    user_id, email = mfa_identity
    store = FakeSecretStore()
    factor_id, _ = enroll(store, user_id, email)

    secret = store.get("fake://mfa/000001")
    correct_code = totp_code(secret, at_time=1_800_000_000)
    wrong_code = "000000" if correct_code != "000000" else "000001"

    with pytest.raises(MFAInvalidCodeError):
        activate_totp_factor(
            user_id=user_id,
            factor_id=factor_id,
            supplied_code=wrong_code,
            store=store,
            at_time=1_800_000_000,
        )

    assert list_totp_factors(user_id=user_id)[0]["factor_status"] == "pending"


def test_factor_cannot_be_accessed_by_another_user(mfa_identity):
    user_id, email = mfa_identity
    store = FakeSecretStore()
    factor_id, _ = enroll(store, user_id, email)

    other_user_id = uuid4()

    with pytest.raises(MFAFactorNotFoundError):
        activate_totp_factor(
            user_id=other_user_id,
            factor_id=factor_id,
            supplied_code="123456",
            store=store,
            at_time=1_800_000_000,
        )

    assert revoke_totp_factor(
        user_id=other_user_id,
        factor_id=factor_id,
        store=store,
    ) is False


def test_revoked_factor_cannot_be_verified(mfa_identity):
    user_id, email = mfa_identity
    store = FakeSecretStore()
    now = 1_800_000_000

    factor_id, _ = enroll(store, user_id, email)
    secret = store.get("fake://mfa/000001")
    code = totp_code(secret, at_time=now)

    activate_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        supplied_code=code,
        store=store,
        at_time=now,
    )

    assert revoke_totp_factor(
        user_id=user_id, factor_id=factor_id, store=store
    ) is True

    from app.secret_store import SecretNotFoundError

    with pytest.raises(SecretNotFoundError):
        store.get("fake://mfa/000001")

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT factor_status, secret_ref FROM mfa_factors "
            "WHERE mfa_factor_id = %s",
            (factor_id,),
        )
        factor_status, secret_ref = cur.fetchone()

    assert factor_status == "revoked"
    assert secret_ref is None

    with pytest.raises(MFAFactorNotFoundError):
        verify_active_totp_factor(
            user_id=user_id,
            factor_id=factor_id,
            supplied_code=code,
            store=store,
            at_time=now + 30,
        )


def test_revocation_retries_secret_cleanup_after_store_failure(mfa_identity):
    from app.secret_store import SecretStoreError

    user_id, email = mfa_identity
    underlying_store = FakeSecretStore()

    class FailsFirstDelete:
        def __init__(self):
            self.failed_once = False

        def put(self, secret):
            return underlying_store.put(secret)

        def get(self, ref):
            return underlying_store.get(ref)

        def delete(self, ref):
            if not self.failed_once:
                self.failed_once = True
                raise SecretStoreError("simulated cleanup failure")
            underlying_store.delete(ref)

    store = FailsFirstDelete()
    factor_id, _ = enroll(store, user_id, email)
    secret_ref = "fake://mfa/000001"

    with pytest.raises(SecretStoreError):
        revoke_totp_factor(
            user_id=user_id,
            factor_id=factor_id,
            store=store,
        )

    # Revocation commits before external secret cleanup is attempted.
    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT factor_status, secret_ref FROM mfa_factors "
            "WHERE mfa_factor_id = %s",
            (factor_id,),
        )
        factor_status, retained_ref = cur.fetchone()

    assert factor_status == "revoked"
    assert retained_ref == secret_ref

    # Retrying revocation retries deletion and clears the stored reference.
    assert revoke_totp_factor(
        user_id=user_id,
        factor_id=factor_id,
        store=store,
    ) is True

    from app.secret_store import SecretNotFoundError

    with pytest.raises(SecretNotFoundError):
        underlying_store.get(secret_ref)

    with connect() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT factor_status, secret_ref FROM mfa_factors "
            "WHERE mfa_factor_id = %s",
            (factor_id,),
        )
        factor_status, secret_ref_after_retry = cur.fetchone()

    assert factor_status == "revoked"
    assert secret_ref_after_retry is None
