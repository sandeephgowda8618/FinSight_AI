import base64
from urllib.parse import parse_qs, unquote, urlparse

from app.mfa_service import (
    create_totp_provisioning,
    matching_totp_step,
    verify_totp_code,
)
from app.secret_store import FakeSecretStore
from app.totp import totp_code


def test_provisioning_returns_opaque_reference_and_valid_totp_uri():
    store = FakeSecretStore()

    reference, uri = create_totp_provisioning(
        account_name="analyst@example.test",
        issuer="FinSight AI",
        store=store,
    )

    assert reference.startswith("fake://mfa/")
    assert uri.startswith("otpauth://totp/")
    parsed = urlparse(uri)
    params = parse_qs(parsed.query)
    encoded_seed = params["secret"][0]
    padded = encoded_seed + "=" * (-len(encoded_seed) % 8)
    seed = base64.b32decode(padded)

    assert len(seed) == 20
    assert params["issuer"] == ["FinSight AI"]
    assert params["algorithm"] == ["SHA1"]
    assert params["digits"] == ["6"]
    assert params["period"] == ["30"]
    assert unquote(parsed.path).endswith("analyst@example.test")
    assert store.get(reference) == seed


def test_provisioning_rejects_empty_account_name():
    store = FakeSecretStore()

    try:
        create_totp_provisioning(account_name=" ", store=store)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected empty account name to be rejected")


def test_verify_totp_code_does_not_return_secret():
    store = FakeSecretStore()
    reference = store.put(b"S" * 20)
    now = 1_700_000_010
    code = totp_code(b"S" * 20, at_time=now)

    assert verify_totp_code(
        store=store,
        secret_ref=reference,
        supplied_code=code,
        at_time=now,
    )
    assert not verify_totp_code(
        store=store,
        secret_ref=reference,
        supplied_code="000000",
        at_time=now,
    )


def test_matching_totp_step_returns_counter_for_valid_code():
    secret = b"S" * 20
    now = 1_700_000_010
    code = totp_code(secret, at_time=now)

    assert matching_totp_step(
        secret=secret,
        supplied_code=code,
        at_time=now,
    ) == now // 30


def test_matching_totp_step_rejects_invalid_or_expired_code():
    secret = b"S" * 20

    assert matching_totp_step(
        secret=secret,
        supplied_code="bad-code",
        at_time=1_700_000_010,
    ) is None

    old_code = totp_code(secret, at_time=30)
    assert matching_totp_step(
        secret=secret,
        supplied_code=old_code,
        at_time=120,
    ) is None
