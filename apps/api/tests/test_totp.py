import pytest

from app.totp import generate_totp_secret, totp_code, verify_totp


def test_totp_matches_rfc_6238_sha1_six_digit_vector():
    # RFC 6238 Appendix B uses ASCII "12345678901234567890" for SHA-1.
    # The application requires 16+ byte secrets; this 20-byte vector is valid.
    secret = b"12345678901234567890"
    assert totp_code(secret, at_time=59) == "287082"


def test_totp_accepts_current_code_and_small_clock_skew():
    secret = b"S" * 20
    now = 1_700_000_010
    code = totp_code(secret, at_time=now)
    assert verify_totp(secret, code, at_time=now)
    assert verify_totp(secret, code, at_time=now + 30)


def test_totp_rejects_expired_code_outside_allowed_window():
    secret = b"S" * 20
    old_code = totp_code(secret, at_time=30)
    assert not verify_totp(secret, old_code, at_time=120)


@pytest.mark.parametrize("bad_code", ["", "123", "1234567", "12a456", "１２３４５６", " 12345"])
def test_totp_rejects_malformed_codes(bad_code):
    assert not verify_totp(b"S" * 20, bad_code, at_time=1_700_000_000)


def test_secret_generation_has_expected_size_and_randomness():
    first = generate_totp_secret()
    second = generate_totp_secret()
    assert len(first) == 20
    assert first != second


def test_secret_generation_rejects_unsafe_lengths():
    with pytest.raises(ValueError):
        generate_totp_secret(10)
