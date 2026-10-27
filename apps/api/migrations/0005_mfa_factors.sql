-- FIN-14 MFA factor metadata; secret material remains in the configured secret store.
BEGIN;

CREATE TABLE mfa_factors (
    mfa_factor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    factor_type VARCHAR(30) NOT NULL CHECK (factor_type IN ('totp','webauthn','recovery_code')),
    label VARCHAR(120),
    secret_ref TEXT,
    public_key_data JSONB,
    factor_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (factor_status IN ('pending', 'active', 'revoked')),
    enrolled_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_mfa_factors_user_status
    ON mfa_factors(user_id, factor_status);

COMMIT;
