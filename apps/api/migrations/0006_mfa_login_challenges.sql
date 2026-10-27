BEGIN;

CREATE TABLE mfa_login_challenges (
    challenge_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    challenge_token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0 AND attempt_count <= 5),
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_mfa_login_challenges_user_expiry
    ON mfa_login_challenges(user_id, expires_at);

CREATE TABLE mfa_totp_replay_guard (
    mfa_factor_id UUID PRIMARY KEY
        REFERENCES mfa_factors(mfa_factor_id) ON DELETE CASCADE,
    last_accepted_step BIGINT NOT NULL
        CHECK (last_accepted_step >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;
