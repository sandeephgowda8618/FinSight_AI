-- Migration 0007: User connections and Release 1 read-only guardrails.
-- Enforces connection ownership by user_id and strictly prohibits trade-capable connections in Release 1.

BEGIN;

CREATE TABLE IF NOT EXISTS user_connections (
    connection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    connection_name VARCHAR(160) NOT NULL,
    connection_type VARCHAR(64) NOT NULL DEFAULT 'market_data'
        CHECK (connection_type IN ('market_data', 'structured_data', 'financial_feed')),
    is_trade_capable BOOLEAN NOT NULL DEFAULT FALSE,
    connection_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (connection_status IN ('unverified', 'active', 'failed', 'revoked', 'disabled')),
    secret_ref TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_release1_read_only_no_trade CHECK (is_trade_capable = FALSE),
    CONSTRAINT uq_user_connection_name UNIQUE (user_id, connection_name)
);

CREATE INDEX IF NOT EXISTS idx_user_connections_user_id ON user_connections(user_id);

COMMIT;

