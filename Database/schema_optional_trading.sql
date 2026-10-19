-- OPTIONAL PHASE 2+ EXTENSION — DO NOT APPLY for the first release.
-- Adds paper trading and broker integration. Real-money trading must remain disabled in
-- application configuration until a separate release, security review and operational approval.

BEGIN;

CREATE TABLE broker_providers (
    broker_provider_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE RESTRICT,
    provider_key VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    supported_markets TEXT[] NOT NULL DEFAULT '{}',
    supports_read_only BOOLEAN NOT NULL DEFAULT true,
    supports_paper BOOLEAN NOT NULL DEFAULT false,
    supports_live_orders BOOLEAN NOT NULL DEFAULT false,
    adapter_name VARCHAR(120) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE broker_connections (
    broker_connection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_provider_id UUID NOT NULL REFERENCES broker_providers(broker_provider_id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    connection_name VARCHAR(160) NOT NULL,
    secret_ref TEXT NOT NULL,
    permission_mode VARCHAR(24) NOT NULL DEFAULT 'read_only'
        CHECK (permission_mode IN ('read_only','paper','trade_capable')),
    connection_status VARCHAR(24) NOT NULL DEFAULT 'unverified'
        CHECK (connection_status IN ('unverified','healthy','failed','revoked','disabled')),
    last_tested_at TIMESTAMPTZ,
    last_successful_sync_at TIMESTAMPTZ,
    non_secret_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, connection_name)
);

CREATE TABLE broker_accounts (
    broker_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_connection_id UUID NOT NULL REFERENCES broker_connections(broker_connection_id) ON DELETE CASCADE,
    external_account_id VARCHAR(240) NOT NULL,
    account_name VARCHAR(160),
    account_type VARCHAR(40),
    account_mode VARCHAR(20) NOT NULL CHECK (account_mode IN ('read_only','paper','live')),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    account_status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (account_status IN ('active','restricted','closed','unknown')),
    last_reconciled_at TIMESTAMPTZ,
    account_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (broker_connection_id, external_account_id)
);

CREATE TABLE paper_trading_accounts (
    paper_trading_account_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID NOT NULL UNIQUE REFERENCES portfolios(portfolio_id) ON DELETE CASCADE,
    initial_cash NUMERIC(30,10) NOT NULL CHECK (initial_cash >= 0),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    simulation_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE TABLE broker_position_snapshots (
    broker_position_snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_account_id UUID NOT NULL REFERENCES broker_accounts(broker_account_id) ON DELETE CASCADE,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    as_of_at TIMESTAMPTZ NOT NULL,
    total_equity NUMERIC(30,10),
    cash_balance NUMERIC(30,10),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    provider_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (broker_account_id, as_of_at)
);

CREATE TABLE broker_positions (
    broker_position_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_position_snapshot_id UUID NOT NULL REFERENCES broker_position_snapshots(broker_position_snapshot_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    quantity NUMERIC(28,10) NOT NULL,
    average_cost NUMERIC(24,10),
    market_price NUMERIC(24,10),
    market_value NUMERIC(30,10),
    unrealized_pnl NUMERIC(30,10),
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    UNIQUE (broker_position_snapshot_id, instrument_id)
);

CREATE TABLE trading_safety_policies (
    trading_safety_policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL UNIQUE REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    allow_paper_orders BOOLEAN NOT NULL DEFAULT true,
    allow_live_orders BOOLEAN NOT NULL DEFAULT false,
    require_human_confirmation BOOLEAN NOT NULL DEFAULT true,
    require_step_up_auth BOOLEAN NOT NULL DEFAULT true,
    max_order_notional NUMERIC(30,10),
    max_position_weight NUMERIC(18,10),
    max_open_orders INTEGER,
    policy_version INTEGER NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    updated_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (max_order_notional IS NULL OR max_order_notional > 0),
    CHECK (max_position_weight IS NULL OR (max_position_weight > 0 AND max_position_weight <= 1)),
    CHECK (max_open_orders IS NULL OR max_open_orders > 0)
);

CREATE TABLE trading_orders (
    trading_order_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID REFERENCES portfolios(portfolio_id) ON DELETE SET NULL,
    broker_account_id UUID REFERENCES broker_accounts(broker_account_id) ON DELETE SET NULL,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    submitted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    strategy_version_id UUID REFERENCES strategy_versions(strategy_version_id) ON DELETE SET NULL,
    client_order_id VARCHAR(240) NOT NULL,
    provider_order_id VARCHAR(240),
    execution_mode VARCHAR(12) NOT NULL CHECK (execution_mode IN ('paper','live')),
    side VARCHAR(8) NOT NULL CHECK (side IN ('buy','sell')),
    order_type VARCHAR(20) NOT NULL CHECK (order_type IN ('market','limit','stop','stop_limit')),
    quantity NUMERIC(28,10) NOT NULL CHECK (quantity > 0),
    limit_price NUMERIC(24,10),
    stop_price NUMERIC(24,10),
    requested_notional NUMERIC(30,10),
    time_in_force VARCHAR(20) NOT NULL DEFAULT 'day',
    order_status VARCHAR(24) NOT NULL DEFAULT 'draft'
        CHECK (order_status IN ('draft','awaiting_approval','pending_submit','submitted','accepted','partially_filled','filled','cancel_pending','cancelled','rejected','expired','unknown')),
    confirmation_snapshot JSONB,
    confirmed_at TIMESTAMPTZ,
    safety_policy_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key VARCHAR(240) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (order_type NOT IN ('limit','stop_limit') OR limit_price IS NOT NULL),
    CHECK (order_type NOT IN ('stop','stop_limit') OR stop_price IS NOT NULL),
    CHECK (execution_mode <> 'live' OR (broker_account_id IS NOT NULL AND confirmed_at IS NOT NULL))
);

CREATE TABLE trading_risk_checks (
    trading_risk_check_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trading_order_id UUID NOT NULL REFERENCES trading_orders(trading_order_id) ON DELETE CASCADE,
    check_key VARCHAR(100) NOT NULL,
    check_version VARCHAR(80) NOT NULL,
    passed BOOLEAN NOT NULL,
    blocking BOOLEAN NOT NULL DEFAULT true,
    input_snapshot JSONB NOT NULL,
    result_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (trading_order_id, check_key, check_version)
);

CREATE TABLE trading_order_approvals (
    trading_order_approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trading_order_id UUID NOT NULL REFERENCES trading_orders(trading_order_id) ON DELETE CASCADE,
    requested_from_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    decided_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    decision VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approved','rejected','expired')),
    displayed_order_snapshot JSONB NOT NULL,
    decision_note TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE trading_order_events (
    trading_order_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trading_order_id UUID NOT NULL REFERENCES trading_orders(trading_order_id) ON DELETE CASCADE,
    event_type VARCHAR(60) NOT NULL,
    previous_status VARCHAR(24),
    new_status VARCHAR(24),
    provider_event_id VARCHAR(240),
    event_detail_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (trading_order_id, provider_event_id)
);

CREATE TABLE trading_order_fills (
    trading_order_fill_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    trading_order_id UUID NOT NULL REFERENCES trading_orders(trading_order_id) ON DELETE CASCADE,
    provider_fill_id VARCHAR(240),
    fill_time TIMESTAMPTZ NOT NULL,
    quantity NUMERIC(28,10) NOT NULL CHECK (quantity > 0),
    fill_price NUMERIC(24,10) NOT NULL CHECK (fill_price > 0),
    fee_amount NUMERIC(24,10) NOT NULL DEFAULT 0 CHECK (fee_amount >= 0),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    fill_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (trading_order_id, provider_fill_id)
);

CREATE TABLE broker_reconciliations (
    broker_reconciliation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_account_id UUID NOT NULL REFERENCES broker_accounts(broker_account_id) ON DELETE CASCADE,
    local_snapshot_id UUID REFERENCES broker_position_snapshots(broker_position_snapshot_id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('running','matched','differences_found','failed')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_redacted TEXT
);

CREATE TABLE broker_reconciliation_items (
    broker_reconciliation_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    broker_reconciliation_id UUID NOT NULL REFERENCES broker_reconciliations(broker_reconciliation_id) ON DELETE CASCADE,
    item_type VARCHAR(40) NOT NULL CHECK (item_type IN ('order','position','cash','fill')),
    local_reference_id UUID,
    provider_reference_id VARCHAR(240),
    reconciliation_status VARCHAR(24) NOT NULL CHECK (reconciliation_status IN ('matched','local_only','provider_only','mismatch','pending_review')),
    local_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    provider_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    resolved_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    resolved_at TIMESTAMPTZ
);

CREATE TABLE trade_journal_entries (
    trade_journal_entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    trading_order_id UUID REFERENCES trading_orders(trading_order_id) ON DELETE SET NULL,
    portfolio_transaction_id UUID REFERENCES portfolio_transactions(portfolio_transaction_id) ON DELETE SET NULL,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    rationale TEXT,
    tags TEXT[] NOT NULL DEFAULT '{}',
    post_trade_observations TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ix_broker_positions_snapshot ON broker_positions(broker_position_snapshot_id);
CREATE INDEX ix_trading_orders_status ON trading_orders(workspace_id, order_status, created_at DESC);
CREATE INDEX ix_trading_order_events_time ON trading_order_events(trading_order_id, occurred_at DESC);

COMMIT;

-- Safety invariants enforced by the application transaction and reviewed at release time:
-- 1) live orders rejected unless trading_safety_policies.allow_live_orders = true;
-- 2) live orders require step-up authentication when configured, a fresh explicit approval,
--    a recent passing set of mandatory trading_risk_checks, and a trade_capable connection;
-- 3) model output, signals and strategy runs can never call the broker directly;
-- 4) if risk/authorization/provider state is unavailable or ambiguous, do not submit the order;
-- 5) first-release deployment must not apply this migration or expose broker execution routes.
