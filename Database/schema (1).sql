-- FinSight AI — PostgreSQL relational schema (full non-broker target schema)
-- This is a target-state schema, not a requirement to implement every table in Release 1.
-- PostgreSQL 16+ recommended. Install pgvector before running this file.
-- Money and market values use NUMERIC, not FLOAT. Calculations are performed in the
-- backend and persist inputs, source snapshot IDs, formula/model versions and outputs.

BEGIN;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================================
-- 01. Identity, access control, workspace and preferences
-- ============================================================================
CREATE TABLE roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_key VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('platform','workspace')),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_key VARCHAR(120) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(320) NOT NULL,
    password_hash TEXT,
    display_name VARCHAR(160) NOT NULL,
    account_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('invited','active','locked','disabled','deleted')),
    platform_role_id UUID REFERENCES roles(role_id) ON DELETE SET NULL,
    email_verified_at TIMESTAMPTZ,
    mfa_required BOOLEAN NOT NULL DEFAULT false,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_users_email_lower ON users (lower(email));

CREATE TABLE workspaces (
    workspace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(160) NOT NULL,
    slug VARCHAR(180) NOT NULL UNIQUE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    workspace_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (workspace_status IN ('active','suspended','archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_members (
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    member_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (member_status IN ('invited','active','suspended','removed')),
    invited_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    joined_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE workspace_invitations (
    invitation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    email VARCHAR(320) NOT NULL,
    role_id UUID NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    invited_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    invitation_token_hash TEXT NOT NULL UNIQUE,
    invitation_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (invitation_status IN ('pending','accepted','expired','revoked')),
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    refresh_token_hash TEXT UNIQUE,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(80)
);

CREATE TABLE password_reset_tokens (
    reset_token_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE mfa_factors (
    mfa_factor_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    factor_type VARCHAR(30) NOT NULL CHECK (factor_type IN ('totp','webauthn','recovery_code')),
    label VARCHAR(120),
    secret_ref TEXT,
    public_key_data JSONB,
    factor_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (factor_status IN ('pending','active','revoked')),
    enrolled_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE auth_events (
    auth_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    email_attempted VARCHAR(320),
    event_type VARCHAR(50) NOT NULL,
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('success','failure','blocked','challenged')),
    ip_address INET,
    user_agent TEXT,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE data_export_requests (
    data_export_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,
    requested_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    export_scope JSONB NOT NULL,
    request_status VARCHAR(24) NOT NULL DEFAULT 'queued'
        CHECK (request_status IN ('queued','processing','ready','failed','expired','cancelled')),
    artifact_uri TEXT,
    artifact_expires_at TIMESTAMPTZ,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    error_redacted TEXT
);

CREATE TABLE account_deletion_requests (
    account_deletion_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    requested_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    approved_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    request_status VARCHAR(24) NOT NULL DEFAULT 'requested'
        CHECK (request_status IN ('requested','under_review','approved','processing','completed','rejected','cancelled')),
    retention_and_ownership_plan JSONB NOT NULL DEFAULT '{}'::jsonb,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    decision_note TEXT
);

CREATE TABLE api_credentials (
    api_credential_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    label VARCHAR(120) NOT NULL,
    token_prefix VARCHAR(24) NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE user_preferences (
    user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    theme VARCHAR(20) NOT NULL DEFAULT 'system' CHECK (theme IN ('light','dark','system')),
    language_code VARCHAR(12) NOT NULL DEFAULT 'en',
    timezone_name VARCHAR(80) NOT NULL DEFAULT 'Asia/Kolkata',
    default_market VARCHAR(20) NOT NULL DEFAULT 'US',
    base_currency CHAR(3) NOT NULL DEFAULT 'USD',
    preferred_benchmark_instrument_id UUID,
    preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_settings (
    workspace_id UUID PRIMARY KEY REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    retention_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    allow_sharing BOOLEAN NOT NULL DEFAULT false,
    allow_public_registration BOOLEAN NOT NULL DEFAULT false,
    updated_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE notification_preferences (
    notification_preference_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    notification_type VARCHAR(80) NOT NULL,
    channel VARCHAR(30) NOT NULL CHECK (channel IN ('in_app','email','webhook')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (user_id, notification_type, channel)
);

CREATE TABLE notifications (
    notification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    notification_type VARCHAR(80) NOT NULL,
    title VARCHAR(240) NOT NULL,
    body TEXT,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    read_at TIMESTAMPTZ,
    delivery_status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (delivery_status IN ('queued','sent','failed','suppressed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    audit_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,
    actor_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    action_key VARCHAR(120) NOT NULL,
    resource_type VARCHAR(80) NOT NULL,
    resource_id UUID,
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('success','failure','denied')),
    correlation_id UUID,
    details_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 02. Source registry, currencies, AI/model configuration and execution tracking
-- ============================================================================
CREATE TABLE currencies (
    currency_code CHAR(3) PRIMARY KEY,
    currency_name VARCHAR(80) NOT NULL,
    minor_unit SMALLINT NOT NULL DEFAULT 2 CHECK (minor_unit BETWEEN 0 AND 4)
);

CREATE TABLE source_registry (
    source_registry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_key VARCHAR(160) NOT NULL UNIQUE,
    source_type VARCHAR(30) NOT NULL
        CHECK (source_type IN ('market_data','filing','news','research','user_upload','internal','other')),
    display_name VARCHAR(200) NOT NULL,
    publisher VARCHAR(200),
    base_url TEXT,
    licence_status VARCHAR(30) NOT NULL DEFAULT 'unknown'
        CHECK (licence_status IN ('approved','restricted','research_only','unknown','revoked')),
    licence_url TEXT,
    permitted_usage JSONB NOT NULL DEFAULT '{}'::jsonb,
    attribution_text TEXT,
    terms_reviewed_at TIMESTAMPTZ,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_providers (
    ai_provider_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_key VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    provider_kind VARCHAR(30) NOT NULL
        CHECK (provider_kind IN ('ollama','openai_compatible','local','hosted','other')),
    base_url TEXT,
    secret_ref TEXT,
    provider_status VARCHAR(20) NOT NULL DEFAULT 'configured'
        CHECK (provider_status IN ('configured','healthy','degraded','unavailable','disabled')),
    last_health_check_at TIMESTAMPTZ,
    non_secret_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE ai_models (
    ai_model_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_provider_id UUID NOT NULL REFERENCES ai_providers(ai_provider_id) ON DELETE RESTRICT,
    model_key VARCHAR(160) NOT NULL,
    model_name VARCHAR(240) NOT NULL,
    model_type VARCHAR(24) NOT NULL CHECK (model_type IN ('chat','embedding','reranker','other')),
    embedding_dimension INTEGER CHECK (embedding_dimension IS NULL OR embedding_dimension > 0),
    context_window_tokens INTEGER CHECK (context_window_tokens IS NULL OR context_window_tokens > 0),
    is_available BOOLEAN NOT NULL DEFAULT true,
    model_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ai_provider_id, model_key),
    CHECK ((model_type = 'embedding' AND embedding_dimension IS NOT NULL) OR model_type <> 'embedding')
);

CREATE TABLE ai_config_versions (
    ai_config_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ai_model_id UUID NOT NULL REFERENCES ai_models(ai_model_id) ON DELETE RESTRICT,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    config_name VARCHAR(160) NOT NULL,
    generation_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (ai_model_id, version_number)
);
CREATE UNIQUE INDEX uq_ai_config_active_per_model ON ai_config_versions(ai_model_id) WHERE is_active;

CREATE TABLE rag_config_versions (
    rag_config_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    config_name VARCHAR(160) NOT NULL,
    chunking_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    retrieval_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    permission_filter_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, version_number)
);
CREATE UNIQUE INDEX uq_rag_config_active_per_workspace ON rag_config_versions(workspace_id) WHERE is_active;

CREATE TABLE tool_registry (
    tool_registry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_key VARCHAR(120) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    description TEXT,
    input_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    permission_scope VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    high_impact BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workspace_tool_policies (
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    tool_registry_id UUID NOT NULL REFERENCES tool_registry(tool_registry_id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT false,
    permission_mode VARCHAR(24) NOT NULL DEFAULT 'read_only'
        CHECK (permission_mode IN ('read_only','write_approved','disabled')),
    policy_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, tool_registry_id)
);

CREATE TABLE execution_runs (
    execution_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,
    initiated_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    execution_type VARCHAR(40) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','failed','cancelled','needs_approval')),
    idempotency_key VARCHAR(200),
    correlation_id UUID,
    input_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_artifact_uri TEXT,
    error_code VARCHAR(100),
    error_message_redacted TEXT,
    queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    duration_ms BIGINT CHECK (duration_ms IS NULL OR duration_ms >= 0),
    UNIQUE (workspace_id, idempotency_key)
);

CREATE TABLE execution_steps (
    execution_step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID NOT NULL REFERENCES execution_runs(execution_run_id) ON DELETE CASCADE,
    step_number INTEGER NOT NULL CHECK (step_number >= 0),
    step_key VARCHAR(120) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','failed','skipped','cancelled')),
    input_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_code VARCHAR(100),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    UNIQUE (execution_run_id, step_number)
);

CREATE TABLE execution_events (
    execution_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID NOT NULL REFERENCES execution_runs(execution_run_id) ON DELETE CASCADE,
    execution_step_id UUID REFERENCES execution_steps(execution_step_id) ON DELETE SET NULL,
    event_type VARCHAR(80) NOT NULL,
    severity VARCHAR(20) NOT NULL DEFAULT 'info' CHECK (severity IN ('debug','info','warning','error')),
    message_redacted TEXT,
    event_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE service_health_checks (
    service_health_check_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_key VARCHAR(120) NOT NULL,
    service_instance VARCHAR(240),
    status VARCHAR(24) NOT NULL CHECK (status IN ('healthy','degraded','unavailable','unknown')),
    latency_ms BIGINT CHECK (latency_ms IS NULL OR latency_ms >= 0),
    details_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE background_jobs (
    background_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    job_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','failed','cancelled','retry_wait')),
    idempotency_key VARCHAR(200) UNIQUE,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    max_attempts SMALLINT NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 20),
    attempt_count SMALLINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error_redacted TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE job_attempts (
    job_attempt_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    background_job_id UUID NOT NULL REFERENCES background_jobs(background_job_id) ON DELETE CASCADE,
    attempt_number SMALLINT NOT NULL CHECK (attempt_number > 0),
    worker_id VARCHAR(120),
    status VARCHAR(20) NOT NULL CHECK (status IN ('running','completed','failed','cancelled')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ,
    error_code VARCHAR(100),
    error_message_redacted TEXT,
    UNIQUE (background_job_id, attempt_number)
);

-- ============================================================================
-- 03. Market reference data, ingestion, point-in-time snapshots and fundamentals
-- ============================================================================
CREATE TABLE exchanges (
    exchange_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mic_code VARCHAR(12) UNIQUE,
    exchange_code VARCHAR(30) NOT NULL UNIQUE,
    exchange_name VARCHAR(160) NOT NULL,
    country_code CHAR(2),
    timezone_name VARCHAR(80) NOT NULL,
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE exchange_calendar_sessions (
    exchange_id UUID NOT NULL REFERENCES exchanges(exchange_id) ON DELETE CASCADE,
    session_date DATE NOT NULL,
    is_trading_day BOOLEAN NOT NULL,
    market_open_at TIMESTAMPTZ,
    market_close_at TIMESTAMPTZ,
    pre_market_open_at TIMESTAMPTZ,
    post_market_close_at TIMESTAMPTZ,
    session_name VARCHAR(40) NOT NULL DEFAULT 'regular',
    source_snapshot_id UUID,
    PRIMARY KEY (exchange_id, session_date, session_name),
    CHECK ((is_trading_day = false) OR (market_open_at IS NOT NULL AND market_close_at IS NOT NULL))
);

CREATE TABLE companies (
    company_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name VARCHAR(240) NOT NULL,
    display_name VARCHAR(240),
    country_code CHAR(2),
    cik VARCHAR(20),
    lei VARCHAR(20),
    website_url TEXT,
    incorporation_date DATE,
    company_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (company_status IN ('active','inactive','delisted','unknown')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_companies_cik_nonnull ON companies(cik) WHERE cik IS NOT NULL;
CREATE UNIQUE INDEX uq_companies_lei_nonnull ON companies(lei) WHERE lei IS NOT NULL;

CREATE TABLE company_aliases (
    company_alias_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    alias_text VARCHAR(240) NOT NULL,
    alias_type VARCHAR(40) NOT NULL CHECK (alias_type IN ('former_name','brand','common_name','ticker_alias','other')),
    valid_from DATE,
    valid_to DATE,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

CREATE TABLE instruments (
    instrument_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID REFERENCES companies(company_id) ON DELETE SET NULL,
    exchange_id UUID REFERENCES exchanges(exchange_id) ON DELETE RESTRICT,
    symbol VARCHAR(40) NOT NULL,
    instrument_name VARCHAR(240) NOT NULL,
    instrument_type VARCHAR(30) NOT NULL
        CHECK (instrument_type IN ('equity','etf','index','fund','adr','future','option','fx','other')),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    isin VARCHAR(20),
    figi VARCHAR(24),
    listing_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (listing_status IN ('active','inactive','delisted','suspended','unknown')),
    valid_from DATE,
    valid_to DATE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);
CREATE UNIQUE INDEX uq_instruments_exchange_symbol_active ON instruments(exchange_id, upper(symbol))
    WHERE listing_status = 'active';
CREATE INDEX ix_instruments_company ON instruments(company_id);

CREATE TABLE instrument_identifiers (
    instrument_identifier_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    identifier_scheme VARCHAR(40) NOT NULL,
    identifier_value VARCHAR(200) NOT NULL,
    valid_from DATE,
    valid_to DATE,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    UNIQUE (identifier_scheme, identifier_value, valid_from),
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

CREATE TABLE instrument_symbol_history (
    instrument_symbol_history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    exchange_id UUID REFERENCES exchanges(exchange_id) ON DELETE SET NULL,
    symbol VARCHAR(40) NOT NULL,
    valid_from DATE NOT NULL,
    valid_to DATE,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    UNIQUE (instrument_id, symbol, valid_from)
);

CREATE TABLE classification_taxonomies (
    taxonomy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    taxonomy_key VARCHAR(80) NOT NULL UNIQUE,
    taxonomy_name VARCHAR(160) NOT NULL,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL
);

CREATE TABLE classifications (
    classification_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    taxonomy_id UUID NOT NULL REFERENCES classification_taxonomies(taxonomy_id) ON DELETE CASCADE,
    parent_classification_id UUID REFERENCES classifications(classification_id) ON DELETE SET NULL,
    classification_code VARCHAR(80),
    classification_name VARCHAR(160) NOT NULL,
    UNIQUE (taxonomy_id, classification_code)
);

CREATE TABLE instrument_classifications (
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    classification_id UUID NOT NULL REFERENCES classifications(classification_id) ON DELETE CASCADE,
    valid_from DATE,
    valid_to DATE,
    source_snapshot_id UUID,
    PRIMARY KEY (instrument_id, classification_id, valid_from),
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

CREATE TABLE market_data_providers (
    market_data_provider_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_registry_id UUID NOT NULL REFERENCES source_registry(source_registry_id) ON DELETE RESTRICT,
    provider_key VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    supported_regions TEXT[] NOT NULL DEFAULT '{}',
    data_delay_type VARCHAR(20) NOT NULL DEFAULT 'end_of_day'
        CHECK (data_delay_type IN ('real_time','delayed','end_of_day','historical_only','demo')),
    adapter_name VARCHAR(120) NOT NULL,
    rate_limit_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    provider_status VARCHAR(20) NOT NULL DEFAULT 'configured'
        CHECK (provider_status IN ('configured','healthy','degraded','unavailable','disabled')),
    last_health_check_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE provider_connections (
    provider_connection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    market_data_provider_id UUID NOT NULL REFERENCES market_data_providers(market_data_provider_id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    connection_name VARCHAR(160) NOT NULL,
    secret_ref TEXT,
    access_mode VARCHAR(20) NOT NULL DEFAULT 'read_only' CHECK (access_mode IN ('read_only','admin')),
    connection_status VARCHAR(20) NOT NULL DEFAULT 'unverified'
        CHECK (connection_status IN ('unverified','healthy','failed','revoked','disabled')),
    last_tested_at TIMESTAMPTZ,
    last_successful_sync_at TIMESTAMPTZ,
    non_secret_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, workspace_id)
);

CREATE TABLE data_snapshots (
    data_snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE SET NULL,
    market_data_provider_id UUID REFERENCES market_data_providers(market_data_provider_id) ON DELETE SET NULL,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    parent_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    dataset_type VARCHAR(60) NOT NULL,
    snapshot_key VARCHAR(240),
    data_mode VARCHAR(24) NOT NULL
        CHECK (data_mode IN ('real_time','delayed','end_of_day','historical','demo','user_upload','derived','cached_copy')),
    freshness_status VARCHAR(20) NOT NULL DEFAULT 'unknown'
        CHECK (freshness_status IN ('fresh','cached','stale','demo','unknown')),
    snapshot_status VARCHAR(20) NOT NULL DEFAULT 'building'
        CHECK (snapshot_status IN ('building','validated','current','stale','failed','superseded','retained')),
    as_of_at TIMESTAMPTZ,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    coverage_start_at TIMESTAMPTZ,
    coverage_end_at TIMESTAMPTZ,
    source_version VARCHAR(160),
    content_hash CHAR(64),
    record_count BIGINT CHECK (record_count IS NULL OR record_count >= 0),
    quality_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    CHECK (coverage_end_at IS NULL OR coverage_start_at IS NULL OR coverage_end_at >= coverage_start_at)
);
CREATE INDEX ix_data_snapshots_type_asof ON data_snapshots(dataset_type, as_of_at DESC);

CREATE TABLE provider_coverage (
    provider_coverage_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_connection_id UUID NOT NULL REFERENCES provider_connections(provider_connection_id) ON DELETE CASCADE,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    data_category VARCHAR(60) NOT NULL,
    frequency VARCHAR(30),
    field_list TEXT[] NOT NULL DEFAULT '{}',
    coverage_start_at TIMESTAMPTZ,
    coverage_end_at TIMESTAMPTZ,
    entitlement_notes TEXT,
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_connection_id, instrument_id, data_category, frequency)
);

CREATE TABLE ingestion_batches (
    ingestion_batch_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_connection_id UUID REFERENCES provider_connections(provider_connection_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    background_job_id UUID REFERENCES background_jobs(background_job_id) ON DELETE SET NULL,
    batch_type VARCHAR(60) NOT NULL,
    idempotency_key VARCHAR(200) NOT NULL UNIQUE,
    request_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','validated','completed','partial','failed','cancelled')),
    requested_start_at TIMESTAMPTZ,
    requested_end_at TIMESTAMPTZ,
    rows_received BIGINT NOT NULL DEFAULT 0 CHECK (rows_received >= 0),
    rows_accepted BIGINT NOT NULL DEFAULT 0 CHECK (rows_accepted >= 0),
    rows_rejected BIGINT NOT NULL DEFAULT 0 CHECK (rows_rejected >= 0),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_summary TEXT
);

CREATE TABLE raw_data_records (
    raw_data_record_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ingestion_batch_id UUID NOT NULL REFERENCES ingestion_batches(ingestion_batch_id) ON DELETE CASCADE,
    external_record_key VARCHAR(240),
    entity_type VARCHAR(80) NOT NULL,
    observed_at TIMESTAMPTZ,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    payload JSONB NOT NULL,
    payload_hash CHAR(64) NOT NULL,
    validation_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (validation_status IN ('pending','accepted','rejected','duplicate')),
    UNIQUE (ingestion_batch_id, payload_hash)
);

CREATE TABLE data_quality_rules (
    data_quality_rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    rule_key VARCHAR(120) NOT NULL,
    entity_type VARCHAR(80) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('info','warning','error','critical')),
    rule_definition JSONB NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, rule_key)
);

CREATE TABLE data_quality_issues (
    data_quality_issue_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE CASCADE,
    ingestion_batch_id UUID REFERENCES ingestion_batches(ingestion_batch_id) ON DELETE CASCADE,
    data_quality_rule_id UUID REFERENCES data_quality_rules(data_quality_rule_id) ON DELETE SET NULL,
    entity_type VARCHAR(80) NOT NULL,
    entity_id UUID,
    field_name VARCHAR(160),
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('info','warning','error','critical')),
    issue_code VARCHAR(100) NOT NULL,
    issue_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    issue_status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (issue_status IN ('open','resolved','waived')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ,
    resolved_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE refresh_policies (
    refresh_policy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_connection_id UUID NOT NULL REFERENCES provider_connections(provider_connection_id) ON DELETE CASCADE,
    data_category VARCHAR(60) NOT NULL,
    frequency VARCHAR(40) NOT NULL,
    schedule_expression VARCHAR(120),
    lookback_days INTEGER NOT NULL DEFAULT 5 CHECK (lookback_days >= 0),
    backfill_enabled BOOLEAN NOT NULL DEFAULT true,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    last_started_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    UNIQUE (provider_connection_id, data_category)
);

CREATE TABLE financial_metric_definitions (
    financial_metric_definition_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_key VARCHAR(120) NOT NULL UNIQUE,
    display_name VARCHAR(160) NOT NULL,
    description TEXT,
    source_concept VARCHAR(200),
    canonical_unit VARCHAR(40) NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'numeric' CHECK (value_type IN ('numeric','text','boolean')),
    calculation_definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_derived BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE financial_statements (
    financial_statement_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id UUID NOT NULL REFERENCES companies(company_id) ON DELETE CASCADE,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    statement_type VARCHAR(24) NOT NULL CHECK (statement_type IN ('income','balance_sheet','cash_flow','other')),
    period_type VARCHAR(24) NOT NULL CHECK (period_type IN ('quarterly','annual','ttm','instant','other')),
    fiscal_year INTEGER,
    fiscal_period VARCHAR(20),
    period_start DATE,
    period_end DATE NOT NULL,
    filed_at TIMESTAMPTZ,
    accepted_at TIMESTAMPTZ,
    accession_number VARCHAR(80),
    filing_url TEXT,
    reporting_currency CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    source_observed_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    CHECK (period_start IS NULL OR period_end >= period_start),
    UNIQUE (company_id, statement_type, period_type, period_end, accession_number)
);

CREATE TABLE financial_facts (
    financial_fact_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    financial_statement_id UUID NOT NULL REFERENCES financial_statements(financial_statement_id) ON DELETE CASCADE,
    financial_metric_definition_id UUID NOT NULL REFERENCES financial_metric_definitions(financial_metric_definition_id) ON DELETE RESTRICT,
    reported_concept VARCHAR(240),
    numeric_value NUMERIC(30,10),
    text_value TEXT,
    boolean_value BOOLEAN,
    unit VARCHAR(40) NOT NULL,
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    dimensions JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_locator VARCHAR(240),
    fact_context JSONB NOT NULL DEFAULT '{}'::jsonb,
    valid_from TIMESTAMPTZ,
    valid_to TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    content_hash CHAR(64),
    CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from),
    CHECK (num_nonnulls(numeric_value, text_value, boolean_value) <= 1)
);
CREATE INDEX ix_financial_facts_metric ON financial_facts(financial_metric_definition_id);
CREATE INDEX ix_financial_statements_company_period ON financial_statements(company_id, period_end DESC);

CREATE TABLE price_bars (
    price_bar_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    interval_code VARCHAR(20) NOT NULL DEFAULT '1d',
    bar_time TIMESTAMPTZ NOT NULL,
    open_price NUMERIC(24,10) NOT NULL CHECK (open_price > 0),
    high_price NUMERIC(24,10) NOT NULL CHECK (high_price > 0),
    low_price NUMERIC(24,10) NOT NULL CHECK (low_price > 0),
    close_price NUMERIC(24,10) NOT NULL CHECK (close_price > 0),
    volume NUMERIC(30,6) CHECK (volume IS NULL OR volume >= 0),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    adjustment_type VARCHAR(24) NOT NULL DEFAULT 'raw'
        CHECK (adjustment_type IN ('raw','split_adjusted','dividend_adjusted','total_return')),
    source_observed_at TIMESTAMPTZ,
    valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at TIMESTAMPTZ,
    quality_status VARCHAR(20) NOT NULL DEFAULT 'valid' CHECK (quality_status IN ('valid','warning','invalid')),
    UNIQUE (data_snapshot_id, instrument_id, interval_code, bar_time, adjustment_type),
    CHECK (high_price >= low_price),
    CHECK (high_price >= GREATEST(open_price, close_price)),
    CHECK (low_price <= LEAST(open_price, close_price)),
    CHECK (valid_to IS NULL OR valid_to >= valid_from)
);
CREATE INDEX ix_price_bars_instrument_time ON price_bars(instrument_id, interval_code, bar_time DESC);
CREATE INDEX ix_price_bars_snapshot ON price_bars(data_snapshot_id, instrument_id);

CREATE TABLE corporate_actions (
    corporate_action_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    action_type VARCHAR(30) NOT NULL CHECK (action_type IN ('dividend','split','spinoff','merger','symbol_change','other')),
    announcement_at TIMESTAMPTZ,
    ex_date DATE NOT NULL,
    record_date DATE,
    payable_date DATE,
    cash_amount NUMERIC(24,10),
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    split_numerator NUMERIC(20,8),
    split_denominator NUMERIC(20,8),
    source_observed_at TIMESTAMPTZ,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    action_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (split_denominator IS NULL OR split_denominator <> 0),
    UNIQUE (data_snapshot_id, instrument_id, action_type, ex_date)
);

CREATE TABLE index_constituents (
    index_constituent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    index_instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    constituent_instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    valid_from DATE NOT NULL,
    valid_to DATE,
    weight NUMERIC(18,10) CHECK (weight IS NULL OR weight >= 0),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (index_instrument_id <> constituent_instrument_id),
    CHECK (valid_to IS NULL OR valid_to >= valid_from),
    UNIQUE (index_instrument_id, constituent_instrument_id, valid_from)
);

-- ============================================================================
-- 04. Structured sources, saved queries, datasets and lineage
-- ============================================================================
CREATE TABLE structured_data_sources (
    structured_data_source_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    source_name VARCHAR(160) NOT NULL,
    source_kind VARCHAR(24) NOT NULL CHECK (source_kind IN ('postgresql','csv','spreadsheet','api','other')),
    connection_secret_ref TEXT,
    non_secret_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    allowlisted_objects JSONB NOT NULL DEFAULT '[]'::jsonb,
    access_mode VARCHAR(20) NOT NULL DEFAULT 'read_only' CHECK (access_mode IN ('read_only','read_write')),
    connection_status VARCHAR(20) NOT NULL DEFAULT 'unverified'
        CHECK (connection_status IN ('unverified','healthy','failed','disabled')),
    last_tested_at TIMESTAMPTZ,
    last_synced_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, source_name)
);

CREATE TABLE saved_queries (
    saved_query_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    structured_data_source_id UUID REFERENCES structured_data_sources(structured_data_source_id) ON DELETE SET NULL,
    query_name VARCHAR(180) NOT NULL,
    query_type VARCHAR(24) NOT NULL CHECK (query_type IN ('sql','visual_builder','financial_screen','api')),
    query_definition JSONB NOT NULL,
    parameter_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    read_only_required BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, query_name)
);

CREATE TABLE user_datasets (
    user_dataset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    parent_dataset_id UUID REFERENCES user_datasets(user_dataset_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    dataset_name VARCHAR(180) NOT NULL,
    source_type VARCHAR(24) NOT NULL CHECK (source_type IN ('upload','query_result','derived','provider_export','demo')),
    storage_uri TEXT,
    schema_definition JSONB NOT NULL DEFAULT '{}'::jsonb,
    row_count BIGINT CHECK (row_count IS NULL OR row_count >= 0),
    content_hash CHAR(64),
    min_observation_date DATE,
    max_observation_date DATE,
    dataset_status VARCHAR(20) NOT NULL DEFAULT 'ready'
        CHECK (dataset_status IN ('uploading','processing','ready','failed','archived','deletion_pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, dataset_name),
    CHECK (max_observation_date IS NULL OR min_observation_date IS NULL OR max_observation_date >= min_observation_date)
);

CREATE TABLE dataset_transformations (
    dataset_transformation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    input_dataset_id UUID REFERENCES user_datasets(user_dataset_id) ON DELETE SET NULL,
    output_dataset_id UUID NOT NULL REFERENCES user_datasets(user_dataset_id) ON DELETE CASCADE,
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    transformation_type VARCHAR(60) NOT NULL,
    transformation_order INTEGER NOT NULL DEFAULT 1 CHECK (transformation_order > 0),
    transformation_definition JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (output_dataset_id, transformation_order)
);

CREATE TABLE dataset_lineage (
    user_dataset_id UUID NOT NULL REFERENCES user_datasets(user_dataset_id) ON DELETE CASCADE,
    upstream_dataset_id UUID NOT NULL REFERENCES user_datasets(user_dataset_id) ON DELETE RESTRICT,
    dataset_transformation_id UUID REFERENCES dataset_transformations(dataset_transformation_id) ON DELETE SET NULL,
    lineage_role VARCHAR(40) NOT NULL DEFAULT 'input',
    PRIMARY KEY (user_dataset_id, upstream_dataset_id, lineage_role),
    CHECK (user_dataset_id <> upstream_dataset_id)
);

CREATE TABLE query_executions (
    query_execution_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saved_query_id UUID REFERENCES saved_queries(saved_query_id) ON DELETE SET NULL,
    structured_data_source_id UUID REFERENCES structured_data_sources(structured_data_source_id) ON DELETE SET NULL,
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    query_text_redacted TEXT,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_outcome VARCHAR(20) NOT NULL CHECK (validation_outcome IN ('approved','rejected','error')),
    row_count BIGINT CHECK (row_count IS NULL OR row_count >= 0),
    result_dataset_id UUID REFERENCES user_datasets(user_dataset_id) ON DELETE SET NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    elapsed_ms BIGINT CHECK (elapsed_ms IS NULL OR elapsed_ms >= 0),
    error_message_redacted TEXT
);

-- ============================================================================
-- 05. Financial research library, document versions, chunks and pgvector RAG
-- ============================================================================
CREATE TABLE research_sources (
    research_source_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_registry_id UUID NOT NULL REFERENCES source_registry(source_registry_id) ON DELETE RESTRICT,
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    source_name VARCHAR(180) NOT NULL,
    connector_kind VARCHAR(40) NOT NULL CHECK (connector_kind IN ('manual_upload','web','filing_api','news_api','rss','other')),
    source_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    sync_enabled BOOLEAN NOT NULL DEFAULT false,
    last_sync_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, source_name)
);

CREATE TABLE research_documents (
    research_document_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    research_source_id UUID REFERENCES research_sources(research_source_id) ON DELETE SET NULL,
    company_id UUID REFERENCES companies(company_id) ON DELETE SET NULL,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    document_type VARCHAR(40) NOT NULL
        CHECK (document_type IN ('filing','earnings_report','transcript','research_note','news','dataset','user_document','other')),
    title VARCHAR(500) NOT NULL,
    canonical_url TEXT,
    publisher_name VARCHAR(200),
    language_code VARCHAR(12),
    published_at TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    content_hash CHAR(64),
    lifecycle_status VARCHAR(24) NOT NULL DEFAULT 'uploaded'
        CHECK (lifecycle_status IN ('uploaded','queued','processing','indexed','failed','deletion_pending','deleted')),
    tags TEXT[] NOT NULL DEFAULT '{}',
    financial_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_research_documents_company_date ON research_documents(company_id, published_at DESC);
CREATE INDEX ix_research_documents_workspace_status ON research_documents(workspace_id, lifecycle_status);

CREATE TABLE document_versions (
    document_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    research_document_id UUID NOT NULL REFERENCES research_documents(research_document_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    supersedes_version_id UUID REFERENCES document_versions(document_version_id) ON DELETE SET NULL,
    mime_type VARCHAR(120),
    size_bytes BIGINT CHECK (size_bytes IS NULL OR size_bytes >= 0),
    malware_scan_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (malware_scan_status IN ('pending','clean','infected','skipped','failed')),
    content_hash CHAR(64) NOT NULL,
    original_storage_uri TEXT,
    extracted_text_storage_uri TEXT,
    extracted_text TEXT,
    extraction_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (extraction_status IN ('pending','processing','succeeded','failed','unsupported')),
    extracted_at TIMESTAMPTZ,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (research_document_id, version_number),
    UNIQUE (research_document_id, content_hash)
);
CREATE UNIQUE INDEX uq_document_one_active_version ON document_versions(research_document_id) WHERE is_active;

CREATE TABLE document_chunks (
    document_chunk_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL REFERENCES document_versions(document_version_id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL CHECK (chunk_index >= 0),
    text_content TEXT NOT NULL,
    token_count INTEGER CHECK (token_count IS NULL OR token_count >= 0),
    page_number INTEGER CHECK (page_number IS NULL OR page_number > 0),
    section_path TEXT,
    character_start BIGINT,
    character_end BIGINT,
    paragraph_start INTEGER,
    paragraph_end INTEGER,
    table_index INTEGER,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    content_hash CHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_version_id, chunk_index),
    CHECK (character_end IS NULL OR character_start IS NULL OR character_end >= character_start)
);

CREATE TABLE document_tables (
    document_table_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL REFERENCES document_versions(document_version_id) ON DELETE CASCADE,
    table_index INTEGER NOT NULL CHECK (table_index >= 0),
    page_number INTEGER,
    caption TEXT,
    header_rows JSONB NOT NULL DEFAULT '[]'::jsonb,
    table_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    extraction_status VARCHAR(20) NOT NULL DEFAULT 'extracted'
        CHECK (extraction_status IN ('extracted','partial','failed')),
    UNIQUE (document_version_id, table_index)
);

CREATE TABLE document_table_cells (
    document_table_cell_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_table_id UUID NOT NULL REFERENCES document_tables(document_table_id) ON DELETE CASCADE,
    row_index INTEGER NOT NULL CHECK (row_index >= 0),
    column_index INTEGER NOT NULL CHECK (column_index >= 0),
    cell_text TEXT,
    row_header TEXT,
    column_header TEXT,
    numeric_value NUMERIC(30,10),
    unit VARCHAR(40),
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    reporting_period_label VARCHAR(80),
    cell_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (document_table_id, row_index, column_index)
);
ALTER TABLE document_chunks ADD COLUMN document_table_id UUID REFERENCES document_tables(document_table_id) ON DELETE SET NULL;
CREATE INDEX ix_document_versions_content_hash ON document_versions(content_hash);

CREATE TABLE document_access_grants (
    document_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    research_document_id UUID NOT NULL REFERENCES research_documents(research_document_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);
CREATE UNIQUE INDEX uq_doc_grant_user ON document_access_grants(research_document_id, grantee_user_id) WHERE grantee_user_id IS NOT NULL;
CREATE UNIQUE INDEX uq_doc_grant_workspace ON document_access_grants(research_document_id, grantee_workspace_id) WHERE grantee_workspace_id IS NOT NULL;

CREATE TABLE knowledge_indexes (
    knowledge_index_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    index_name VARCHAR(180) NOT NULL,
    ai_model_id UUID NOT NULL REFERENCES ai_models(ai_model_id) ON DELETE RESTRICT,
    embedding_dimension INTEGER NOT NULL CHECK (embedding_dimension > 0),
    distance_metric VARCHAR(20) NOT NULL DEFAULT 'cosine' CHECK (distance_metric IN ('cosine','l2','inner_product')),
    chunking_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    index_version INTEGER NOT NULL DEFAULT 1 CHECK (index_version > 0),
    index_status VARCHAR(20) NOT NULL DEFAULT 'building'
        CHECK (index_status IN ('building','ready','stale','rebuilding','failed','disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, index_name, index_version)
);

CREATE TABLE chunk_embeddings (
    chunk_embedding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_chunk_id UUID NOT NULL REFERENCES document_chunks(document_chunk_id) ON DELETE CASCADE,
    knowledge_index_id UUID NOT NULL REFERENCES knowledge_indexes(knowledge_index_id) ON DELETE CASCADE,
    embedding vector NOT NULL,
    embedding_dimension INTEGER NOT NULL CHECK (embedding_dimension > 0),
    embedding_model_key VARCHAR(160) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (document_chunk_id, knowledge_index_id),
    CHECK (vector_dims(embedding) = embedding_dimension)
);
-- For performant ANN search, create an HNSW index whose vector dimension matches the configured index.
-- Example for a 768-dimensional index: CREATE INDEX ... USING hnsw ((embedding::vector(768)) vector_cosine_ops);

CREATE TABLE document_index_jobs (
    document_index_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID NOT NULL REFERENCES document_versions(document_version_id) ON DELETE CASCADE,
    knowledge_index_id UUID NOT NULL REFERENCES knowledge_indexes(knowledge_index_id) ON DELETE CASCADE,
    background_job_id UUID REFERENCES background_jobs(background_job_id) ON DELETE SET NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','processing','indexed','failed','deletion_pending','deleted')),
    operation_key VARCHAR(200) NOT NULL UNIQUE,
    chunks_expected INTEGER,
    chunks_indexed INTEGER NOT NULL DEFAULT 0 CHECK (chunks_indexed >= 0),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    last_error_redacted TEXT,
    UNIQUE (document_version_id, knowledge_index_id, operation_key)
);

CREATE TABLE index_reconciliation_events (
    index_reconciliation_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_version_id UUID REFERENCES document_versions(document_version_id) ON DELETE SET NULL,
    knowledge_index_id UUID REFERENCES knowledge_indexes(knowledge_index_id) ON DELETE SET NULL,
    document_chunk_id UUID REFERENCES document_chunks(document_chunk_id) ON DELETE SET NULL,
    background_job_id UUID REFERENCES background_jobs(background_job_id) ON DELETE SET NULL,
    operation_type VARCHAR(30) NOT NULL CHECK (operation_type IN ('upsert','delete','rebuild','verify')),
    outcome VARCHAR(24) NOT NULL CHECK (outcome IN ('pending','success','retryable_failure','permanent_failure')),
    retry_count SMALLINT NOT NULL DEFAULT 0 CHECK (retry_count >= 0),
    detail_redacted JSONB NOT NULL DEFAULT '{}'::jsonb,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE research_collections (
    research_collection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    collection_name VARCHAR(180) NOT NULL,
    description TEXT,
    collection_type VARCHAR(40) NOT NULL DEFAULT 'research',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, collection_name)
);

CREATE TABLE research_collection_documents (
    research_collection_id UUID NOT NULL REFERENCES research_collections(research_collection_id) ON DELETE CASCADE,
    research_document_id UUID NOT NULL REFERENCES research_documents(research_document_id) ON DELETE CASCADE,
    added_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (research_collection_id, research_document_id)
);

-- ============================================================================
-- 06. Conversations, RAG provenance, model calls and AI tool tracing
-- ============================================================================
CREATE TABLE conversations (
    conversation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    title VARCHAR(300) NOT NULL DEFAULT 'New conversation',
    conversation_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (conversation_status IN ('active','archived','deleted')),
    rag_enabled BOOLEAN NOT NULL DEFAULT true,
    selected_ai_model_id UUID REFERENCES ai_models(ai_model_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    parent_message_id UUID REFERENCES messages(message_id) ON DELETE SET NULL,
    role VARCHAR(20) NOT NULL CHECK (role IN ('system','user','assistant','tool')),
    content TEXT,
    structured_content JSONB NOT NULL DEFAULT '{}'::jsonb,
    message_status VARCHAR(20) NOT NULL DEFAULT 'completed'
        CHECK (message_status IN ('pending','streaming','completed','cancelled','failed')),
    generation_number INTEGER NOT NULL DEFAULT 1 CHECK (generation_number > 0),
    ai_model_id UUID REFERENCES ai_models(ai_model_id) ON DELETE SET NULL,
    ai_config_version_id UUID REFERENCES ai_config_versions(ai_config_version_id) ON DELETE SET NULL,
    prompt_tokens INTEGER CHECK (prompt_tokens IS NULL OR prompt_tokens >= 0),
    completion_tokens INTEGER CHECK (completion_tokens IS NULL OR completion_tokens >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    UNIQUE (parent_message_id, generation_number)
);
CREATE INDEX ix_messages_conversation_time ON messages(conversation_id, created_at);

CREATE TABLE message_attachments (
    message_attachment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    uploaded_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    original_filename VARCHAR(500) NOT NULL,
    mime_type VARCHAR(120) NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    content_hash CHAR(64),
    storage_uri TEXT NOT NULL,
    processing_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (processing_status IN ('pending','processing','ready','failed','rejected','deleted')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE message_feedback (
    message_feedback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    rating VARCHAR(20) NOT NULL CHECK (rating IN ('helpful','unhelpful','report_issue')),
    comment TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (message_id, user_id)
);

CREATE TABLE retrieval_runs (
    retrieval_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(conversation_id) ON DELETE SET NULL,
    message_id UUID REFERENCES messages(message_id) ON DELETE SET NULL,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    rag_config_version_id UUID REFERENCES rag_config_versions(rag_config_version_id) ON DELETE SET NULL,
    knowledge_index_id UUID REFERENCES knowledge_indexes(knowledge_index_id) ON DELETE SET NULL,
    query_text_redacted TEXT,
    query_embedding_model_id UUID REFERENCES ai_models(ai_model_id) ON DELETE SET NULL,
    filter_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'completed' CHECK (status IN ('running','completed','failed','empty')),
    candidates_count INTEGER NOT NULL DEFAULT 0 CHECK (candidates_count >= 0),
    returned_count INTEGER NOT NULL DEFAULT 0 CHECK (returned_count >= 0),
    permission_filtered_count INTEGER NOT NULL DEFAULT 0 CHECK (permission_filtered_count >= 0),
    elapsed_ms BIGINT CHECK (elapsed_ms IS NULL OR elapsed_ms >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE retrieval_run_chunks (
    retrieval_run_id UUID NOT NULL REFERENCES retrieval_runs(retrieval_run_id) ON DELETE CASCADE,
    document_chunk_id UUID NOT NULL REFERENCES document_chunks(document_chunk_id) ON DELETE RESTRICT,
    rank_position INTEGER NOT NULL CHECK (rank_position > 0),
    similarity_score NUMERIC(12,10),
    included_in_context BOOLEAN NOT NULL DEFAULT false,
    exclusion_reason VARCHAR(100),
    source_page INTEGER,
    source_section TEXT,
    PRIMARY KEY (retrieval_run_id, document_chunk_id),
    UNIQUE (retrieval_run_id, rank_position)
);

CREATE TABLE model_invocations (
    model_invocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    conversation_id UUID REFERENCES conversations(conversation_id) ON DELETE SET NULL,
    message_id UUID REFERENCES messages(message_id) ON DELETE SET NULL,
    ai_model_id UUID NOT NULL REFERENCES ai_models(ai_model_id) ON DELETE RESTRICT,
    ai_config_version_id UUID REFERENCES ai_config_versions(ai_config_version_id) ON DELETE SET NULL,
    operation_type VARCHAR(40) NOT NULL CHECK (operation_type IN ('generation','embedding','reranking','other')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('success','failure','cancelled','timeout')),
    input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
    output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
    elapsed_ms BIGINT CHECK (elapsed_ms IS NULL OR elapsed_ms >= 0),
    reported_cost NUMERIC(18,8) CHECK (reported_cost IS NULL OR reported_cost >= 0),
    error_code VARCHAR(100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tool_invocations (
    tool_invocation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool_registry_id UUID NOT NULL REFERENCES tool_registry(tool_registry_id) ON DELETE RESTRICT,
    message_id UUID REFERENCES messages(message_id) ON DELETE SET NULL,
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    requested_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL CHECK (status IN ('queued','running','completed','failed','blocked','needs_approval')),
    approval_required BOOLEAN NOT NULL DEFAULT false,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    error_code VARCHAR(100)
);

-- ============================================================================
-- 07. News, events, price watchlists, portfolios and dashboard state
-- ============================================================================
CREATE TABLE news_items (
    news_item_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    headline VARCHAR(600) NOT NULL,
    summary TEXT,
    article_url TEXT,
    publisher_name VARCHAR(200),
    published_at TIMESTAMPTZ,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    language_code VARCHAR(12),
    content_hash CHAR(64),
    sentiment_score NUMERIC(8,6),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE news_instruments (
    news_item_id UUID NOT NULL REFERENCES news_items(news_item_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    relevance_score NUMERIC(8,6),
    linking_method VARCHAR(30) NOT NULL DEFAULT 'provider',
    PRIMARY KEY (news_item_id, instrument_id)
);

CREATE TABLE market_events (
    market_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    company_id UUID REFERENCES companies(company_id) ON DELETE CASCADE,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    event_type VARCHAR(40) NOT NULL
        CHECK (event_type IN ('earnings','dividend','split','filing','guidance','macro','other')),
    event_title VARCHAR(300) NOT NULL,
    scheduled_at TIMESTAMPTZ,
    event_date DATE,
    event_status VARCHAR(24) NOT NULL DEFAULT 'scheduled'
        CHECK (event_status IN ('scheduled','reported','cancelled','estimated','unknown')),
    event_details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE portfolios (
    portfolio_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    portfolio_name VARCHAR(180) NOT NULL,
    portfolio_type VARCHAR(20) NOT NULL DEFAULT 'manual'
        CHECK (portfolio_type IN ('manual','imported','paper')),
    base_currency CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    benchmark_instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    data_source_label VARCHAR(160),
    portfolio_status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (portfolio_status IN ('active','archived','read_only')),
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, portfolio_name)
);

CREATE TABLE portfolio_transactions (
    portfolio_transaction_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID NOT NULL REFERENCES portfolios(portfolio_id) ON DELETE CASCADE,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    transaction_type VARCHAR(24) NOT NULL
        CHECK (transaction_type IN ('buy','sell','dividend','deposit','withdrawal','fee','split','transfer','other')),
    transaction_time TIMESTAMPTZ NOT NULL,
    settlement_date DATE,
    quantity NUMERIC(28,10),
    unit_price NUMERIC(24,10),
    gross_amount NUMERIC(28,10),
    fees NUMERIC(24,10) NOT NULL DEFAULT 0 CHECK (fees >= 0),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    external_transaction_id VARCHAR(200),
    notes TEXT,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (portfolio_id, external_transaction_id)
);

CREATE TABLE portfolio_snapshots (
    portfolio_snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID NOT NULL REFERENCES portfolios(portfolio_id) ON DELETE CASCADE,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    as_of_at TIMESTAMPTZ NOT NULL,
    total_market_value NUMERIC(30,10),
    cash_value NUMERIC(30,10),
    total_equity_value NUMERIC(30,10),
    realized_pnl NUMERIC(30,10),
    unrealized_pnl NUMERIC(30,10),
    base_currency CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    valuation_status VARCHAR(20) NOT NULL DEFAULT 'complete'
        CHECK (valuation_status IN ('complete','partial','unavailable')),
    limitation_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (portfolio_id, as_of_at, data_snapshot_id)
);

CREATE TABLE portfolio_positions (
    portfolio_position_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_snapshot_id UUID NOT NULL REFERENCES portfolio_snapshots(portfolio_snapshot_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    quantity NUMERIC(28,10) NOT NULL,
    average_cost NUMERIC(24,10),
    market_price NUMERIC(24,10),
    market_value NUMERIC(30,10),
    cost_basis NUMERIC(30,10),
    realized_pnl NUMERIC(30,10),
    unrealized_pnl NUMERIC(30,10),
    portfolio_weight NUMERIC(18,10),
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    valuation_source VARCHAR(30) NOT NULL DEFAULT 'market_data',
    UNIQUE (portfolio_snapshot_id, instrument_id)
);

CREATE TABLE portfolio_cash_balances (
    portfolio_snapshot_id UUID NOT NULL REFERENCES portfolio_snapshots(portfolio_snapshot_id) ON DELETE CASCADE,
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    cash_balance NUMERIC(30,10) NOT NULL,
    PRIMARY KEY (portfolio_snapshot_id, currency_code)
);

CREATE TABLE portfolio_returns (
    portfolio_return_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    portfolio_id UUID NOT NULL REFERENCES portfolios(portfolio_id) ON DELETE CASCADE,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    observation_date DATE NOT NULL,
    return_frequency VARCHAR(20) NOT NULL DEFAULT 'daily',
    period_return NUMERIC(18,10),
    cumulative_return NUMERIC(18,10),
    benchmark_return NUMERIC(18,10),
    portfolio_value NUMERIC(30,10),
    is_partial BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (portfolio_id, observation_date, return_frequency, data_snapshot_id)
);

CREATE TABLE watchlists (
    watchlist_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    watchlist_name VARCHAR(160) NOT NULL,
    display_order INTEGER NOT NULL DEFAULT 0,
    display_preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, watchlist_name)
);

CREATE TABLE watchlist_items (
    watchlist_id UUID NOT NULL REFERENCES watchlists(watchlist_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    display_order INTEGER NOT NULL DEFAULT 0,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    note TEXT,
    PRIMARY KEY (watchlist_id, instrument_id)
);

CREATE TABLE dashboard_layouts (
    dashboard_layout_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    layout_name VARCHAR(160) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    layout_version INTEGER NOT NULL DEFAULT 1 CHECK (layout_version > 0),
    layout_preferences JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, layout_name)
);
CREATE UNIQUE INDEX uq_dashboard_default_per_user ON dashboard_layouts(workspace_id, owner_user_id) WHERE is_default;

CREATE TABLE dashboard_widgets (
    dashboard_widget_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_layout_id UUID NOT NULL REFERENCES dashboard_layouts(dashboard_layout_id) ON DELETE CASCADE,
    widget_key VARCHAR(120) NOT NULL,
    title VARCHAR(180),
    position_x INTEGER NOT NULL DEFAULT 0,
    position_y INTEGER NOT NULL DEFAULT 0,
    width_units INTEGER NOT NULL DEFAULT 4 CHECK (width_units > 0),
    height_units INTEGER NOT NULL DEFAULT 3 CHECK (height_units > 0),
    widget_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    display_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE technical_indicator_definitions (
    technical_indicator_definition_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_key VARCHAR(80) NOT NULL UNIQUE,
    display_name VARCHAR(140) NOT NULL,
    description TEXT,
    calculation_version VARCHAR(100) NOT NULL,
    parameter_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    default_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_units VARCHAR(60),
    is_enabled BOOLEAN NOT NULL DEFAULT true
);

CREATE TABLE indicator_profiles (
    indicator_profile_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    profile_name VARCHAR(140) NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, profile_name)
);
CREATE UNIQUE INDEX uq_indicator_profile_default ON indicator_profiles(workspace_id, owner_user_id) WHERE is_default;

CREATE TABLE indicator_profile_items (
    indicator_profile_id UUID NOT NULL REFERENCES indicator_profiles(indicator_profile_id) ON DELETE CASCADE,
    technical_indicator_definition_id UUID NOT NULL REFERENCES technical_indicator_definitions(technical_indicator_definition_id) ON DELETE RESTRICT,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    display_order INTEGER NOT NULL DEFAULT 0,
    enabled BOOLEAN NOT NULL DEFAULT true,
    PRIMARY KEY (indicator_profile_id, technical_indicator_definition_id)
);

-- Add foreign keys to tables created before their referenced instrument tables are complete.
ALTER TABLE exchange_calendar_sessions ADD CONSTRAINT fk_exchange_calendar_snapshot
    FOREIGN KEY (source_snapshot_id) REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL;
ALTER TABLE instrument_classifications ADD CONSTRAINT fk_instrument_classification_snapshot
    FOREIGN KEY (source_snapshot_id) REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL;
ALTER TABLE user_preferences ADD CONSTRAINT fk_user_pref_benchmark
    FOREIGN KEY (preferred_benchmark_instrument_id) REFERENCES instruments(instrument_id) ON DELETE SET NULL;
ALTER TABLE user_preferences ADD CONSTRAINT fk_user_pref_currency
    FOREIGN KEY (base_currency) REFERENCES currencies(currency_code) ON DELETE RESTRICT;

-- ============================================================================
-- 08. DCF valuation: model versions, inputs/provenance, forecasts and sensitivities
-- ============================================================================
CREATE TABLE valuation_model_versions (
    valuation_model_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_key VARCHAR(80) NOT NULL,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    methodology VARCHAR(40) NOT NULL DEFAULT 'dcf' CHECK (methodology IN ('dcf','other')),
    formula_version VARCHAR(120) NOT NULL,
    implementation_version VARCHAR(120) NOT NULL,
    implementation_hash CHAR(64),
    model_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (model_key, version_number)
);

CREATE TABLE valuation_runs (
    valuation_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID NOT NULL UNIQUE REFERENCES execution_runs(execution_run_id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    company_id UUID NOT NULL REFERENCES companies(company_id) ON DELETE RESTRICT,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    valuation_model_version_id UUID NOT NULL REFERENCES valuation_model_versions(valuation_model_version_id) ON DELETE RESTRICT,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    parent_valuation_run_id UUID REFERENCES valuation_runs(valuation_run_id) ON DELETE SET NULL,
    scenario_name VARCHAR(160) NOT NULL DEFAULT 'Base case',
    valuation_date DATE NOT NULL,
    financial_period_end DATE,
    output_currency CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    forecast_years SMALLINT NOT NULL DEFAULT 5 CHECK (forecast_years BETWEEN 1 AND 30),
    wacc NUMERIC(14,10),
    terminal_growth_rate NUMERIC(14,10),
    terminal_value NUMERIC(30,10),
    present_value_forecast_cash_flows NUMERIC(30,10),
    present_value_terminal_value NUMERIC(30,10),
    enterprise_value NUMERIC(30,10),
    cash_and_equivalents NUMERIC(30,10),
    total_debt NUMERIC(30,10),
    equity_value NUMERIC(30,10),
    diluted_shares_outstanding NUMERIC(30,10),
    value_per_share NUMERIC(24,10),
    valuation_status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (valuation_status IN ('queued','running','completed','partial','failed')),
    data_quality_warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
    input_manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (wacc IS NULL OR (wacc > -1 AND wacc < 1)),
    CHECK (terminal_growth_rate IS NULL OR (terminal_growth_rate > -1 AND terminal_growth_rate < 1)),
    CHECK (wacc IS NULL OR terminal_growth_rate IS NULL OR terminal_growth_rate < wacc)
);
CREATE INDEX ix_valuation_runs_company_date ON valuation_runs(company_id, valuation_date DESC);

CREATE TABLE valuation_assumptions (
    valuation_assumption_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    valuation_run_id UUID NOT NULL REFERENCES valuation_runs(valuation_run_id) ON DELETE CASCADE,
    assumption_key VARCHAR(100) NOT NULL,
    forecast_year SMALLINT,
    numeric_value NUMERIC(30,12),
    text_value TEXT,
    unit VARCHAR(40) NOT NULL,
    source_type VARCHAR(24) NOT NULL
        CHECK (source_type IN ('user_input','source_fact','document_evidence','derived','scenario_override')),
    source_financial_fact_id UUID REFERENCES financial_facts(financial_fact_id) ON DELETE SET NULL,
    source_document_chunk_id UUID REFERENCES document_chunks(document_chunk_id) ON DELETE SET NULL,
    source_url TEXT,
    formula_or_method TEXT,
    is_user_approved BOOLEAN NOT NULL DEFAULT false,
    provenance_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (valuation_run_id, assumption_key, forecast_year),
    CHECK (source_type <> 'source_fact' OR source_financial_fact_id IS NOT NULL),
    CHECK (source_type <> 'document_evidence' OR source_document_chunk_id IS NOT NULL)
);

CREATE TABLE valuation_forecasts (
    valuation_forecast_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    valuation_run_id UUID NOT NULL REFERENCES valuation_runs(valuation_run_id) ON DELETE CASCADE,
    forecast_year SMALLINT NOT NULL CHECK (forecast_year > 0),
    fiscal_year INTEGER,
    revenue NUMERIC(30,10),
    revenue_growth_rate NUMERIC(14,10),
    operating_income NUMERIC(30,10),
    operating_margin NUMERIC(14,10),
    tax_rate NUMERIC(14,10),
    nopat NUMERIC(30,10),
    depreciation_amortization NUMERIC(30,10),
    capital_expenditure NUMERIC(30,10),
    change_in_working_capital NUMERIC(30,10),
    free_cash_flow NUMERIC(30,10),
    discount_factor NUMERIC(24,14),
    present_value_fcf NUMERIC(30,10),
    calculation_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (valuation_run_id, forecast_year)
);

CREATE TABLE valuation_sensitivity_runs (
    valuation_sensitivity_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    base_valuation_run_id UUID NOT NULL REFERENCES valuation_runs(valuation_run_id) ON DELETE CASCADE,
    variable_x VARCHAR(100) NOT NULL DEFAULT 'wacc',
    variable_y VARCHAR(100) NOT NULL DEFAULT 'terminal_growth_rate',
    x_values NUMERIC(14,10)[] NOT NULL,
    y_values NUMERIC(14,10)[] NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE valuation_sensitivity_points (
    valuation_sensitivity_run_id UUID NOT NULL REFERENCES valuation_sensitivity_runs(valuation_sensitivity_run_id) ON DELETE CASCADE,
    x_value NUMERIC(14,10) NOT NULL,
    y_value NUMERIC(14,10) NOT NULL,
    enterprise_value NUMERIC(30,10),
    equity_value NUMERIC(30,10),
    value_per_share NUMERIC(24,10),
    result_status VARCHAR(20) NOT NULL DEFAULT 'valid' CHECK (result_status IN ('valid','invalid','insufficient_data')),
    limitation TEXT,
    PRIMARY KEY (valuation_sensitivity_run_id, x_value, y_value)
);

CREATE TABLE valuation_run_comparisons (
    valuation_run_comparison_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    comparison_name VARCHAR(180) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, comparison_name)
);

CREATE TABLE valuation_comparison_members (
    valuation_run_comparison_id UUID NOT NULL REFERENCES valuation_run_comparisons(valuation_run_comparison_id) ON DELETE CASCADE,
    valuation_run_id UUID NOT NULL REFERENCES valuation_runs(valuation_run_id) ON DELETE CASCADE,
    display_order INTEGER NOT NULL DEFAULT 0,
    comparison_label VARCHAR(160),
    PRIMARY KEY (valuation_run_comparison_id, valuation_run_id)
);

-- ============================================================================
-- 09. Quantitative risk analytics: reproducible runs, metrics, covariance and stress
-- ============================================================================
CREATE TABLE risk_model_versions (
    risk_model_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model_key VARCHAR(100) NOT NULL,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    methodology VARCHAR(40) NOT NULL,
    implementation_version VARCHAR(120) NOT NULL,
    implementation_hash CHAR(64),
    formula_definitions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (model_key, version_number)
);

CREATE TABLE risk_config_versions (
    risk_config_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    config_name VARCHAR(160) NOT NULL,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    risk_free_rate NUMERIC(14,10),
    annualization_factor NUMERIC(12,6) NOT NULL DEFAULT 252 CHECK (annualization_factor > 0),
    default_confidence_level NUMERIC(6,5) NOT NULL DEFAULT 0.95000 CHECK (default_confidence_level > 0 AND default_confidence_level < 1),
    default_benchmark_instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    configuration JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT false,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, config_name, version_number)
);
CREATE UNIQUE INDEX uq_risk_config_active ON risk_config_versions(workspace_id, config_name) WHERE is_active;

CREATE TABLE risk_runs (
    risk_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID NOT NULL UNIQUE REFERENCES execution_runs(execution_run_id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    portfolio_id UUID REFERENCES portfolios(portfolio_id) ON DELETE SET NULL,
    portfolio_snapshot_id UUID REFERENCES portfolio_snapshots(portfolio_snapshot_id) ON DELETE SET NULL,
    risk_model_version_id UUID NOT NULL REFERENCES risk_model_versions(risk_model_version_id) ON DELETE RESTRICT,
    risk_config_version_id UUID REFERENCES risk_config_versions(risk_config_version_id) ON DELETE SET NULL,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    benchmark_instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    run_name VARCHAR(180),
    calculation_method VARCHAR(24) NOT NULL
        CHECK (calculation_method IN ('historical','parametric','monte_carlo','hybrid')),
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    return_frequency VARCHAR(20) NOT NULL DEFAULT 'daily',
    confidence_level NUMERIC(6,5) NOT NULL DEFAULT 0.95000 CHECK (confidence_level > 0 AND confidence_level < 1),
    annualization_factor NUMERIC(12,6) NOT NULL DEFAULT 252 CHECK (annualization_factor > 0),
    risk_free_rate NUMERIC(14,10),
    simulation_count INTEGER,
    random_seed BIGINT,
    covariance_method VARCHAR(40),
    config_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(20) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','partial','failed','insufficient_data')),
    data_limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (end_date >= start_date),
    CHECK (simulation_count IS NULL OR simulation_count > 0)
);
CREATE INDEX ix_risk_runs_portfolio_date ON risk_runs(portfolio_id, created_at DESC);

CREATE TABLE risk_run_positions (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    quantity NUMERIC(28,10),
    market_value NUMERIC(30,10),
    portfolio_weight NUMERIC(18,10) NOT NULL,
    currency_code CHAR(3) REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    source_portfolio_position_id UUID REFERENCES portfolio_positions(portfolio_position_id) ON DELETE SET NULL,
    PRIMARY KEY (risk_run_id, instrument_id)
);

CREATE TABLE risk_metric_results (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    metric_key VARCHAR(100) NOT NULL,
    metric_value NUMERIC(30,12),
    unit VARCHAR(40) NOT NULL,
    method VARCHAR(80) NOT NULL,
    confidence_level NUMERIC(6,5),
    annualization_factor NUMERIC(12,6),
    assumptions JSONB NOT NULL DEFAULT '{}'::jsonb,
    limitation TEXT,
    PRIMARY KEY (risk_run_id, metric_key)
);

CREATE TABLE risk_covariance_pairs (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    instrument_a_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    instrument_b_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    covariance NUMERIC(30,16),
    correlation NUMERIC(18,12),
    observation_count INTEGER CHECK (observation_count IS NULL OR observation_count >= 0),
    PRIMARY KEY (risk_run_id, instrument_a_id, instrument_b_id),
    CHECK (instrument_a_id <= instrument_b_id),
    CHECK (correlation IS NULL OR correlation BETWEEN -1 AND 1)
);

CREATE TABLE risk_time_series (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    observation_date DATE NOT NULL,
    portfolio_return NUMERIC(18,10),
    benchmark_return NUMERIC(18,10),
    portfolio_value NUMERIC(30,10),
    drawdown NUMERIC(18,10),
    high_water_mark NUMERIC(30,10),
    rolling_volatility NUMERIC(18,10),
    source_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    PRIMARY KEY (risk_run_id, observation_date)
);

CREATE TABLE stress_scenarios (
    stress_scenario_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    scenario_name VARCHAR(180) NOT NULL,
    scenario_description TEXT,
    scenario_type VARCHAR(30) NOT NULL CHECK (scenario_type IN ('historical_replay','factor_shock','custom','macro')),
    shocks JSONB NOT NULL,
    is_system_scenario BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, scenario_name)
);

CREATE TABLE risk_stress_results (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    stress_scenario_id UUID NOT NULL REFERENCES stress_scenarios(stress_scenario_id) ON DELETE RESTRICT,
    pnl_amount NUMERIC(30,10),
    pnl_percent NUMERIC(18,10),
    stressed_portfolio_value NUMERIC(30,10),
    result_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    scenario_definition_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    limitation TEXT,
    PRIMARY KEY (risk_run_id, stress_scenario_id)
);

CREATE TABLE risk_distribution_points (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    metric_key VARCHAR(100) NOT NULL,
    percentile NUMERIC(8,6) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    metric_value NUMERIC(30,12) NOT NULL,
    PRIMARY KEY (risk_run_id, metric_key, percentile)
);

CREATE TABLE risk_simulation_points (
    risk_run_id UUID NOT NULL REFERENCES risk_runs(risk_run_id) ON DELETE CASCADE,
    path_number INTEGER NOT NULL CHECK (path_number >= 0),
    step_number INTEGER NOT NULL CHECK (step_number >= 0),
    observation_date DATE,
    simulated_return NUMERIC(18,10),
    simulated_portfolio_value NUMERIC(30,10),
    PRIMARY KEY (risk_run_id, path_number, step_number)
);

-- ============================================================================
-- 10. DCF-linked reports, citations and saved report artefacts
-- ============================================================================
CREATE TABLE reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    execution_run_id UUID REFERENCES execution_runs(execution_run_id) ON DELETE SET NULL,
    report_type VARCHAR(40) NOT NULL
        CHECK (report_type IN ('company_research','valuation','risk_analysis','portfolio_review','screen','backtest','custom')),
    title VARCHAR(300) NOT NULL,
    summary TEXT,
    report_content JSONB NOT NULL DEFAULT '{}'::jsonb,
    artifact_uri TEXT,
    artifact_mime_type VARCHAR(120),
    as_of_at TIMESTAMPTZ,
    report_status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (report_status IN ('draft','generating','ready','failed','archived','deletion_pending')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE research_collection_conversations (
    research_collection_id UUID NOT NULL REFERENCES research_collections(research_collection_id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL REFERENCES conversations(conversation_id) ON DELETE CASCADE,
    added_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (research_collection_id, conversation_id)
);

CREATE TABLE research_collection_reports (
    research_collection_id UUID NOT NULL REFERENCES research_collections(research_collection_id) ON DELETE CASCADE,
    report_id UUID NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    added_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (research_collection_id, report_id)
);

CREATE TABLE report_data_snapshots (
    report_id UUID NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    usage_purpose VARCHAR(80) NOT NULL DEFAULT 'analysis_input',
    PRIMARY KEY (report_id, data_snapshot_id)
);

CREATE TABLE report_citations (
    report_citation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    document_version_id UUID REFERENCES document_versions(document_version_id) ON DELETE SET NULL,
    document_chunk_id UUID REFERENCES document_chunks(document_chunk_id) ON DELETE SET NULL,
    financial_fact_id UUID REFERENCES financial_facts(financial_fact_id) ON DELETE SET NULL,
    source_registry_id UUID REFERENCES source_registry(source_registry_id) ON DELETE SET NULL,
    citation_label VARCHAR(300),
    source_url TEXT,
    page_number INTEGER,
    section_label TEXT,
    quoted_text TEXT,
    accessed_at TIMESTAMPTZ,
    CHECK (num_nonnulls(document_version_id, document_chunk_id, financial_fact_id, source_registry_id, source_url) >= 1)
);

-- ============================================================================
-- 11. Screening, strategy versioning, signals and alerts
-- ============================================================================
CREATE TABLE saved_screens (
    saved_screen_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    screen_name VARCHAR(180) NOT NULL,
    description TEXT,
    market_code VARCHAR(20) NOT NULL DEFAULT 'US',
    rule_definition JSONB NOT NULL,
    version_number INTEGER NOT NULL DEFAULT 1 CHECK (version_number > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, screen_name)
);

CREATE TABLE screen_runs (
    screen_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    saved_screen_id UUID NOT NULL REFERENCES saved_screens(saved_screen_id) ON DELETE RESTRICT,
    execution_run_id UUID NOT NULL UNIQUE REFERENCES execution_runs(execution_run_id) ON DELETE RESTRICT,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    run_parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count >= 0),
    status VARCHAR(20) NOT NULL CHECK (status IN ('queued','running','completed','partial','failed','insufficient_data')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE screen_results (
    screen_run_id UUID NOT NULL REFERENCES screen_runs(screen_run_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    result_rank INTEGER,
    matched_conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (screen_run_id, instrument_id)
);

CREATE TABLE strategies (
    strategy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    strategy_name VARCHAR(180) NOT NULL,
    description TEXT,
    strategy_status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (strategy_status IN ('draft','validated','archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, strategy_name)
);

CREATE TABLE strategy_versions (
    strategy_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    strategy_id UUID NOT NULL REFERENCES strategies(strategy_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    parent_version_id UUID REFERENCES strategy_versions(strategy_version_id) ON DELETE SET NULL,
    strategy_definition JSONB NOT NULL,
    entry_rules JSONB NOT NULL,
    exit_rules JSONB NOT NULL,
    position_sizing_rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    risk_controls JSONB NOT NULL DEFAULT '{}'::jsonb,
    parameter_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_status VARCHAR(20) NOT NULL DEFAULT 'unvalidated'
        CHECK (validation_status IN ('unvalidated','valid','invalid','needs_data')),
    validation_report JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (strategy_id, version_number)
);

CREATE TABLE strategy_universe_instruments (
    strategy_version_id UUID NOT NULL REFERENCES strategy_versions(strategy_version_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    PRIMARY KEY (strategy_version_id, instrument_id)
);

CREATE TABLE strategy_variants (
    strategy_variant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    strategy_version_id UUID NOT NULL REFERENCES strategy_versions(strategy_version_id) ON DELETE CASCADE,
    variant_name VARCHAR(160) NOT NULL,
    parameter_overrides JSONB NOT NULL,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (strategy_version_id, variant_name)
);

CREATE TABLE alert_rules (
    alert_rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    alert_name VARCHAR(180) NOT NULL,
    alert_type VARCHAR(40) NOT NULL CHECK (alert_type IN ('price','percentage_change','indicator','screen','signal','workflow','data_quality','system')),
    rule_definition JSONB NOT NULL,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE CASCADE,
    watchlist_id UUID REFERENCES watchlists(watchlist_id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0 CHECK (cooldown_seconds >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alert_events (
    alert_event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_rule_id UUID NOT NULL REFERENCES alert_rules(alert_rule_id) ON DELETE CASCADE,
    instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    data_snapshot_id UUID REFERENCES data_snapshots(data_snapshot_id) ON DELETE SET NULL,
    deduplication_key VARCHAR(240) NOT NULL UNIQUE,
    triggering_observation JSONB NOT NULL,
    trigger_condition JSONB NOT NULL,
    event_status VARCHAR(20) NOT NULL DEFAULT 'triggered'
        CHECK (event_status IN ('triggered','acknowledged','resolved','suppressed','delivery_failed')),
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE TABLE signals (
    signal_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    strategy_version_id UUID REFERENCES strategy_versions(strategy_version_id) ON DELETE SET NULL,
    screen_run_id UUID REFERENCES screen_runs(screen_run_id) ON DELETE SET NULL,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    signal_type VARCHAR(40) NOT NULL,
    direction VARCHAR(20) CHECK (direction IN ('bullish','bearish','neutral','long','short','exit')),
    explanation TEXT,
    triggering_rule JSONB NOT NULL,
    observed_inputs JSONB NOT NULL DEFAULT '{}'::jsonb,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    current_status VARCHAR(24) NOT NULL DEFAULT 'new'
        CHECK (current_status IN ('new','active','acknowledged','expired','invalidated','closed'))
);

CREATE TABLE signal_observations (
    signal_observation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id UUID NOT NULL REFERENCES signals(signal_id) ON DELETE CASCADE,
    metric_key VARCHAR(100) NOT NULL,
    numeric_value NUMERIC(30,12),
    text_value TEXT,
    unit VARCHAR(40),
    source_price_bar_id UUID REFERENCES price_bars(price_bar_id) ON DELETE SET NULL,
    source_financial_fact_id UUID REFERENCES financial_facts(financial_fact_id) ON DELETE SET NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    observation_detail JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE signal_status_history (
    signal_status_history_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id UUID NOT NULL REFERENCES signals(signal_id) ON DELETE CASCADE,
    previous_status VARCHAR(24),
    new_status VARCHAR(24) NOT NULL,
    changed_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    reason TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 12. Agent workflows and approvals
-- ============================================================================
CREATE TABLE workflow_definitions (
    workflow_definition_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    workflow_name VARCHAR(180) NOT NULL,
    description TEXT,
    workflow_status VARCHAR(20) NOT NULL DEFAULT 'draft'
        CHECK (workflow_status IN ('draft','enabled','disabled','archived')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, workflow_name)
);

CREATE TABLE workflow_versions (
    workflow_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_definition_id UUID NOT NULL REFERENCES workflow_definitions(workflow_definition_id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    instructions TEXT,
    ai_model_id UUID REFERENCES ai_models(ai_model_id) ON DELETE SET NULL,
    ai_config_version_id UUID REFERENCES ai_config_versions(ai_config_version_id) ON DELETE SET NULL,
    input_schema JSONB NOT NULL DEFAULT '{}'::jsonb,
    execution_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    retry_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeout_seconds INTEGER NOT NULL DEFAULT 300 CHECK (timeout_seconds > 0),
    is_published BOOLEAN NOT NULL DEFAULT false,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workflow_definition_id, version_number)
);

CREATE TABLE workflow_steps (
    workflow_step_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE CASCADE,
    step_key VARCHAR(100) NOT NULL,
    step_order INTEGER NOT NULL CHECK (step_order > 0),
    step_type VARCHAR(40) NOT NULL CHECK (step_type IN ('llm','tool','retrieval','condition','approval','transform','report')),
    step_config JSONB NOT NULL,
    timeout_seconds INTEGER CHECK (timeout_seconds IS NULL OR timeout_seconds > 0),
    retry_limit SMALLINT NOT NULL DEFAULT 0 CHECK (retry_limit BETWEEN 0 AND 20),
    UNIQUE (workflow_version_id, step_key),
    UNIQUE (workflow_version_id, step_order)
);

CREATE TABLE workflow_tool_bindings (
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE CASCADE,
    tool_registry_id UUID NOT NULL REFERENCES tool_registry(tool_registry_id) ON DELETE RESTRICT,
    allowed_operations TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (workflow_version_id, tool_registry_id)
);

CREATE TABLE workflow_collection_bindings (
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE CASCADE,
    research_collection_id UUID NOT NULL REFERENCES research_collections(research_collection_id) ON DELETE CASCADE,
    PRIMARY KEY (workflow_version_id, research_collection_id)
);

CREATE TABLE workflow_data_source_bindings (
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE CASCADE,
    structured_data_source_id UUID NOT NULL REFERENCES structured_data_sources(structured_data_source_id) ON DELETE CASCADE,
    allowed_objects JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_operations TEXT[] NOT NULL DEFAULT ARRAY['select'],
    PRIMARY KEY (workflow_version_id, structured_data_source_id)
);

CREATE TABLE workflow_schedules (
    workflow_schedule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_definition_id UUID NOT NULL REFERENCES workflow_definitions(workflow_definition_id) ON DELETE CASCADE,
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE RESTRICT,
    schedule_expression VARCHAR(120) NOT NULL,
    timezone_name VARCHAR(80) NOT NULL,
    schedule_status VARCHAR(20) NOT NULL DEFAULT 'enabled' CHECK (schedule_status IN ('enabled','paused','disabled')),
    next_run_at TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workflow_runs (
    workflow_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_definition_id UUID NOT NULL REFERENCES workflow_definitions(workflow_definition_id) ON DELETE RESTRICT,
    workflow_version_id UUID NOT NULL REFERENCES workflow_versions(workflow_version_id) ON DELETE RESTRICT,
    execution_run_id UUID NOT NULL UNIQUE REFERENCES execution_runs(execution_run_id) ON DELETE RESTRICT,
    workflow_schedule_id UUID REFERENCES workflow_schedules(workflow_schedule_id) ON DELETE SET NULL,
    input_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    output_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    validation_result JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE workflow_approvals (
    workflow_approval_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_run_id UUID NOT NULL REFERENCES workflow_runs(workflow_run_id) ON DELETE CASCADE,
    workflow_step_id UUID REFERENCES workflow_steps(workflow_step_id) ON DELETE SET NULL,
    requested_from_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    decision_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    decision VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending','approved','rejected','expired')),
    requested_action JSONB NOT NULL,
    decision_note TEXT,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ
);

-- ============================================================================
-- 13. Backtesting, costs, comparable runs and trade-level research results
-- ============================================================================
CREATE TABLE cost_model_versions (
    cost_model_version_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    model_name VARCHAR(160) NOT NULL,
    version_number INTEGER NOT NULL CHECK (version_number > 0),
    market_code VARCHAR(20) NOT NULL DEFAULT 'US',
    assumptions JSONB NOT NULL,
    created_by_user_id UUID REFERENCES users(user_id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, model_name, version_number)
);

CREATE TABLE backtest_runs (
    backtest_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    execution_run_id UUID NOT NULL UNIQUE REFERENCES execution_runs(execution_run_id) ON DELETE RESTRICT,
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    strategy_version_id UUID NOT NULL REFERENCES strategy_versions(strategy_version_id) ON DELETE RESTRICT,
    strategy_variant_id UUID REFERENCES strategy_variants(strategy_variant_id) ON DELETE SET NULL,
    data_snapshot_id UUID NOT NULL REFERENCES data_snapshots(data_snapshot_id) ON DELETE RESTRICT,
    cost_model_version_id UUID REFERENCES cost_model_versions(cost_model_version_id) ON DELETE RESTRICT,
    benchmark_instrument_id UUID REFERENCES instruments(instrument_id) ON DELETE SET NULL,
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    interval_code VARCHAR(20) NOT NULL DEFAULT '1d',
    initial_capital NUMERIC(30,10) NOT NULL CHECK (initial_capital > 0),
    currency_code CHAR(3) NOT NULL REFERENCES currencies(currency_code) ON DELETE RESTRICT,
    execution_assumptions JSONB NOT NULL DEFAULT '{}'::jsonb,
    integrity_checks JSONB NOT NULL DEFAULT '{}'::jsonb,
    out_of_sample_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    status VARCHAR(24) NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','running','completed','partial','failed','insufficient_data','cancelled')),
    data_limitations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (end_date >= start_date)
);

CREATE TABLE backtest_metrics (
    backtest_run_id UUID NOT NULL REFERENCES backtest_runs(backtest_run_id) ON DELETE CASCADE,
    metric_key VARCHAR(100) NOT NULL,
    metric_value NUMERIC(30,12),
    unit VARCHAR(40) NOT NULL,
    definition_version VARCHAR(100),
    metric_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (backtest_run_id, metric_key)
);

CREATE TABLE backtest_equity_points (
    backtest_run_id UUID NOT NULL REFERENCES backtest_runs(backtest_run_id) ON DELETE CASCADE,
    observation_date DATE NOT NULL,
    portfolio_value NUMERIC(30,10),
    benchmark_value NUMERIC(30,10),
    period_return NUMERIC(18,10),
    drawdown NUMERIC(18,10),
    exposure NUMERIC(18,10),
    PRIMARY KEY (backtest_run_id, observation_date)
);

CREATE TABLE backtest_trades (
    backtest_trade_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backtest_run_id UUID NOT NULL REFERENCES backtest_runs(backtest_run_id) ON DELETE CASCADE,
    instrument_id UUID NOT NULL REFERENCES instruments(instrument_id) ON DELETE RESTRICT,
    entry_signal_id UUID REFERENCES signals(signal_id) ON DELETE SET NULL,
    exit_signal_id UUID REFERENCES signals(signal_id) ON DELETE SET NULL,
    direction VARCHAR(12) NOT NULL CHECK (direction IN ('long','short')),
    entry_at TIMESTAMPTZ NOT NULL,
    exit_at TIMESTAMPTZ,
    quantity NUMERIC(28,10) NOT NULL,
    entry_price NUMERIC(24,10) NOT NULL,
    exit_price NUMERIC(24,10),
    gross_pnl NUMERIC(30,10),
    fees NUMERIC(24,10) NOT NULL DEFAULT 0,
    slippage_cost NUMERIC(24,10) NOT NULL DEFAULT 0,
    net_pnl NUMERIC(30,10),
    holding_period_seconds BIGINT,
    trade_detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (exit_at IS NULL OR exit_at >= entry_at)
);

CREATE TABLE backtest_run_comparisons (
    backtest_run_comparison_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    owner_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    comparison_name VARCHAR(180) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, owner_user_id, comparison_name)
);

CREATE TABLE backtest_comparison_members (
    backtest_run_comparison_id UUID NOT NULL REFERENCES backtest_run_comparisons(backtest_run_comparison_id) ON DELETE CASCADE,
    backtest_run_id UUID NOT NULL REFERENCES backtest_runs(backtest_run_id) ON DELETE CASCADE,
    display_order INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (backtest_run_comparison_id, backtest_run_id)
);

-- Saved-item sharing uses dedicated FK-backed grant tables (no polymorphic resource IDs).
CREATE TABLE dashboard_access_grants (
    dashboard_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dashboard_layout_id UUID NOT NULL REFERENCES dashboard_layouts(dashboard_layout_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','edit','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);
CREATE TABLE dataset_access_grants (
    dataset_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_dataset_id UUID NOT NULL REFERENCES user_datasets(user_dataset_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','edit','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);
CREATE TABLE collection_access_grants (
    collection_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    research_collection_id UUID NOT NULL REFERENCES research_collections(research_collection_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','edit','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);
CREATE TABLE report_access_grants (
    report_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id UUID NOT NULL REFERENCES reports(report_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','edit','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);
CREATE TABLE strategy_access_grants (
    strategy_access_grant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    strategy_id UUID NOT NULL REFERENCES strategies(strategy_id) ON DELETE CASCADE,
    grantee_user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    grantee_workspace_id UUID REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    permission_level VARCHAR(20) NOT NULL CHECK (permission_level IN ('read','edit','manage')),
    granted_by_user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(grantee_user_id, grantee_workspace_id) = 1)
);

-- ============================================================================
-- 14. Operational indexes and targeted referential/performance indexes
-- ============================================================================
CREATE INDEX ix_workspace_members_user ON workspace_members(user_id, member_status);
CREATE INDEX ix_auth_sessions_active ON auth_sessions(user_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX ix_notifications_inbox ON notifications(user_id, created_at DESC) WHERE read_at IS NULL;
CREATE INDEX ix_audit_events_time ON audit_events(occurred_at DESC);
CREATE INDEX ix_execution_runs_workspace_time ON execution_runs(workspace_id, queued_at DESC);
CREATE INDEX ix_execution_runs_status ON execution_runs(status, queued_at);
CREATE INDEX ix_background_jobs_dispatch ON background_jobs(status, available_at) WHERE status IN ('queued','retry_wait');
CREATE INDEX ix_job_attempts_job ON job_attempts(background_job_id, attempt_number DESC);
CREATE INDEX ix_quality_issues_snapshot ON data_quality_issues(data_snapshot_id, severity, issue_status);
CREATE INDEX ix_raw_records_batch ON raw_data_records(ingestion_batch_id, validation_status);
CREATE INDEX ix_portfolio_snapshots_asof ON portfolio_snapshots(portfolio_id, as_of_at DESC);
CREATE INDEX ix_portfolio_transactions_time ON portfolio_transactions(portfolio_id, transaction_time DESC);
CREATE INDEX ix_retrieval_runs_conversation ON retrieval_runs(conversation_id, created_at DESC);
CREATE INDEX ix_document_chunks_version_page ON document_chunks(document_version_id, page_number, chunk_index);
CREATE INDEX ix_document_chunks_fts ON document_chunks USING gin (to_tsvector('simple', text_content));
CREATE INDEX ix_chunk_embeddings_index ON chunk_embeddings(knowledge_index_id);
CREATE INDEX ix_index_reconciliation_status ON index_reconciliation_events(outcome, occurred_at DESC);
CREATE INDEX ix_model_invocations_created ON model_invocations(created_at DESC, status);
CREATE INDEX ix_messages_created ON messages(created_at DESC);
CREATE INDEX ix_risk_runs_status_created ON risk_runs(status, created_at DESC);
CREATE INDEX ix_valuation_runs_status_created ON valuation_runs(valuation_status, created_at DESC);
CREATE INDEX ix_screen_runs_screen_created ON screen_runs(saved_screen_id, created_at DESC);
CREATE INDEX ix_alert_events_time ON alert_events(triggered_at DESC, event_status);
CREATE INDEX ix_signals_instrument_time ON signals(instrument_id, generated_at DESC);
CREATE INDEX ix_backtest_runs_strategy_created ON backtest_runs(strategy_version_id, created_at DESC);
CREATE INDEX ix_reports_owner_created ON reports(workspace_id, owner_user_id, created_at DESC);
CREATE INDEX ix_data_export_requests_status ON data_export_requests(request_status, requested_at DESC);
CREATE INDEX ix_account_deletion_requests_status ON account_deletion_requests(request_status, requested_at DESC);
CREATE INDEX ix_valuation_comparisons_owner ON valuation_run_comparisons(workspace_id, owner_user_id, created_at DESC);

COMMIT;

-- NOTE: No production provider secrets, user-defined roles, currency rows, market rows, or
-- permission seeds are inserted here. Seed these via migrations/fixtures for the deployment.
-- NOTE: Price history is designed for daily data at launch. Partition price_bars and large
-- time-series tables by time when measured data volume justifies it; keep stable IDs and snapshot lineage.
