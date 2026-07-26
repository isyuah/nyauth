CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255),
    email_verified_at TIMESTAMPTZ,
    password_hash TEXT,
    password_changed_at TIMESTAMPTZ,
    display_name VARCHAR(128),
    avatar_url TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    auth_version BIGINT NOT NULL DEFAULT 1,
    session_version BIGINT NOT NULL DEFAULT 1,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    last_authenticated_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    last_login_ip VARCHAR(45),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'suspended', 'pending')),
    CONSTRAINT users_role_valid CHECK (role IN ('user', 'admin')),
    CONSTRAINT users_auth_version_positive CHECK (auth_version > 0),
    CONSTRAINT users_session_version_positive CHECK (session_version > 0),
    CONSTRAINT users_verified_email_present CHECK (email_verified_at IS NULL OR email IS NOT NULL),
    CONSTRAINT users_password_timestamp_consistent CHECK (password_hash IS NOT NULL OR password_changed_at IS NULL),
    CONSTRAINT users_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE UNIQUE INDEX idx_users_email_normalized ON users (LOWER(BTRIM(email))) WHERE email IS NOT NULL;
CREATE INDEX idx_users_status ON users (status);
CREATE INDEX idx_users_role ON users (role);

CREATE TABLE oauth_clients (
    id VARCHAR(64) PRIMARY KEY,
    secret_hash TEXT,
    secret_hint VARCHAR(16),
    secret_version BIGINT NOT NULL DEFAULT 0,
    secret_rotated_at TIMESTAMPTZ,
    secret_last_used_at TIMESTAMPTZ,
    name VARCHAR(128) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grants TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    owner_id UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_clients_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT oauth_clients_redirect_uris_not_empty CHECK (cardinality(redirect_uris) > 0),
    CONSTRAINT oauth_clients_redirect_uris_no_null CHECK (array_position(redirect_uris, NULL) IS NULL),
    CONSTRAINT oauth_clients_post_logout_redirect_uris_no_null CHECK (array_position(post_logout_redirect_uris, NULL) IS NULL),
    CONSTRAINT oauth_clients_grants_not_empty CHECK (cardinality(grants) > 0),
    CONSTRAINT oauth_clients_grants_no_null CHECK (array_position(grants, NULL) IS NULL),
    CONSTRAINT oauth_clients_scopes_no_null CHECK (array_position(scopes, NULL) IS NULL),
    CONSTRAINT oauth_clients_secret_kind_consistent CHECK (
        (is_public AND secret_hash IS NULL AND secret_hint IS NULL AND secret_version = 0 AND secret_rotated_at IS NULL)
        OR (NOT is_public AND secret_hash IS NOT NULL AND secret_version > 0 AND secret_rotated_at IS NOT NULL)
    ),
    CONSTRAINT oauth_clients_secret_version_nonnegative CHECK (secret_version >= 0),
    CONSTRAINT oauth_clients_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX idx_oauth_clients_name ON oauth_clients (name);
CREATE INDEX idx_oauth_clients_owner ON oauth_clients (owner_id) WHERE owner_id IS NOT NULL;

CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(64) NOT NULL UNIQUE,
    type VARCHAR(32) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    discovery_url TEXT,
    authorization_url TEXT,
    token_url TEXT,
    userinfo_url TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    revision BIGINT NOT NULL DEFAULT 1,
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_providers_name_valid CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'),
    CONSTRAINT oauth_providers_type_valid CHECK (type IN ('github', 'google', 'generic')),
    CONSTRAINT oauth_providers_scopes_no_null CHECK (array_position(scopes, NULL) IS NULL),
    CONSTRAINT oauth_providers_generic_discovery_required CHECK (type <> 'generic' OR (discovery_url IS NOT NULL AND btrim(discovery_url) <> '')),
    CONSTRAINT oauth_providers_revision_positive CHECK (revision > 0),
    CONSTRAINT oauth_providers_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX idx_oauth_providers_enabled ON oauth_providers (enabled) WHERE enabled = TRUE;

CREATE TABLE identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider VARCHAR(64) NOT NULL,
    external_id VARCHAR(255) NOT NULL,
    external_username VARCHAR(255),
    external_email VARCHAR(255),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT identities_provider_not_blank CHECK (btrim(provider) <> ''),
    CONSTRAINT identities_external_id_not_blank CHECK (btrim(external_id) <> ''),
    CONSTRAINT identities_external_unique UNIQUE (provider, external_id),
    CONSTRAINT identities_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX idx_identities_user_id ON identities (user_id);

CREATE TABLE jwk_keys (
    kid VARCHAR(64) PRIMARY KEY,
    key_type VARCHAR(16) NOT NULL,
    usage VARCHAR(16) NOT NULL,
    algorithm VARCHAR(16) NOT NULL,
    encrypted_private_key TEXT,
    public_key TEXT NOT NULL,
    status VARCHAR(16) NOT NULL,
    signing_started_at TIMESTAMPTZ NOT NULL,
    verify_until TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT jwk_keys_status_valid CHECK (status IN ('signing', 'verification', 'retired')),
    CONSTRAINT jwk_keys_private_key_lifecycle CHECK (
        (status = 'signing' AND encrypted_private_key IS NOT NULL)
        OR (status IN ('verification', 'retired') AND encrypted_private_key IS NULL)
    ),
    CONSTRAINT jwk_keys_verify_window_valid CHECK (verify_until > signing_started_at)
);
CREATE UNIQUE INDEX idx_jwk_keys_single_signing ON jwk_keys ((status)) WHERE status = 'signing';
CREATE INDEX idx_jwk_keys_verification ON jwk_keys (verify_until) WHERE status IN ('signing', 'verification');

CREATE TABLE oauth_authorizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_authorizations_user_client_unique UNIQUE (user_id, client_id),
    CONSTRAINT oauth_authorizations_scopes_no_null CHECK (array_position(scopes, NULL) IS NULL)
);
CREATE INDEX idx_oauth_authorizations_user_active ON oauth_authorizations (user_id, updated_at DESC) WHERE revoked_at IS NULL;

CREATE TABLE account_action_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    action VARCHAR(32) NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    payload_ciphertext TEXT NOT NULL,
    requested_ip INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT account_action_tokens_action_valid CHECK (action IN ('password_reset', 'email_verification', 'email_change')),
    CONSTRAINT account_action_tokens_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT account_action_tokens_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT account_action_tokens_terminal_state CHECK (consumed_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX idx_account_action_tokens_user_active ON account_action_tokens (user_id, action, created_at DESC)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX idx_account_action_tokens_expiry ON account_action_tokens (expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE email_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message_type VARCHAR(64) NOT NULL,
    recipient_hash BYTEA NOT NULL,
    encrypted_message TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(128),
    sent_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT email_outbox_message_type_not_blank CHECK (btrim(message_type) <> ''),
    CONSTRAINT email_outbox_recipient_hash_length CHECK (octet_length(recipient_hash) = 32),
    CONSTRAINT email_outbox_status_valid CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'expired')),
    CONSTRAINT email_outbox_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT email_outbox_expiry_valid CHECK (expires_at > created_at)
);
CREATE INDEX idx_email_outbox_dispatch ON email_outbox (available_at, created_at)
    WHERE status IN ('pending', 'failed');
CREATE INDEX idx_email_outbox_user_created ON email_outbox (user_id, created_at DESC);

CREATE TABLE audit_logs (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    event VARCHAR(64) NOT NULL,
    actor_id UUID,
    actor_name VARCHAR(128),
    target_type VARCHAR(32),
    target_id VARCHAR(128),
    ip_address VARCHAR(255),
    user_agent TEXT,
    result VARCHAR(16) NOT NULL DEFAULT 'success',
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',
    details JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, created_at),
    CONSTRAINT audit_logs_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT audit_logs_risk_level_valid CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT audit_logs_details_object CHECK (jsonb_typeof(details) = 'object')
) PARTITION BY RANGE (created_at);

-- Keep a generous rolling partition window in the baseline so serving traffic
-- never depends on application-side DDL. The migration/maintenance command,
-- which runs with the separate migration account, extends this window.
DO $$
DECLARE
    partition_start TIMESTAMPTZ :=
        (date_trunc('month', CURRENT_TIMESTAMP AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') - INTERVAL '1 month';
    partition_end TIMESTAMPTZ;
    partition_name TEXT;
    month_offset INTEGER;
BEGIN
    FOR month_offset IN 0..37 LOOP
        partition_end := partition_start + INTERVAL '1 month';
        partition_name := 'audit_logs_' || to_char(partition_start AT TIME ZONE 'UTC', 'YYYY_MM');
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF audit_logs FOR VALUES FROM (%L) TO (%L)',
            partition_name,
            partition_start,
            partition_end
        );
        partition_start := partition_end;
    END LOOP;
END $$;
CREATE INDEX idx_audit_logs_event_created ON audit_logs (event, created_at DESC);
CREATE INDEX idx_audit_logs_actor_created ON audit_logs (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_target ON audit_logs (target_type, target_id) WHERE target_type IS NOT NULL;

-- Authentication-path audit events are first written here in the same
-- transaction as their state change, then delivered to audit_logs.
CREATE TABLE audit_event_outbox (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event VARCHAR(64) NOT NULL,
    aggregate_type VARCHAR(32) NOT NULL,
    aggregate_id VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(128),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_event_outbox_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT audit_event_outbox_status_valid CHECK (status IN ('pending', 'processing', 'processed', 'failed')),
    CONSTRAINT audit_event_outbox_attempt_count_nonnegative CHECK (attempt_count >= 0)
);

-- Dashboard reads are served from these bounded aggregates. Application
-- instances refresh them under a PostgreSQL advisory lock, so an admin page
-- request never performs full-table counts over security data.
CREATE TABLE system_stats_snapshot (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    user_count BIGINT NOT NULL DEFAULT 0,
    app_count BIGINT NOT NULL DEFAULT 0,
    active_sessions BIGINT NOT NULL DEFAULT 0,
    login_count_7d BIGINT NOT NULL DEFAULT 0,
    failed_logins_7d BIGINT NOT NULL DEFAULT 0,
    refreshed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT system_stats_snapshot_singleton CHECK (singleton),
    CONSTRAINT system_stats_snapshot_nonnegative CHECK (
        user_count >= 0 AND app_count >= 0 AND active_sessions >= 0
        AND login_count_7d >= 0 AND failed_logins_7d >= 0
    )
);

CREATE TABLE login_stats_daily (
    day DATE PRIMARY KEY,
    successful_logins BIGINT NOT NULL DEFAULT 0,
    failed_logins BIGINT NOT NULL DEFAULT 0,
    refreshed_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT login_stats_daily_nonnegative CHECK (
        successful_logins >= 0 AND failed_logins >= 0
    )
);
CREATE INDEX idx_audit_event_outbox_dispatch ON audit_event_outbox (available_at, created_at)
    WHERE status IN ('pending', 'failed');
