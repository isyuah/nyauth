-- Nyauth 0.3.0-rc.1 release baseline.

-- Fresh databases only; earlier development schemas are intentionally incompatible.

-- Folded from 000001_baseline.up.sql
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

-- Folded from 000002_runtime_settings.up.sql
-- Operational settings editable at runtime from the admin UI. Deployment-shape
-- configuration (issuer, keys, connections) stays in the config file on purpose.
CREATE TABLE runtime_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Folded from 000003_client_access_policy.up.sql
-- Per-client access policy: which users may complete an OAuth flow against a
-- client. 'open' preserves the previous behavior for existing clients.
ALTER TABLE oauth_clients ADD COLUMN access_policy TEXT NOT NULL DEFAULT 'open'
    CONSTRAINT oauth_clients_access_policy_valid CHECK (access_policy IN ('open', 'admins_only', 'allowlist'));

CREATE TABLE client_access_users (
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, user_id)
);
CREATE INDEX idx_client_access_users_user ON client_access_users(user_id);

-- Folded from 000004_invites.up.sql
-- Invitation codes and durable self-registration lifecycle state.
CREATE TABLE invites (
    id UUID PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    note TEXT NOT NULL DEFAULT '',
    max_uses INT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT invites_max_uses_positive CHECK (max_uses >= 1),
    CONSTRAINT invites_expiry_valid CHECK (expires_at > created_at)
);
CREATE INDEX idx_invites_created_at ON invites (created_at DESC);

CREATE TABLE self_registrations (
    id UUID PRIMARY KEY,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE SET NULL,
    invite_id UUID REFERENCES invites(id) ON DELETE RESTRICT,
    status VARCHAR(16) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    release_reason VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT self_registrations_status_valid CHECK (status IN ('pending', 'completed', 'released')),
    CONSTRAINT self_registrations_expiry_valid CHECK (expires_at > created_at),
    CONSTRAINT self_registrations_terminal_state_valid CHECK (
        (status = 'pending' AND user_id IS NOT NULL AND completed_at IS NULL AND released_at IS NULL AND release_reason IS NULL)
        OR (status = 'completed' AND completed_at IS NOT NULL AND released_at IS NULL AND release_reason IS NULL)
        OR (status = 'released' AND completed_at IS NULL AND released_at IS NOT NULL AND release_reason IS NOT NULL)
    )
);
CREATE INDEX idx_self_registrations_invite_status ON self_registrations (invite_id, status)
    WHERE invite_id IS NOT NULL;
CREATE INDEX idx_self_registrations_pending_expiry ON self_registrations (expires_at, id)
    WHERE status = 'pending';

-- Folded from 000005_runtime_mail.up.sql
-- Immutable SMTP configuration history and HA-shared runtime mail state.
ALTER TABLE email_outbox DROP CONSTRAINT email_outbox_status_valid;
ALTER TABLE email_outbox ADD CONSTRAINT email_outbox_status_valid
    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'expired', 'rejected'));
-- Schema 4 persisted transport text verbatim. It may contain recipient
-- addresses or SMTP server responses, so do not carry it into the runtime-mail
-- model where all new failures use machine-safe summaries.
UPDATE email_outbox SET last_error=NULL WHERE last_error IS NOT NULL;
CREATE INDEX idx_email_outbox_active_expiry
    ON email_outbox (expires_at, id)
    WHERE status IN ('pending', 'failed', 'sending');

CREATE TABLE mail_config_versions (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    host VARCHAR(253) NOT NULL,
    port INTEGER NOT NULL,
    username VARCHAR(320) NOT NULL DEFAULT '',
    password_ciphertext TEXT,
    tls_mode VARCHAR(16) NOT NULL,
    from_address VARCHAR(320) NOT NULL,
    from_name VARCHAR(255) NOT NULL DEFAULT '',
    public_base_url TEXT NOT NULL,
    connect_timeout_ms INTEGER NOT NULL,
    send_timeout_ms INTEGER NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_config_versions_host_valid CHECK (
        btrim(host) <> '' AND host = btrim(host)
        AND position(chr(10) IN host) = 0 AND position(chr(13) IN host) = 0
    ),
    CONSTRAINT mail_config_versions_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT mail_config_versions_username_valid CHECK (
        username = btrim(username)
        AND position(chr(10) IN username) = 0 AND position(chr(13) IN username) = 0
    ),
    CONSTRAINT mail_config_versions_password_valid CHECK (
        password_ciphertext IS NULL OR btrim(password_ciphertext) <> ''
    ),
    CONSTRAINT mail_config_versions_tls_mode_valid CHECK (
        tls_mode IN ('starttls', 'implicit', 'plain')
    ),
    CONSTRAINT mail_config_versions_from_address_valid CHECK (
        btrim(from_address) <> '' AND from_address = btrim(from_address)
        AND position(chr(10) IN from_address) = 0 AND position(chr(13) IN from_address) = 0
    ),
    CONSTRAINT mail_config_versions_from_name_valid CHECK (
        from_name = btrim(from_name)
        AND position(chr(10) IN from_name) = 0 AND position(chr(13) IN from_name) = 0
    ),
    CONSTRAINT mail_config_versions_public_base_url_valid CHECK (
        length(public_base_url) BETWEEN 1 AND 2048
        AND public_base_url = btrim(public_base_url)
        AND public_base_url ~ '^https?://'
        AND position(chr(10) IN public_base_url) = 0
        AND position(chr(13) IN public_base_url) = 0
    ),
    CONSTRAINT mail_config_versions_connect_timeout_valid CHECK (
        connect_timeout_ms BETWEEN 100 AND 300000
    ),
    CONSTRAINT mail_config_versions_send_timeout_valid CHECK (
        send_timeout_ms BETWEEN 100 AND 600000
    )
);

CREATE TABLE mail_config_tests (
    id UUID PRIMARY KEY,
    version_id UUID NOT NULL REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    recipient_hash BYTEA NOT NULL,
    result VARCHAR(16) NOT NULL,
    error_category VARCHAR(32),
    tested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_config_tests_recipient_hash_length CHECK (octet_length(recipient_hash) = 32),
    CONSTRAINT mail_config_tests_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT mail_config_tests_result_category_consistent CHECK (
        (result = 'success' AND error_category IS NULL)
        OR (
            result = 'failure'
            AND error_category IN (
                'configuration', 'authentication', 'tls', 'transport', 'recipient', 'unknown'
            )
        )
    )
);
CREATE INDEX idx_mail_config_tests_recent_success
    ON mail_config_tests (version_id, created_at DESC)
    WHERE result = 'success';

CREATE TABLE mail_runtime_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mode VARCHAR(16) NOT NULL DEFAULT 'fallback',
    active_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    candidate_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    previous_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0,
    circuit_state VARCHAR(16) NOT NULL DEFAULT 'closed',
    circuit_open_reason VARCHAR(64),
    circuit_open_category VARCHAR(32),
    circuit_opened_at TIMESTAMPTZ,
    transport_failure_window_started_at TIMESTAMPTZ,
    transport_failure_count INTEGER NOT NULL DEFAULT 0,
    next_probe_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_runtime_state_singleton CHECK (singleton),
    CONSTRAINT mail_runtime_state_mode_valid CHECK (mode IN ('fallback', 'active', 'disabled')),
    CONSTRAINT mail_runtime_state_revision_nonnegative CHECK (revision >= 0),
    CONSTRAINT mail_runtime_state_mode_consistent CHECK (
        (mode = 'fallback' AND active_version_id IS NULL AND previous_version_id IS NULL)
        OR (mode = 'active' AND active_version_id IS NOT NULL)
        OR (mode = 'disabled' AND active_version_id IS NULL)
    ),
    CONSTRAINT mail_runtime_state_version_pointers_distinct CHECK (
        (candidate_version_id IS NULL OR active_version_id IS NULL OR candidate_version_id <> active_version_id)
        AND (candidate_version_id IS NULL OR previous_version_id IS NULL OR candidate_version_id <> previous_version_id)
        AND (active_version_id IS NULL OR previous_version_id IS NULL OR active_version_id <> previous_version_id)
    ),
    CONSTRAINT mail_runtime_state_circuit_state_valid CHECK (circuit_state IN ('closed', 'open')),
    CONSTRAINT mail_runtime_state_transport_count_nonnegative CHECK (transport_failure_count >= 0),
    CONSTRAINT mail_runtime_state_transport_window_consistent CHECK (
        (transport_failure_count = 0 AND transport_failure_window_started_at IS NULL)
        OR (transport_failure_count > 0 AND transport_failure_window_started_at IS NOT NULL)
    ),
    CONSTRAINT mail_runtime_state_circuit_consistent CHECK (
        (
            circuit_state = 'closed'
            AND circuit_open_reason IS NULL
            AND circuit_open_category IS NULL
            AND circuit_opened_at IS NULL
            AND next_probe_at IS NULL
        )
        OR (
            circuit_state = 'open'
            AND btrim(circuit_open_reason) <> ''
            AND circuit_open_category IN ('configuration', 'authentication', 'tls', 'transport')
            AND circuit_opened_at IS NOT NULL
            AND next_probe_at IS NOT NULL
            AND next_probe_at > circuit_opened_at
        )
    ),
    CONSTRAINT mail_runtime_state_open_transport_consistent CHECK (
        circuit_state <> 'open'
        OR circuit_open_category <> 'transport'
        OR transport_failure_count >= 3
    ),
    CONSTRAINT mail_runtime_state_open_permanent_consistent CHECK (
        circuit_state <> 'open'
        OR circuit_open_category = 'transport'
        OR (transport_failure_count = 0 AND transport_failure_window_started_at IS NULL)
    )
);

INSERT INTO mail_runtime_state (singleton) VALUES (TRUE);

-- Configuration versions and test evidence are append-only even though the
-- runtime role receives generic table privileges after migration.
CREATE FUNCTION protect_mail_config_version_history() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.created_by IS NOT NULL
       AND NEW.created_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.host IS NOT DISTINCT FROM OLD.host
       AND NEW.port IS NOT DISTINCT FROM OLD.port
       AND NEW.username IS NOT DISTINCT FROM OLD.username
       AND NEW.password_ciphertext IS NOT DISTINCT FROM OLD.password_ciphertext
       AND NEW.tls_mode IS NOT DISTINCT FROM OLD.tls_mode
       AND NEW.from_address IS NOT DISTINCT FROM OLD.from_address
       AND NEW.from_name IS NOT DISTINCT FROM OLD.from_name
       AND NEW.public_base_url IS NOT DISTINCT FROM OLD.public_base_url
       AND NEW.connect_timeout_ms IS NOT DISTINCT FROM OLD.connect_timeout_ms
       AND NEW.send_timeout_ms IS NOT DISTINCT FROM OLD.send_timeout_ms
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION protect_mail_config_test_history() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.tested_by IS NOT NULL
       AND NEW.tested_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.version_id IS NOT DISTINCT FROM OLD.version_id
       AND NEW.recipient_hash IS NOT DISTINCT FROM OLD.recipient_hash
       AND NEW.result IS NOT DISTINCT FROM OLD.result
       AND NEW.error_category IS NOT DISTINCT FROM OLD.error_category
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER mail_config_versions_append_only
    BEFORE UPDATE OR DELETE ON mail_config_versions
    FOR EACH ROW EXECUTE FUNCTION protect_mail_config_version_history();

CREATE TRIGGER mail_config_tests_append_only
    BEFORE UPDATE OR DELETE ON mail_config_tests
    FOR EACH ROW EXECUTE FUNCTION protect_mail_config_test_history();

-- Folded from 000006_registration_mail_stats.up.sql
-- Low-cardinality registration and email observability aggregates.
CREATE TABLE registration_stats_daily (
    day DATE PRIMARY KEY,
    registrations_started BIGINT NOT NULL DEFAULT 0,
    registrations_completed BIGINT NOT NULL DEFAULT 0,
    registrations_expired BIGINT NOT NULL DEFAULT 0,
    invites_reserved BIGINT NOT NULL DEFAULT 0,
    invites_consumed BIGINT NOT NULL DEFAULT 0,
    invites_released BIGINT NOT NULL DEFAULT 0,
    cohort_started BIGINT NOT NULL DEFAULT 0,
    cohort_completed BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT registration_stats_daily_nonnegative CHECK (
        registrations_started >= 0
        AND registrations_completed >= 0
        AND registrations_expired >= 0
        AND invites_reserved >= 0
        AND invites_consumed >= 0
        AND invites_released >= 0
        AND cohort_started >= 0
        AND cohort_completed >= 0
    )
);

CREATE TABLE mail_stats_daily (
    day DATE PRIMARY KEY,
    enqueued BIGINT NOT NULL DEFAULT 0,
    sent BIGINT NOT NULL DEFAULT 0,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    rejected BIGINT NOT NULL DEFAULT 0,
    expired BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_stats_daily_nonnegative CHECK (
        enqueued >= 0
        AND sent >= 0
        AND failed_attempts >= 0
        AND rejected >= 0
        AND expired >= 0
        AND rejected <= failed_attempts
    )
);

-- A minute bucket keeps the rolling 24-hour failure count accurate to within
-- one minute without retaining one row per delivery attempt.
CREATE TABLE mail_failure_stats_minute (
    minute TIMESTAMPTZ PRIMARY KEY,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_failure_stats_minute_aligned CHECK (
        minute = date_trunc('minute', minute)
    ),
    CONSTRAINT mail_failure_stats_minute_nonnegative CHECK (failed_attempts >= 0)
);

-- Schema 5 has only final outbox state and cannot reconstruct historical
-- delivery attempts after retries or user deletion. Expose this boundary
-- instead of presenting unavailable pre-migration history as observed zeros.
CREATE TABLE stats_observability_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mail_stats_available_from TIMESTAMPTZ NOT NULL,
    CONSTRAINT stats_observability_state_singleton CHECK (singleton)
);
INSERT INTO stats_observability_state (singleton, mail_stats_available_from)
VALUES (TRUE, NOW());

ALTER TABLE system_stats_snapshot
    ADD COLUMN pending_registrations BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN completed_registrations_7d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN registration_started_30d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN registration_completed_30d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN mail_backlog BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN mail_failures_24h BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN smtp_circuit_state VARCHAR(16) NOT NULL DEFAULT 'closed';

ALTER TABLE system_stats_snapshot
    ADD CONSTRAINT system_stats_snapshot_registration_mail_nonnegative CHECK (
        pending_registrations >= 0
        AND completed_registrations_7d >= 0
        AND registration_started_30d >= 0
        AND registration_completed_30d >= 0
        AND registration_completed_30d <= registration_started_30d
        AND mail_backlog >= 0
        AND mail_failures_24h >= 0
    ),
    ADD CONSTRAINT system_stats_snapshot_smtp_circuit_valid CHECK (
        smtp_circuit_state IN ('closed', 'open')
    );

CREATE INDEX idx_email_outbox_active_created
    ON email_outbox (created_at)
    WHERE status IN ('pending', 'failed', 'sending');

-- Registration lifecycle rows retain enough timestamps to backfill their
-- event and cohort aggregates exactly. Mail delivery attempts do not, so mail
-- aggregates intentionally begin at stats_observability_state's timestamp.
INSERT INTO registration_stats_daily (
    day, registrations_started, invites_reserved, cohort_started, updated_at
)
SELECT
    (created_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (
        WHERE invite_id IS NOT NULL
          AND (status IN ('pending', 'released') OR completed_at > created_at)
    ),
    COUNT(*),
    NOW()
FROM self_registrations
GROUP BY (created_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_started = registration_stats_daily.registrations_started + EXCLUDED.registrations_started,
    invites_reserved = registration_stats_daily.invites_reserved + EXCLUDED.invites_reserved,
    cohort_started = registration_stats_daily.cohort_started + EXCLUDED.cohort_started,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (
    day, registrations_completed, invites_consumed, updated_at
)
SELECT
    (completed_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (WHERE invite_id IS NOT NULL),
    NOW()
FROM self_registrations
WHERE status = 'completed'
GROUP BY (completed_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_completed = registration_stats_daily.registrations_completed + EXCLUDED.registrations_completed,
    invites_consumed = registration_stats_daily.invites_consumed + EXCLUDED.invites_consumed,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (day, cohort_completed, updated_at)
SELECT
    (created_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    NOW()
FROM self_registrations
WHERE status = 'completed'
GROUP BY (created_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    cohort_completed = registration_stats_daily.cohort_completed + EXCLUDED.cohort_completed,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (
    day, registrations_expired, invites_released, updated_at
)
SELECT
    (expires_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (WHERE invite_id IS NOT NULL),
    NOW()
FROM self_registrations
WHERE status = 'released' AND release_reason = 'expired'
GROUP BY (expires_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_expired = registration_stats_daily.registrations_expired + EXCLUDED.registrations_expired,
    invites_released = registration_stats_daily.invites_released + EXCLUDED.invites_released,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (day, invites_released, updated_at)
SELECT
    (released_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    NOW()
FROM self_registrations
WHERE status = 'released'
  AND release_reason <> 'expired'
  AND invite_id IS NOT NULL
GROUP BY (released_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    invites_released = registration_stats_daily.invites_released + EXCLUDED.invites_released,
    updated_at = EXCLUDED.updated_at;

-- Folded from 000007_totp_mfa.up.sql
-- TOTP credentials and one-time recovery codes.
-- Secrets are encrypted by the application with the deployment master key;
-- recovery codes are stored only as Argon2id hashes.
CREATE TABLE user_totp_credentials (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext TEXT NOT NULL,
    confirmed_at TIMESTAMPTZ,
    last_used_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_totp_secret_not_blank CHECK (btrim(secret_ciphertext) <> ''),
    CONSTRAINT user_totp_step_requires_confirmation CHECK (
        last_used_step IS NULL OR confirmed_at IS NOT NULL
    )
);

CREATE TABLE user_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES user_totp_credentials(user_id) ON DELETE CASCADE,
    selector_hash BYTEA NOT NULL,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_recovery_code_selector_length CHECK (octet_length(selector_hash) = 32),
    CONSTRAINT user_recovery_code_hash_not_blank CHECK (btrim(code_hash) <> ''),
    CONSTRAINT user_recovery_code_selector_unique UNIQUE (user_id, selector_hash)
);

CREATE INDEX idx_user_recovery_codes_available
    ON user_recovery_codes (user_id, created_at)
    WHERE used_at IS NULL;

-- Folded from 000008_passkeys.up.sql
-- WebAuthn user handles are opaque, stable identifiers shared by every
-- credential owned by one account. They deliberately remain separate from
-- application user UUIDs and survive deleting the user's last passkey.
CREATE TABLE user_passkey_handles (
    rp_id TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_handle BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_passkey_handles_pkey PRIMARY KEY (rp_id, user_id),
    CONSTRAINT user_passkey_handle_unique UNIQUE (rp_id, user_handle),
    CONSTRAINT user_passkey_rp_id_not_blank CHECK (btrim(rp_id) <> ''),
    CONSTRAINT user_passkey_handle_length CHECK (octet_length(user_handle) = 32)
);

-- The complete go-webauthn Credential record is envelope-encrypted by the
-- application. Credential IDs remain indexable for discoverable login; the
-- remaining columns are non-secret metadata used for management UI, risk
-- reporting, and enforcing monotonic assertion state.
CREATE TABLE user_passkey_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rp_id TEXT NOT NULL,
    user_id UUID NOT NULL,
    credential_id BYTEA NOT NULL,
    credential_ciphertext TEXT NOT NULL,
    name TEXT NOT NULL,
    transports TEXT[] NOT NULL DEFAULT '{}',
    aaguid BYTEA,
    sign_count BIGINT NOT NULL DEFAULT 0,
    clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
    attachment TEXT NOT NULL DEFAULT '',
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    CONSTRAINT user_passkey_credentials_owner_fk FOREIGN KEY (rp_id, user_id)
        REFERENCES user_passkey_handles(rp_id, user_id) ON DELETE CASCADE,
    CONSTRAINT user_passkey_credential_unique UNIQUE (rp_id, credential_id),
    CONSTRAINT user_passkey_credential_rp_id_not_blank CHECK (btrim(rp_id) <> ''),
    CONSTRAINT user_passkey_credential_id_length CHECK (
        octet_length(credential_id) BETWEEN 1 AND 1024
    ),
    CONSTRAINT user_passkey_ciphertext_not_blank CHECK (btrim(credential_ciphertext) <> ''),
    CONSTRAINT user_passkey_name_length CHECK (char_length(name) BETWEEN 1 AND 64),
    CONSTRAINT user_passkey_aaguid_length CHECK (
        aaguid IS NULL OR octet_length(aaguid) = 16
    ),
    CONSTRAINT user_passkey_sign_count_range CHECK (
        sign_count BETWEEN 0 AND 4294967295
    ),
    CONSTRAINT user_passkey_backup_state_valid CHECK (
        NOT backup_state OR backup_eligible
    )
);

CREATE INDEX idx_user_passkey_credentials_user
    ON user_passkey_credentials (rp_id, user_id, created_at, id);

CREATE INDEX idx_user_passkey_credentials_clone_warning
    ON user_passkey_credentials (rp_id, user_id, last_used_at)
    WHERE clone_warning;

-- Folded from 000009_avatar_media.up.sql
CREATE TABLE user_avatars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    storage_backend TEXT NOT NULL,
    object_prefix TEXT NOT NULL,
    variants JSONB NOT NULL DEFAULT '[]'::JSONB,
    content_sha256 BYTEA NOT NULL,
    original_media_type TEXT NOT NULL,
    original_width INTEGER NOT NULL,
    original_height INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    replaced_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    storage_deleted_at TIMESTAMPTZ,
    cleanup_claimed_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT user_avatars_source_valid CHECK (source IN ('user_upload', 'admin_upload', 'provider_import')),
    CONSTRAINT user_avatars_status_valid CHECK (status IN ('staging', 'active', 'replaced', 'failed', 'deleted')),
    CONSTRAINT user_avatars_storage_backend_valid CHECK (storage_backend IN ('local', 's3')),
    CONSTRAINT user_avatars_object_prefix_not_blank CHECK (btrim(object_prefix) <> ''),
    CONSTRAINT user_avatars_variants_array CHECK (jsonb_typeof(variants) = 'array'),
    CONSTRAINT user_avatars_hash_length CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT user_avatars_original_media_type_valid CHECK (original_media_type IN ('image/jpeg', 'image/png', 'image/webp')),
    CONSTRAINT user_avatars_dimensions_positive CHECK (
        original_width > 0 AND original_height > 0
    ),
    CONSTRAINT user_avatars_activation_consistent CHECK (
        (status = 'active') = (activated_at IS NOT NULL AND replaced_at IS NULL AND deleted_at IS NULL AND failed_at IS NULL)
    ),
    CONSTRAINT user_avatars_replaced_consistent CHECK (
        (status <> 'replaced') OR (replaced_at IS NOT NULL)
    ),
    CONSTRAINT user_avatars_deleted_consistent CHECK (
        (status <> 'deleted') OR (deleted_at IS NOT NULL)
    ),
    CONSTRAINT user_avatars_failed_consistent CHECK (
        (status <> 'failed') OR (failed_at IS NOT NULL AND last_error IS NOT NULL AND btrim(last_error) <> '')
    )
);

CREATE UNIQUE INDEX idx_user_avatars_one_active
    ON user_avatars (user_id)
    WHERE status = 'active';

CREATE INDEX idx_user_avatars_user_created
    ON user_avatars (user_id, created_at DESC, id);

CREATE INDEX idx_user_avatars_cleanup
    ON user_avatars (updated_at, id)
    WHERE storage_deleted_at IS NULL;

ALTER TABLE users ADD COLUMN current_avatar_id UUID;

ALTER TABLE users
    ADD CONSTRAINT users_current_avatar_fk
    FOREIGN KEY (current_avatar_id)
    REFERENCES user_avatars(id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE users DROP COLUMN avatar_url;

CREATE TABLE provider_avatar_import_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_avatar_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    completed_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT provider_avatar_jobs_url_lifecycle CHECK (
        (status IN ('pending', 'processing') AND btrim(encrypted_avatar_url) <> '') OR
        (status IN ('completed', 'failed') AND encrypted_avatar_url = '')
    ),
    CONSTRAINT provider_avatar_jobs_status_valid CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT provider_avatar_jobs_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT provider_avatar_jobs_locked_consistent CHECK (
        (status = 'processing') = (locked_at IS NOT NULL AND locked_by IS NOT NULL AND btrim(locked_by) <> '')
    ),
    CONSTRAINT provider_avatar_jobs_completed_consistent CHECK (
        (status <> 'completed') OR (completed_at IS NOT NULL AND encrypted_avatar_url = '')
    ),
    CONSTRAINT provider_avatar_jobs_failed_consistent CHECK (
        (status <> 'failed') OR (failed_at IS NOT NULL AND encrypted_avatar_url = '' AND last_error IS NOT NULL AND btrim(last_error) <> '')
    )
);

CREATE INDEX idx_provider_avatar_jobs_claim
    ON provider_avatar_import_jobs (available_at, created_at, id)
    WHERE status = 'pending';

CREATE INDEX idx_provider_avatar_jobs_user
    ON provider_avatar_import_jobs (user_id, created_at DESC, id);

ALTER TABLE oauth_providers ADD COLUMN import_avatar BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE oauth_providers ADD COLUMN avatar_allowed_hosts TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_avatar_allowed_hosts_no_null
    CHECK (array_position(avatar_allowed_hosts, NULL) IS NULL);

ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_generic_avatar_allowlist_required
    CHECK (type <> 'generic' OR NOT import_avatar OR cardinality(avatar_allowed_hosts) > 0);

-- Folded from 000010_admin_user_insights.up.sql
-- Durable user creation provenance and indexes supporting exact user activity.
ALTER TABLE users
    ADD COLUMN creation_source VARCHAR(32),
    ADD COLUMN created_by UUID;

-- self_registrations is the only authoritative historical source marker.
-- Existing identities may have been bound after a local account was created,
-- so every other pre-migration account remains explicitly legacy.
UPDATE users AS subject
SET creation_source = 'self_registration'
WHERE EXISTS (
    SELECT 1
    FROM self_registrations AS registration
    WHERE registration.user_id = subject.id
);

UPDATE users
SET creation_source = 'legacy'
WHERE creation_source IS NULL;

ALTER TABLE users
    ALTER COLUMN creation_source SET NOT NULL,
    ADD CONSTRAINT users_creation_source_valid CHECK (
        creation_source IN ('bootstrap', 'admin', 'self_registration', 'provider', 'legacy')
    ),
    ADD CONSTRAINT users_created_by_source_valid CHECK (
        created_by IS NULL OR creation_source = 'admin'
    ),
    ADD CONSTRAINT users_created_by_not_self CHECK (
        created_by IS NULL OR created_by <> id
    ),
    ADD CONSTRAINT users_created_by_fkey FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_users_created_by
    ON users (created_by)
    WHERE created_by IS NOT NULL;

CREATE INDEX idx_audit_logs_target_created
    ON audit_logs (target_type, target_id, created_at DESC)
    WHERE target_type IS NOT NULL AND target_id IS NOT NULL;
