CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(64) NOT NULL UNIQUE,
    email VARCHAR(255),
    password_hash TEXT,
    display_name VARCHAR(128),
    avatar_url TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    auth_version BIGINT NOT NULL DEFAULT 1,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    last_login_ip VARCHAR(45),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_status_valid CHECK (status IN ('active', 'suspended', 'pending')),
    CONSTRAINT users_role_valid CHECK (role IN ('user', 'admin')),
    CONSTRAINT users_email_unique UNIQUE (email),
    CONSTRAINT users_auth_version_positive CHECK (auth_version > 0),
    CONSTRAINT users_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX idx_users_status ON users (status);
CREATE INDEX idx_users_role ON users (role);

CREATE TABLE oauth_clients (
    id VARCHAR(64) PRIMARY KEY,
    secret_hash TEXT,
    name VARCHAR(128) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    post_logout_redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grants TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    owner_id UUID REFERENCES users(id) ON DELETE CASCADE,
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
    CONSTRAINT oauth_clients_secret_kind_consistent CHECK ((is_public AND secret_hash IS NULL) OR (NOT is_public AND secret_hash IS NOT NULL)),
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
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT oauth_providers_name_valid CHECK (name ~ '^[A-Za-z0-9._-]{1,64}$'),
    CONSTRAINT oauth_providers_type_valid CHECK (type IN ('github', 'google', 'generic')),
    CONSTRAINT oauth_providers_scopes_no_null CHECK (array_position(scopes, NULL) IS NULL),
    CONSTRAINT oauth_providers_generic_discovery_required CHECK (type <> 'generic' OR (discovery_url IS NOT NULL AND btrim(discovery_url) <> '')),
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

CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event VARCHAR(64) NOT NULL,
    actor_id UUID,
    actor_name VARCHAR(128),
    target_type VARCHAR(32),
    target_id VARCHAR(128),
    ip_address VARCHAR(255),
    user_agent TEXT,
    result VARCHAR(16) NOT NULL DEFAULT 'success',
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT audit_logs_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT audit_logs_risk_level_valid CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT audit_logs_metadata_object CHECK (jsonb_typeof(metadata) = 'object')
);
CREATE INDEX idx_audit_logs_event_created ON audit_logs (event, created_at DESC);
CREATE INDEX idx_audit_logs_actor_created ON audit_logs (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_audit_logs_created ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_logs_target ON audit_logs (target_type, target_id) WHERE target_type IS NOT NULL;
