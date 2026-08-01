CREATE TABLE user_trusted_devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    auth_version BIGINT NOT NULL,
    session_version BIGINT NOT NULL,
    initial_ip VARCHAR(45),
    last_used_ip VARCHAR(45),
    user_agent VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT user_trusted_devices_token_hash_length CHECK (octet_length(token_hash) = 32),
    CONSTRAINT user_trusted_devices_auth_version_positive CHECK (auth_version > 0),
    CONSTRAINT user_trusted_devices_session_version_positive CHECK (session_version > 0),
    CONSTRAINT user_trusted_devices_expiry_after_creation CHECK (expires_at > created_at),
    CONSTRAINT user_trusted_devices_last_use_not_before_creation CHECK (last_used_at >= created_at),
    CONSTRAINT user_trusted_devices_revocation_not_before_creation CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE UNIQUE INDEX idx_user_trusted_devices_token_hash
    ON user_trusted_devices (token_hash);

CREATE INDEX idx_user_trusted_devices_user_active
    ON user_trusted_devices (user_id, last_used_at DESC, id)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_user_trusted_devices_cleanup
    ON user_trusted_devices (expires_at, id);
