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
