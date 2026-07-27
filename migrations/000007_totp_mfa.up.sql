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
