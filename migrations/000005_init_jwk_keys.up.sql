-- Migration 005: JWK Keys

CREATE TABLE IF NOT EXISTS jwk_keys (
    kid VARCHAR(64) PRIMARY KEY,
    key_type VARCHAR(16) NOT NULL,
    usage VARCHAR(16) NOT NULL,
    algorithm VARCHAR(16) NOT NULL,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ
);

CREATE INDEX idx_jwk_keys_active ON jwk_keys(is_active) WHERE is_active = TRUE;
