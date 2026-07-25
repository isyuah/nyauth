-- Migration 002: OAuth Clients table

CREATE TABLE IF NOT EXISTS oauth_clients (
    id VARCHAR(64) PRIMARY KEY,
    secret_hash VARCHAR(255),
    name VARCHAR(128) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    grants TEXT[] NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    is_public BOOLEAN NOT NULL DEFAULT FALSE,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_name ON oauth_clients(name);
