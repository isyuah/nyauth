-- Migration 008: Add owner_id to oauth_clients for user-owned apps

ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS owner_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX idx_oauth_clients_owner ON oauth_clients(owner_id) WHERE owner_id IS NOT NULL;
