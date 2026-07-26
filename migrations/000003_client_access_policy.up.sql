-- Per-client access policy: which users may complete an OAuth flow against a
-- client. 'open' preserves the previous behavior for existing clients.
-- NOTE: fold into the 000001 baseline when cutting the 0.3.0 release.
ALTER TABLE oauth_clients ADD COLUMN access_policy TEXT NOT NULL DEFAULT 'open'
    CONSTRAINT oauth_clients_access_policy_valid CHECK (access_policy IN ('open', 'admins_only', 'allowlist'));

CREATE TABLE client_access_users (
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, user_id)
);
CREATE INDEX idx_client_access_users_user ON client_access_users(user_id);
