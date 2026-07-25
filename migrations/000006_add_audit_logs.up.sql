-- Migration 006: Audit logs table

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event VARCHAR(64) NOT NULL,
    actor_id UUID,
    actor_name VARCHAR(128),
    target_type VARCHAR(32),
    target_id VARCHAR(128),
    ip_address VARCHAR(45),
    user_agent TEXT,
    result VARCHAR(16) NOT NULL DEFAULT 'success',
    risk_level VARCHAR(16) NOT NULL DEFAULT 'low',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_event ON audit_logs(event);
CREATE INDEX idx_audit_logs_actor ON audit_logs(actor_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_target ON audit_logs(target_type, target_id);

-- Default test OAuth client for /test-client page
INSERT INTO oauth_clients (id, name, redirect_uris, grants, scopes, is_public)
VALUES ('nya-test-client', 'Nya Test Client',
  ARRAY['http://localhost:8080/test-client'],
  ARRAY['authorization_code', 'refresh_token'],
  ARRAY['openid', 'profile', 'email', 'offline_access'],
  TRUE)
ON CONFLICT (id) DO NOTHING;

-- Web UI client (public, no secret needed for refresh)
INSERT INTO oauth_clients (id, name, redirect_uris, grants, scopes, is_public)
VALUES ('nyauth-web', 'Nya Web',
  ARRAY['http://localhost:8080'],
  ARRAY['authorization_code', 'refresh_token'],
  ARRAY['openid', 'profile', 'email'],
  TRUE)
ON CONFLICT (id) DO UPDATE SET is_public = TRUE;
