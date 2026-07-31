ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_required_scope_present,
    DROP CONSTRAINT IF EXISTS oauth_clients_optional_scopes_authorization_code,
    DROP CONSTRAINT IF EXISTS oauth_clients_openid_required,
    DROP CONSTRAINT IF EXISTS oauth_clients_optional_scopes_subset,
    DROP CONSTRAINT IF EXISTS oauth_clients_optional_scopes_no_null,
    DROP COLUMN IF EXISTS optional_scopes;
