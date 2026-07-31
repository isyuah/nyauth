ALTER TABLE oauth_authorizations
    DROP CONSTRAINT IF EXISTS oauth_authorizations_openid_sub_consistent,
    DROP CONSTRAINT IF EXISTS oauth_authorizations_allowed_claims_supported,
    DROP CONSTRAINT IF EXISTS oauth_authorizations_allowed_claims_no_null,
    DROP COLUMN IF EXISTS allowed_claims;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_openid_sub_consistent,
    DROP CONSTRAINT IF EXISTS oauth_clients_allowed_claims_supported,
    DROP CONSTRAINT IF EXISTS oauth_clients_allowed_claims_no_null,
    DROP COLUMN IF EXISTS allowed_claims;
