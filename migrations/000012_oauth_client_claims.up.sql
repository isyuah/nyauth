ALTER TABLE oauth_clients
    ADD COLUMN allowed_claims TEXT[] NOT NULL DEFAULT '{}';

UPDATE oauth_clients
SET allowed_claims = ARRAY_REMOVE(ARRAY[
    CASE WHEN 'openid' = ANY(scopes) THEN 'sub' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'preferred_username' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'name' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'picture' END,
    CASE WHEN 'email' = ANY(scopes) THEN 'email' END
]::TEXT[], NULL);

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_allowed_claims_no_null
        CHECK (array_position(allowed_claims, NULL) IS NULL),
    ADD CONSTRAINT oauth_clients_allowed_claims_supported
        CHECK (allowed_claims <@ ARRAY[
            'sub', 'preferred_username', 'name', 'picture',
            'email', 'email_verified', 'role'
        ]::TEXT[]),
    ADD CONSTRAINT oauth_clients_openid_sub_consistent
        CHECK (('sub' = ANY(allowed_claims)) = ('openid' = ANY(scopes)));

ALTER TABLE oauth_authorizations
    ADD COLUMN allowed_claims TEXT[] NOT NULL DEFAULT '{}';

UPDATE oauth_authorizations
SET allowed_claims = ARRAY_REMOVE(ARRAY[
    CASE WHEN 'openid' = ANY(scopes) THEN 'sub' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'preferred_username' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'name' END,
    CASE WHEN 'profile' = ANY(scopes) THEN 'picture' END,
    CASE WHEN 'email' = ANY(scopes) THEN 'email' END
]::TEXT[], NULL);

ALTER TABLE oauth_authorizations
    ADD CONSTRAINT oauth_authorizations_allowed_claims_no_null
        CHECK (array_position(allowed_claims, NULL) IS NULL),
    ADD CONSTRAINT oauth_authorizations_allowed_claims_supported
        CHECK (allowed_claims <@ ARRAY[
            'sub', 'preferred_username', 'name', 'picture',
            'email', 'email_verified', 'role'
        ]::TEXT[]),
    ADD CONSTRAINT oauth_authorizations_openid_sub_consistent
        CHECK (('sub' = ANY(allowed_claims)) = ('openid' = ANY(scopes)));
