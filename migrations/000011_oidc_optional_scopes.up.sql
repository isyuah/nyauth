ALTER TABLE oauth_clients
    ADD COLUMN optional_scopes TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_optional_scopes_no_null
        CHECK (array_position(optional_scopes, NULL) IS NULL),
    ADD CONSTRAINT oauth_clients_optional_scopes_subset
        CHECK (optional_scopes <@ scopes),
    ADD CONSTRAINT oauth_clients_openid_required
        CHECK (NOT ('openid' = ANY(optional_scopes))),
    ADD CONSTRAINT oauth_clients_optional_scopes_authorization_code
        CHECK (cardinality(optional_scopes) = 0 OR 'authorization_code' = ANY(grants)),
    ADD CONSTRAINT oauth_clients_required_scope_present
        CHECK (cardinality(scopes) = 0 OR cardinality(optional_scopes) < cardinality(scopes));
