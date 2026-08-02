ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_optional_scopes_interactive_grant,
    ADD CONSTRAINT oauth_clients_optional_scopes_authorization_code
        CHECK (cardinality(optional_scopes) = 0 OR 'authorization_code' = ANY(grants));
