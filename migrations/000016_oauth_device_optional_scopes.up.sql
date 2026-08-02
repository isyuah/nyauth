ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_optional_scopes_authorization_code,
    ADD CONSTRAINT oauth_clients_optional_scopes_interactive_grant
        CHECK (
            cardinality(optional_scopes) = 0 OR
            'authorization_code' = ANY(grants) OR
            'urn:ietf:params:oauth:grant-type:device_code' = ANY(grants)
        );
