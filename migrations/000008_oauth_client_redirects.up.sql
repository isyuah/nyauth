ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_redirect_uris_not_empty,
    ADD CONSTRAINT oauth_clients_authorization_code_redirects CHECK (
        NOT ('authorization_code' = ANY(grants)) OR cardinality(redirect_uris) > 0
    );
