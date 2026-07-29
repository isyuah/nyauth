ALTER TABLE oauth_clients
    DROP CONSTRAINT oauth_clients_authorization_code_redirects,
    ADD CONSTRAINT oauth_clients_redirect_uris_not_empty CHECK (cardinality(redirect_uris) > 0);
