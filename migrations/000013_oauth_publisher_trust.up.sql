ALTER TABLE oauth_clients
    ADD COLUMN publisher_type VARCHAR(32) NOT NULL DEFAULT 'system_managed',
    ADD COLUMN publisher_verification_status VARCHAR(32) NOT NULL DEFAULT 'not_applicable',
    ADD COLUMN publisher_verified_at TIMESTAMPTZ,
    ADD COLUMN publisher_verified_by UUID REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_publisher_type_valid
        CHECK (publisher_type IN ('system_managed', 'user_registered')),
    ADD CONSTRAINT oauth_clients_publisher_verification_status_valid
        CHECK (publisher_verification_status IN ('not_applicable', 'unverified', 'verified')),
    ADD CONSTRAINT oauth_clients_publisher_verification_consistent
        CHECK (
            (publisher_type = 'system_managed'
                AND publisher_verification_status = 'not_applicable'
                AND publisher_verified_at IS NULL
                AND publisher_verified_by IS NULL)
            OR
            (publisher_type = 'user_registered'
                AND publisher_verification_status = 'unverified'
                AND publisher_verified_at IS NULL
                AND publisher_verified_by IS NULL)
            OR
            (publisher_type = 'user_registered'
                AND publisher_verification_status = 'verified'
                AND publisher_verified_at IS NOT NULL)
        );

CREATE INDEX idx_oauth_clients_publisher_review
    ON oauth_clients (publisher_verification_status, created_at DESC)
    WHERE publisher_type = 'user_registered';
