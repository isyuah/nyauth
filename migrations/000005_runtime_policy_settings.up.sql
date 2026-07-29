ALTER TABLE runtime_settings
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1,
    ADD CONSTRAINT runtime_settings_revision_positive CHECK (revision > 0);

ALTER TABLE users
    ADD COLUMN owned_client_limit_override INTEGER,
    ADD CONSTRAINT users_owned_client_limit_override_range CHECK (
        owned_client_limit_override IS NULL OR
        owned_client_limit_override BETWEEN 0 AND 1000
    );
