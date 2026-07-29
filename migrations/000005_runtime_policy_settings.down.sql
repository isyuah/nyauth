ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_owned_client_limit_override_range,
    DROP COLUMN IF EXISTS owned_client_limit_override;

ALTER TABLE runtime_settings
    DROP CONSTRAINT IF EXISTS runtime_settings_revision_positive,
    DROP COLUMN IF EXISTS revision;
