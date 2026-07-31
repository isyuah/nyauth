DROP INDEX IF EXISTS idx_oauth_clients_publisher_review;

ALTER TABLE oauth_clients
    DROP CONSTRAINT IF EXISTS oauth_clients_publisher_verification_consistent,
    DROP CONSTRAINT IF EXISTS oauth_clients_publisher_verification_status_valid,
    DROP CONSTRAINT IF EXISTS oauth_clients_publisher_type_valid,
    DROP COLUMN IF EXISTS publisher_verified_by,
    DROP COLUMN IF EXISTS publisher_verified_at,
    DROP COLUMN IF EXISTS publisher_verification_status,
    DROP COLUMN IF EXISTS publisher_type;
