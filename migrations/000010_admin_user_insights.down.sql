DROP INDEX IF EXISTS idx_audit_logs_target_created;
DROP INDEX IF EXISTS idx_users_created_by;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_created_by_fkey,
    DROP CONSTRAINT IF EXISTS users_created_by_not_self,
    DROP CONSTRAINT IF EXISTS users_created_by_source_valid,
    DROP CONSTRAINT IF EXISTS users_creation_source_valid,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS creation_source;
