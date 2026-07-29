DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM media_storage_migrations WHERE target_backend = 'local'
    ) THEN
        RAISE EXCEPTION 'cannot downgrade runtime media fallback after a local-target migration exists';
    END IF;
END;
$$;

ALTER TABLE media_storage_migration_items
    DROP CONSTRAINT media_storage_migration_items_target_consistent,
    DROP CONSTRAINT media_storage_migration_items_target_backend_valid,
    ALTER COLUMN target_profile_id SET NOT NULL,
    DROP COLUMN target_backend;

ALTER TABLE media_storage_migrations
    DROP CONSTRAINT media_storage_migrations_target_consistent,
    DROP CONSTRAINT media_storage_migrations_target_backend_valid,
    ALTER COLUMN target_profile_id SET NOT NULL,
    DROP COLUMN target_backend;
