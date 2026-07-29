ALTER TABLE media_storage_migrations
    ADD COLUMN target_backend TEXT NOT NULL DEFAULT 's3';

ALTER TABLE media_storage_migrations
    ALTER COLUMN target_backend DROP DEFAULT,
    ALTER COLUMN target_profile_id DROP NOT NULL,
    ADD CONSTRAINT media_storage_migrations_target_backend_valid
        CHECK (target_backend IN ('local', 's3')),
    ADD CONSTRAINT media_storage_migrations_target_consistent
        CHECK (
            (target_backend = 'local' AND target_profile_id IS NULL) OR
            (target_backend = 's3' AND target_profile_id IS NOT NULL)
        );

ALTER TABLE media_storage_migration_items
    ADD COLUMN target_backend TEXT NOT NULL DEFAULT 's3';

ALTER TABLE media_storage_migration_items
    ALTER COLUMN target_backend DROP DEFAULT,
    ALTER COLUMN target_profile_id DROP NOT NULL,
    ADD CONSTRAINT media_storage_migration_items_target_backend_valid
        CHECK (target_backend IN ('local', 's3')),
    ADD CONSTRAINT media_storage_migration_items_target_consistent
        CHECK (
            (target_backend = 'local' AND target_profile_id IS NULL) OR
            (target_backend = 's3' AND target_profile_id IS NOT NULL)
        );
