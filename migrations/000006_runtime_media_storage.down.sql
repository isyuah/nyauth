DROP TABLE IF EXISTS media_storage_instances;
DROP TABLE IF EXISTS media_storage_migration_items;
DROP TABLE IF EXISTS media_storage_migrations;
DROP INDEX IF EXISTS idx_user_avatars_storage_profile;
ALTER TABLE user_avatars DROP COLUMN IF EXISTS storage_profile_id;
DROP TABLE IF EXISTS media_storage_state;
DROP TRIGGER IF EXISTS media_storage_profiles_immutable ON media_storage_profiles;
DROP FUNCTION IF EXISTS protect_media_storage_profile();
DROP TABLE IF EXISTS media_storage_profiles;
