ALTER TABLE oauth_providers DROP CONSTRAINT IF EXISTS oauth_providers_generic_avatar_allowlist_required;
ALTER TABLE oauth_providers DROP CONSTRAINT IF EXISTS oauth_providers_avatar_allowed_hosts_no_null;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS avatar_allowed_hosts;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS import_avatar;

DROP TABLE IF EXISTS provider_avatar_import_jobs;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_current_avatar_fk;
ALTER TABLE users ADD COLUMN avatar_url TEXT;
ALTER TABLE users DROP COLUMN IF EXISTS current_avatar_id;

DROP TABLE IF EXISTS user_avatars;
