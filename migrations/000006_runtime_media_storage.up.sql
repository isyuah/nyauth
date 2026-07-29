CREATE TABLE media_storage_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backend TEXT NOT NULL DEFAULT 's3',
    endpoint TEXT NOT NULL DEFAULT '',
    region TEXT NOT NULL,
    bucket TEXT NOT NULL,
    object_prefix TEXT NOT NULL DEFAULT '',
    path_style BOOLEAN NOT NULL DEFAULT FALSE,
    encrypted_access_key_id TEXT NOT NULL,
    encrypted_secret_access_key TEXT NOT NULL,
    encrypted_session_token TEXT NOT NULL DEFAULT '',
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tested_at TIMESTAMPTZ,
    test_result TEXT,
    test_error_category TEXT,
    test_error TEXT,
    CONSTRAINT media_storage_profiles_backend_valid CHECK (backend = 's3'),
    CONSTRAINT media_storage_profiles_region_not_blank CHECK (btrim(region) <> ''),
    CONSTRAINT media_storage_profiles_bucket_not_blank CHECK (btrim(bucket) <> ''),
    CONSTRAINT media_storage_profiles_creator_not_blank CHECK (btrim(created_by_name) <> ''),
    CONSTRAINT media_storage_profiles_test_consistent CHECK (
        (tested_at IS NULL AND test_result IS NULL AND test_error_category IS NULL AND test_error IS NULL) OR
        (tested_at IS NOT NULL AND test_result IN ('success', 'failure'))
    )
);

CREATE FUNCTION protect_media_storage_profile() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.backend IS NOT DISTINCT FROM OLD.backend
       AND NEW.endpoint IS NOT DISTINCT FROM OLD.endpoint
       AND NEW.region IS NOT DISTINCT FROM OLD.region
       AND NEW.bucket IS NOT DISTINCT FROM OLD.bucket
       AND NEW.object_prefix IS NOT DISTINCT FROM OLD.object_prefix
       AND NEW.path_style IS NOT DISTINCT FROM OLD.path_style
       AND NEW.encrypted_access_key_id IS NOT DISTINCT FROM OLD.encrypted_access_key_id
       AND NEW.encrypted_secret_access_key IS NOT DISTINCT FROM OLD.encrypted_secret_access_key
       AND NEW.encrypted_session_token IS NOT DISTINCT FROM OLD.encrypted_session_token
       AND (NEW.created_by IS NOT DISTINCT FROM OLD.created_by OR (OLD.created_by IS NOT NULL AND NEW.created_by IS NULL))
       AND NEW.created_by_name IS NOT DISTINCT FROM OLD.created_by_name
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% configuration is immutable', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER media_storage_profiles_immutable
    BEFORE UPDATE OR DELETE ON media_storage_profiles
    FOR EACH ROW EXECUTE FUNCTION protect_media_storage_profile();

CREATE TABLE media_storage_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    active_profile_id UUID REFERENCES media_storage_profiles(id),
    candidate_profile_id UUID REFERENCES media_storage_profiles(id),
    previous_profile_id UUID REFERENCES media_storage_profiles(id),
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by_name TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO media_storage_state (singleton) VALUES (TRUE);

ALTER TABLE user_avatars
    ADD COLUMN storage_profile_id UUID REFERENCES media_storage_profiles(id);

CREATE INDEX idx_user_avatars_storage_profile
    ON user_avatars (storage_profile_id, updated_at, id)
    WHERE storage_deleted_at IS NULL;

CREATE TABLE media_storage_migrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_profile_id UUID REFERENCES media_storage_profiles(id),
    source_backend TEXT NOT NULL,
    target_profile_id UUID NOT NULL REFERENCES media_storage_profiles(id),
    status TEXT NOT NULL DEFAULT 'pending',
    total_count BIGINT NOT NULL DEFAULT 0,
    copied_count BIGINT NOT NULL DEFAULT 0,
    completed_count BIGINT NOT NULL DEFAULT 0,
    failed_count BIGINT NOT NULL DEFAULT 0,
    service_control_revision BIGINT,
    service_control_previous JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_by_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT media_storage_migrations_source_backend_valid CHECK (source_backend IN ('local', 's3')),
    CONSTRAINT media_storage_migrations_status_valid CHECK (status IN ('pending', 'running', 'applying', 'completed', 'failed')),
    CONSTRAINT media_storage_migrations_counts_nonnegative CHECK (
        total_count >= 0 AND copied_count >= 0 AND completed_count >= 0 AND failed_count >= 0
    ),
    CONSTRAINT media_storage_migrations_creator_not_blank CHECK (btrim(created_by_name) <> '')
);

CREATE UNIQUE INDEX idx_media_storage_one_active_migration
    ON media_storage_migrations ((TRUE))
    WHERE status <> 'completed';

CREATE TABLE media_storage_migration_items (
    migration_id UUID NOT NULL REFERENCES media_storage_migrations(id) ON DELETE CASCADE,
    avatar_id UUID NOT NULL REFERENCES user_avatars(id) ON DELETE CASCADE,
    source_profile_id UUID REFERENCES media_storage_profiles(id),
    source_backend TEXT NOT NULL,
    target_profile_id UUID NOT NULL REFERENCES media_storage_profiles(id),
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    copied_at TIMESTAMPTZ,
    switched_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (migration_id, avatar_id),
    CONSTRAINT media_storage_migration_items_source_backend_valid CHECK (source_backend IN ('local', 's3')),
    CONSTRAINT media_storage_migration_items_status_valid CHECK (status IN ('pending', 'copying', 'switched', 'completed', 'failed')),
    CONSTRAINT media_storage_migration_items_attempts_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT media_storage_migration_items_lock_consistent CHECK (
        (status = 'copying') = (locked_at IS NOT NULL AND locked_by IS NOT NULL AND btrim(locked_by) <> '')
    )
);

CREATE INDEX idx_media_storage_migration_items_claim
    ON media_storage_migration_items (migration_id, status, updated_at, avatar_id)
    WHERE status IN ('pending', 'copying', 'switched', 'failed');

CREATE TABLE media_storage_instances (
    instance_id UUID PRIMARY KEY,
    version TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    loaded_revision BIGINT NOT NULL CHECK (loaded_revision >= 0),
    prepared_profile_id UUID REFERENCES media_storage_profiles(id)
);

CREATE INDEX idx_media_storage_instances_heartbeat
    ON media_storage_instances (heartbeat_at);
