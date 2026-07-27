CREATE TABLE user_avatars (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    storage_backend TEXT NOT NULL,
    object_prefix TEXT NOT NULL,
    variants JSONB NOT NULL DEFAULT '[]'::JSONB,
    content_sha256 BYTEA NOT NULL,
    original_media_type TEXT NOT NULL,
    original_width INTEGER NOT NULL,
    original_height INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    replaced_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    storage_deleted_at TIMESTAMPTZ,
    cleanup_claimed_at TIMESTAMPTZ,
    last_error TEXT,
    CONSTRAINT user_avatars_source_valid CHECK (source IN ('user_upload', 'admin_upload', 'provider_import')),
    CONSTRAINT user_avatars_status_valid CHECK (status IN ('staging', 'active', 'replaced', 'failed', 'deleted')),
    CONSTRAINT user_avatars_storage_backend_valid CHECK (storage_backend IN ('local', 's3')),
    CONSTRAINT user_avatars_object_prefix_not_blank CHECK (btrim(object_prefix) <> ''),
    CONSTRAINT user_avatars_variants_array CHECK (jsonb_typeof(variants) = 'array'),
    CONSTRAINT user_avatars_hash_length CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT user_avatars_original_media_type_valid CHECK (original_media_type IN ('image/jpeg', 'image/png', 'image/webp')),
    CONSTRAINT user_avatars_dimensions_positive CHECK (
        original_width > 0 AND original_height > 0
    ),
    CONSTRAINT user_avatars_activation_consistent CHECK (
        (status = 'active') = (activated_at IS NOT NULL AND replaced_at IS NULL AND deleted_at IS NULL AND failed_at IS NULL)
    ),
    CONSTRAINT user_avatars_replaced_consistent CHECK (
        (status <> 'replaced') OR (replaced_at IS NOT NULL)
    ),
    CONSTRAINT user_avatars_deleted_consistent CHECK (
        (status <> 'deleted') OR (deleted_at IS NOT NULL)
    ),
    CONSTRAINT user_avatars_failed_consistent CHECK (
        (status <> 'failed') OR (failed_at IS NOT NULL AND last_error IS NOT NULL AND btrim(last_error) <> '')
    )
);

CREATE UNIQUE INDEX idx_user_avatars_one_active
    ON user_avatars (user_id)
    WHERE status = 'active';

CREATE INDEX idx_user_avatars_user_created
    ON user_avatars (user_id, created_at DESC, id);

CREATE INDEX idx_user_avatars_cleanup
    ON user_avatars (updated_at, id)
    WHERE storage_deleted_at IS NULL;

ALTER TABLE users ADD COLUMN current_avatar_id UUID;

ALTER TABLE users
    ADD CONSTRAINT users_current_avatar_fk
    FOREIGN KEY (current_avatar_id)
    REFERENCES user_avatars(id)
    ON DELETE SET NULL
    DEFERRABLE INITIALLY IMMEDIATE;

ALTER TABLE users DROP COLUMN avatar_url;

CREATE TABLE provider_avatar_import_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_avatar_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by TEXT,
    completed_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT provider_avatar_jobs_url_lifecycle CHECK (
        (status IN ('pending', 'processing') AND btrim(encrypted_avatar_url) <> '') OR
        (status IN ('completed', 'failed') AND encrypted_avatar_url = '')
    ),
    CONSTRAINT provider_avatar_jobs_status_valid CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    CONSTRAINT provider_avatar_jobs_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT provider_avatar_jobs_locked_consistent CHECK (
        (status = 'processing') = (locked_at IS NOT NULL AND locked_by IS NOT NULL AND btrim(locked_by) <> '')
    ),
    CONSTRAINT provider_avatar_jobs_completed_consistent CHECK (
        (status <> 'completed') OR (completed_at IS NOT NULL AND encrypted_avatar_url = '')
    ),
    CONSTRAINT provider_avatar_jobs_failed_consistent CHECK (
        (status <> 'failed') OR (failed_at IS NOT NULL AND encrypted_avatar_url = '' AND last_error IS NOT NULL AND btrim(last_error) <> '')
    )
);

CREATE INDEX idx_provider_avatar_jobs_claim
    ON provider_avatar_import_jobs (available_at, created_at, id)
    WHERE status = 'pending';

CREATE INDEX idx_provider_avatar_jobs_user
    ON provider_avatar_import_jobs (user_id, created_at DESC, id);

ALTER TABLE oauth_providers ADD COLUMN import_avatar BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE oauth_providers ADD COLUMN avatar_allowed_hosts TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_avatar_allowed_hosts_no_null
    CHECK (array_position(avatar_allowed_hosts, NULL) IS NULL);

ALTER TABLE oauth_providers
    ADD CONSTRAINT oauth_providers_generic_avatar_allowlist_required
    CHECK (type <> 'generic' OR NOT import_avatar OR cardinality(avatar_allowed_hosts) > 0);
