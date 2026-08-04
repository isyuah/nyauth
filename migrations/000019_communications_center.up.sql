CREATE TABLE announcements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status VARCHAR(16) NOT NULL DEFAULT 'draft',
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    audience VARCHAR(16) NOT NULL DEFAULT 'authenticated',
    title VARCHAR(120) NOT NULL,
    summary VARCHAR(240) NOT NULL DEFAULT '',
    body_markdown TEXT NOT NULL,
    link_url TEXT,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    starts_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,
    published_at TIMESTAMPTZ,
    archived_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT announcements_status_valid CHECK (status IN ('draft','published','archived')),
    CONSTRAINT announcements_severity_valid CHECK (severity IN ('info','warning','critical')),
    CONSTRAINT announcements_audience_valid CHECK (audience IN ('authenticated','admins')),
    CONSTRAINT announcements_revision_positive CHECK (revision > 0),
    CONSTRAINT announcements_time_order CHECK (ends_at IS NULL OR starts_at IS NULL OR ends_at > starts_at),
    CONSTRAINT announcements_published_has_content CHECK (status <> 'published' OR (btrim(title) <> '' AND btrim(body_markdown) <> ''))
);

CREATE INDEX idx_announcements_public ON announcements (status, starts_at, ends_at, pinned DESC, updated_at DESC);
CREATE INDEX idx_announcements_admin ON announcements (status, updated_at DESC);

CREATE TABLE announcement_reads (
    announcement_id UUID NOT NULL REFERENCES announcements(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    read_revision BIGINT NOT NULL,
    read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (announcement_id, user_id),
    CONSTRAINT announcement_reads_revision_positive CHECK (read_revision > 0)
);

CREATE TABLE user_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    notification_type VARCHAR(64) NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    title VARCHAR(160) NOT NULL,
    body_markdown TEXT NOT NULL,
    link_url TEXT,
    source_type VARCHAR(32),
    source_id VARCHAR(128),
    dedupe_key VARCHAR(192),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    read_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    CONSTRAINT user_notifications_severity_valid CHECK (severity IN ('info','warning','critical')),
    CONSTRAINT user_notifications_source_pair CHECK ((source_type IS NULL AND source_id IS NULL) OR (source_type IS NOT NULL AND source_id IS NOT NULL)),
    CONSTRAINT user_notifications_dedupe_not_blank CHECK (dedupe_key IS NULL OR btrim(dedupe_key) <> '')
);

CREATE INDEX idx_user_notifications_user_time ON user_notifications (user_id, created_at DESC, id DESC);
CREATE INDEX idx_user_notifications_unread ON user_notifications (user_id, read_at, created_at DESC);
CREATE UNIQUE INDEX idx_user_notifications_dedupe ON user_notifications (user_id, dedupe_key) WHERE dedupe_key IS NOT NULL;
