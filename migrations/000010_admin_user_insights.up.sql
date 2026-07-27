-- Durable user creation provenance and indexes supporting exact user activity.
ALTER TABLE users
    ADD COLUMN creation_source VARCHAR(32),
    ADD COLUMN created_by UUID;

-- self_registrations is the only authoritative historical source marker.
-- Existing identities may have been bound after a local account was created,
-- so every other pre-migration account remains explicitly legacy.
UPDATE users AS subject
SET creation_source = 'self_registration'
WHERE EXISTS (
    SELECT 1
    FROM self_registrations AS registration
    WHERE registration.user_id = subject.id
);

UPDATE users
SET creation_source = 'legacy'
WHERE creation_source IS NULL;

ALTER TABLE users
    ALTER COLUMN creation_source SET NOT NULL,
    ADD CONSTRAINT users_creation_source_valid CHECK (
        creation_source IN ('bootstrap', 'admin', 'self_registration', 'provider', 'legacy')
    ),
    ADD CONSTRAINT users_created_by_source_valid CHECK (
        created_by IS NULL OR creation_source = 'admin'
    ),
    ADD CONSTRAINT users_created_by_not_self CHECK (
        created_by IS NULL OR created_by <> id
    ),
    ADD CONSTRAINT users_created_by_fkey FOREIGN KEY (created_by)
        REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX idx_users_created_by
    ON users (created_by)
    WHERE created_by IS NOT NULL;

CREATE INDEX idx_audit_logs_target_created
    ON audit_logs (target_type, target_id, created_at DESC)
    WHERE target_type IS NOT NULL AND target_id IS NOT NULL;
