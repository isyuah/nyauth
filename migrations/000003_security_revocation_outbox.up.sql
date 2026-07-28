CREATE TABLE security_revocation_outbox (
    user_id UUID PRIMARY KEY,
    revision BIGINT NOT NULL DEFAULT 1,
    auth_version BIGINT NOT NULL,
    session_version BIGINT NOT NULL,
    user_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    reason VARCHAR(64) NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    locked_at TIMESTAMPTZ,
    locked_by VARCHAR(128),
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT security_revocation_revision_positive CHECK (revision > 0),
    CONSTRAINT security_revocation_versions_positive CHECK (auth_version > 0 AND session_version > 0),
    CONSTRAINT security_revocation_attempt_count_nonnegative CHECK (attempt_count >= 0),
    CONSTRAINT security_revocation_reason_not_blank CHECK (btrim(reason) <> ''),
    CONSTRAINT security_revocation_lock_consistent CHECK ((locked_at IS NULL) = (locked_by IS NULL))
);

CREATE INDEX idx_security_revocation_outbox_available
    ON security_revocation_outbox (available_at, updated_at)
    WHERE locked_at IS NULL;

CREATE FUNCTION nyauth_enqueue_security_revocation() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    target_user_id UUID;
    target_auth_version BIGINT;
    target_session_version BIGINT;
    target_deleted BOOLEAN;
    target_reason VARCHAR(64);
BEGIN
    IF TG_OP = 'DELETE' THEN
        target_user_id := OLD.id;
        target_auth_version := OLD.auth_version;
        target_session_version := OLD.session_version;
        target_deleted := TRUE;
        target_reason := 'user_deleted';
    ELSE
        IF NEW.auth_version = OLD.auth_version AND NEW.session_version = OLD.session_version THEN
            RETURN NEW;
        END IF;
        target_user_id := NEW.id;
        target_auth_version := NEW.auth_version;
        target_session_version := NEW.session_version;
        target_deleted := FALSE;
        target_reason := CASE
            WHEN NEW.auth_version <> OLD.auth_version AND NEW.session_version <> OLD.session_version THEN 'security_versions_changed'
            WHEN NEW.auth_version <> OLD.auth_version THEN 'auth_version_changed'
            ELSE 'session_version_changed'
        END;
    END IF;

    INSERT INTO security_revocation_outbox (
        user_id, auth_version, session_version, user_deleted, reason
    ) VALUES (
        target_user_id, target_auth_version, target_session_version, target_deleted, target_reason
    )
    ON CONFLICT (user_id) DO UPDATE SET
        revision = security_revocation_outbox.revision + 1,
        auth_version = GREATEST(security_revocation_outbox.auth_version, EXCLUDED.auth_version),
        session_version = GREATEST(security_revocation_outbox.session_version, EXCLUDED.session_version),
        user_deleted = security_revocation_outbox.user_deleted OR EXCLUDED.user_deleted,
        reason = EXCLUDED.reason,
        attempt_count = 0,
        available_at = LEAST(security_revocation_outbox.available_at, NOW()),
        last_error = NULL,
        updated_at = NOW();

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER users_security_revocation_outbox
AFTER UPDATE OF auth_version, session_version OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION nyauth_enqueue_security_revocation();
