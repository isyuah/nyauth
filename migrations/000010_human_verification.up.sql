CREATE TABLE human_verification_config_versions (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    provider VARCHAR(32) NOT NULL,
    site_key TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    widget_mode VARCHAR(32) NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT human_verification_provider_valid CHECK (provider IN ('turnstile')),
    CONSTRAINT human_verification_site_key_valid CHECK (
        length(site_key) BETWEEN 1 AND 256
        AND site_key = btrim(site_key)
        AND position(chr(10) IN site_key) = 0
        AND position(chr(13) IN site_key) = 0
    ),
    CONSTRAINT human_verification_secret_valid CHECK (btrim(secret_ciphertext) <> ''),
    CONSTRAINT human_verification_widget_mode_valid CHECK (
        widget_mode IN ('managed', 'non-interactive', 'invisible')
    )
);

CREATE TABLE human_verification_config_tests (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    version_id UUID NOT NULL REFERENCES human_verification_config_versions(id) ON DELETE RESTRICT,
    result VARCHAR(16) NOT NULL,
    error_code VARCHAR(64),
    tested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT human_verification_test_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT human_verification_test_result_consistent CHECK (
        (result = 'success' AND error_code IS NULL)
        OR (result = 'failure' AND error_code IS NOT NULL AND btrim(error_code) <> '')
    )
);
CREATE INDEX idx_human_verification_tests_recent_success
    ON human_verification_config_tests (version_id, created_at DESC)
    WHERE result = 'success';

CREATE TABLE human_verification_runtime_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mode VARCHAR(16) NOT NULL DEFAULT 'disabled',
    active_version_id UUID REFERENCES human_verification_config_versions(id) ON DELETE RESTRICT,
    candidate_version_id UUID REFERENCES human_verification_config_versions(id) ON DELETE RESTRICT,
    previous_version_id UUID REFERENCES human_verification_config_versions(id) ON DELETE RESTRICT,
    policy JSONB NOT NULL DEFAULT '{
        "registration": true,
        "login_mode": "adaptive",
        "login_trigger_after": 3,
        "password_reset": true,
        "email_verification_resend": true,
        "provider_login": true
    }'::JSONB,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT human_verification_state_singleton CHECK (singleton),
    CONSTRAINT human_verification_state_mode_valid CHECK (mode IN ('active', 'disabled')),
    CONSTRAINT human_verification_state_revision_positive CHECK (revision > 0),
    CONSTRAINT human_verification_state_policy_object CHECK (jsonb_typeof(policy) = 'object'),
    CONSTRAINT human_verification_state_mode_consistent CHECK (
        mode <> 'active' OR active_version_id IS NOT NULL
    ),
    CONSTRAINT human_verification_state_pointers_distinct CHECK (
        (candidate_version_id IS NULL OR active_version_id IS NULL OR candidate_version_id <> active_version_id)
        AND (candidate_version_id IS NULL OR previous_version_id IS NULL OR candidate_version_id <> previous_version_id)
        AND (active_version_id IS NULL OR previous_version_id IS NULL OR active_version_id <> previous_version_id)
    )
);
INSERT INTO human_verification_runtime_state (singleton) VALUES (TRUE);

CREATE FUNCTION protect_human_verification_config_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.created_by IS NOT NULL AND NEW.created_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.provider IS NOT DISTINCT FROM OLD.provider
       AND NEW.site_key IS NOT DISTINCT FROM OLD.site_key
       AND NEW.secret_ciphertext IS NOT DISTINCT FROM OLD.secret_ciphertext
       AND NEW.widget_mode IS NOT DISTINCT FROM OLD.widget_mode
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION protect_human_verification_test_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.tested_by IS NOT NULL AND NEW.tested_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.version_id IS NOT DISTINCT FROM OLD.version_id
       AND NEW.result IS NOT DISTINCT FROM OLD.result
       AND NEW.error_code IS NOT DISTINCT FROM OLD.error_code
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER human_verification_config_versions_append_only
    BEFORE UPDATE OR DELETE ON human_verification_config_versions
    FOR EACH ROW EXECUTE FUNCTION protect_human_verification_config_history();
CREATE TRIGGER human_verification_config_tests_append_only
    BEFORE UPDATE OR DELETE ON human_verification_config_tests
    FOR EACH ROW EXECUTE FUNCTION protect_human_verification_test_history();
