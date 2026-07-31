CREATE TABLE otlp_config_versions (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    endpoint TEXT NOT NULL,
    authorization_ciphertext TEXT,
    export_interval_ms INTEGER NOT NULL,
    timeout_ms INTEGER NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT otlp_config_versions_endpoint_valid CHECK (
        length(endpoint) BETWEEN 1 AND 2048
        AND endpoint = btrim(endpoint)
        AND endpoint ~ '^https?://'
        AND position(chr(10) IN endpoint) = 0
        AND position(chr(13) IN endpoint) = 0
    ),
    CONSTRAINT otlp_config_versions_authorization_valid CHECK (
        authorization_ciphertext IS NULL OR btrim(authorization_ciphertext) <> ''
    ),
    CONSTRAINT otlp_config_versions_interval_valid CHECK (export_interval_ms BETWEEN 10000 AND 3600000),
    CONSTRAINT otlp_config_versions_timeout_valid CHECK (timeout_ms BETWEEN 1000 AND 30000)
);

CREATE TABLE otlp_config_tests (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    version_id UUID NOT NULL REFERENCES otlp_config_versions(id) ON DELETE RESTRICT,
    result VARCHAR(16) NOT NULL,
    error_code VARCHAR(64),
    tested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT otlp_config_tests_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT otlp_config_tests_result_consistent CHECK (
        (result = 'success' AND error_code IS NULL)
        OR (result = 'failure' AND btrim(error_code) <> '')
    )
);
CREATE INDEX idx_otlp_config_tests_recent_success
    ON otlp_config_tests (version_id, created_at DESC)
    WHERE result = 'success';

CREATE TABLE otlp_runtime_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mode VARCHAR(16) NOT NULL DEFAULT 'fallback',
    active_version_id UUID REFERENCES otlp_config_versions(id) ON DELETE RESTRICT,
    candidate_version_id UUID REFERENCES otlp_config_versions(id) ON DELETE RESTRICT,
    previous_version_id UUID REFERENCES otlp_config_versions(id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT otlp_runtime_state_singleton CHECK (singleton),
    CONSTRAINT otlp_runtime_state_mode_valid CHECK (mode IN ('fallback', 'active', 'disabled')),
    CONSTRAINT otlp_runtime_state_revision_nonnegative CHECK (revision >= 0),
    CONSTRAINT otlp_runtime_state_mode_consistent CHECK (
        (mode = 'fallback' AND active_version_id IS NULL AND previous_version_id IS NULL)
        OR (mode = 'active' AND active_version_id IS NOT NULL)
        OR (mode = 'disabled' AND active_version_id IS NULL)
    ),
    CONSTRAINT otlp_runtime_state_version_pointers_distinct CHECK (
        (candidate_version_id IS NULL OR active_version_id IS NULL OR candidate_version_id <> active_version_id)
        AND (candidate_version_id IS NULL OR previous_version_id IS NULL OR candidate_version_id <> previous_version_id)
        AND (active_version_id IS NULL OR previous_version_id IS NULL OR active_version_id <> previous_version_id)
    )
);
INSERT INTO otlp_runtime_state (singleton) VALUES (TRUE);

CREATE FUNCTION protect_otlp_config_version_history() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.created_by IS NOT NULL AND NEW.created_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.endpoint IS NOT DISTINCT FROM OLD.endpoint
       AND NEW.authorization_ciphertext IS NOT DISTINCT FROM OLD.authorization_ciphertext
       AND NEW.export_interval_ms IS NOT DISTINCT FROM OLD.export_interval_ms
       AND NEW.timeout_ms IS NOT DISTINCT FROM OLD.timeout_ms
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION protect_otlp_config_test_history() RETURNS trigger
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

CREATE TRIGGER otlp_config_versions_append_only
    BEFORE UPDATE OR DELETE ON otlp_config_versions
    FOR EACH ROW EXECUTE FUNCTION protect_otlp_config_version_history();
CREATE TRIGGER otlp_config_tests_append_only
    BEFORE UPDATE OR DELETE ON otlp_config_tests
    FOR EACH ROW EXECUTE FUNCTION protect_otlp_config_test_history();
