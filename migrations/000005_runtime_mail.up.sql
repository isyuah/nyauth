-- Immutable SMTP configuration history and HA-shared runtime mail state.
-- NOTE: fold into the 000001 baseline when cutting the 0.3.0 release.
ALTER TABLE email_outbox DROP CONSTRAINT email_outbox_status_valid;
ALTER TABLE email_outbox ADD CONSTRAINT email_outbox_status_valid
    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'expired', 'rejected'));
-- Schema 4 persisted transport text verbatim. It may contain recipient
-- addresses or SMTP server responses, so do not carry it into the runtime-mail
-- model where all new failures use machine-safe summaries.
UPDATE email_outbox SET last_error=NULL WHERE last_error IS NOT NULL;
CREATE INDEX idx_email_outbox_active_expiry
    ON email_outbox (expires_at, id)
    WHERE status IN ('pending', 'failed', 'sending');

CREATE TABLE mail_config_versions (
    id UUID PRIMARY KEY,
    revision BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
    host VARCHAR(253) NOT NULL,
    port INTEGER NOT NULL,
    username VARCHAR(320) NOT NULL DEFAULT '',
    password_ciphertext TEXT,
    tls_mode VARCHAR(16) NOT NULL,
    from_address VARCHAR(320) NOT NULL,
    from_name VARCHAR(255) NOT NULL DEFAULT '',
    public_base_url TEXT NOT NULL,
    connect_timeout_ms INTEGER NOT NULL,
    send_timeout_ms INTEGER NOT NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_config_versions_host_valid CHECK (
        btrim(host) <> '' AND host = btrim(host)
        AND position(chr(10) IN host) = 0 AND position(chr(13) IN host) = 0
    ),
    CONSTRAINT mail_config_versions_port_valid CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT mail_config_versions_username_valid CHECK (
        username = btrim(username)
        AND position(chr(10) IN username) = 0 AND position(chr(13) IN username) = 0
    ),
    CONSTRAINT mail_config_versions_password_valid CHECK (
        password_ciphertext IS NULL OR btrim(password_ciphertext) <> ''
    ),
    CONSTRAINT mail_config_versions_tls_mode_valid CHECK (
        tls_mode IN ('starttls', 'implicit', 'plain')
    ),
    CONSTRAINT mail_config_versions_from_address_valid CHECK (
        btrim(from_address) <> '' AND from_address = btrim(from_address)
        AND position(chr(10) IN from_address) = 0 AND position(chr(13) IN from_address) = 0
    ),
    CONSTRAINT mail_config_versions_from_name_valid CHECK (
        from_name = btrim(from_name)
        AND position(chr(10) IN from_name) = 0 AND position(chr(13) IN from_name) = 0
    ),
    CONSTRAINT mail_config_versions_public_base_url_valid CHECK (
        length(public_base_url) BETWEEN 1 AND 2048
        AND public_base_url = btrim(public_base_url)
        AND public_base_url ~ '^https?://'
        AND position(chr(10) IN public_base_url) = 0
        AND position(chr(13) IN public_base_url) = 0
    ),
    CONSTRAINT mail_config_versions_connect_timeout_valid CHECK (
        connect_timeout_ms BETWEEN 100 AND 300000
    ),
    CONSTRAINT mail_config_versions_send_timeout_valid CHECK (
        send_timeout_ms BETWEEN 100 AND 600000
    )
);

CREATE TABLE mail_config_tests (
    id UUID PRIMARY KEY,
    version_id UUID NOT NULL REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    recipient_hash BYTEA NOT NULL,
    result VARCHAR(16) NOT NULL,
    error_category VARCHAR(32),
    tested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_config_tests_recipient_hash_length CHECK (octet_length(recipient_hash) = 32),
    CONSTRAINT mail_config_tests_result_valid CHECK (result IN ('success', 'failure')),
    CONSTRAINT mail_config_tests_result_category_consistent CHECK (
        (result = 'success' AND error_category IS NULL)
        OR (
            result = 'failure'
            AND error_category IN (
                'configuration', 'authentication', 'tls', 'transport', 'recipient', 'unknown'
            )
        )
    )
);
CREATE INDEX idx_mail_config_tests_recent_success
    ON mail_config_tests (version_id, created_at DESC)
    WHERE result = 'success';

CREATE TABLE mail_runtime_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mode VARCHAR(16) NOT NULL DEFAULT 'fallback',
    active_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    candidate_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    previous_version_id UUID REFERENCES mail_config_versions(id) ON DELETE RESTRICT,
    revision BIGINT NOT NULL DEFAULT 0,
    circuit_state VARCHAR(16) NOT NULL DEFAULT 'closed',
    circuit_open_reason VARCHAR(64),
    circuit_open_category VARCHAR(32),
    circuit_opened_at TIMESTAMPTZ,
    transport_failure_window_started_at TIMESTAMPTZ,
    transport_failure_count INTEGER NOT NULL DEFAULT 0,
    next_probe_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_runtime_state_singleton CHECK (singleton),
    CONSTRAINT mail_runtime_state_mode_valid CHECK (mode IN ('fallback', 'active', 'disabled')),
    CONSTRAINT mail_runtime_state_revision_nonnegative CHECK (revision >= 0),
    CONSTRAINT mail_runtime_state_mode_consistent CHECK (
        (mode = 'fallback' AND active_version_id IS NULL AND previous_version_id IS NULL)
        OR (mode = 'active' AND active_version_id IS NOT NULL)
        OR (mode = 'disabled' AND active_version_id IS NULL)
    ),
    CONSTRAINT mail_runtime_state_version_pointers_distinct CHECK (
        (candidate_version_id IS NULL OR active_version_id IS NULL OR candidate_version_id <> active_version_id)
        AND (candidate_version_id IS NULL OR previous_version_id IS NULL OR candidate_version_id <> previous_version_id)
        AND (active_version_id IS NULL OR previous_version_id IS NULL OR active_version_id <> previous_version_id)
    ),
    CONSTRAINT mail_runtime_state_circuit_state_valid CHECK (circuit_state IN ('closed', 'open')),
    CONSTRAINT mail_runtime_state_transport_count_nonnegative CHECK (transport_failure_count >= 0),
    CONSTRAINT mail_runtime_state_transport_window_consistent CHECK (
        (transport_failure_count = 0 AND transport_failure_window_started_at IS NULL)
        OR (transport_failure_count > 0 AND transport_failure_window_started_at IS NOT NULL)
    ),
    CONSTRAINT mail_runtime_state_circuit_consistent CHECK (
        (
            circuit_state = 'closed'
            AND circuit_open_reason IS NULL
            AND circuit_open_category IS NULL
            AND circuit_opened_at IS NULL
            AND next_probe_at IS NULL
        )
        OR (
            circuit_state = 'open'
            AND btrim(circuit_open_reason) <> ''
            AND circuit_open_category IN ('configuration', 'authentication', 'tls', 'transport')
            AND circuit_opened_at IS NOT NULL
            AND next_probe_at IS NOT NULL
            AND next_probe_at > circuit_opened_at
        )
    ),
    CONSTRAINT mail_runtime_state_open_transport_consistent CHECK (
        circuit_state <> 'open'
        OR circuit_open_category <> 'transport'
        OR transport_failure_count >= 3
    ),
    CONSTRAINT mail_runtime_state_open_permanent_consistent CHECK (
        circuit_state <> 'open'
        OR circuit_open_category = 'transport'
        OR (transport_failure_count = 0 AND transport_failure_window_started_at IS NULL)
    )
);

INSERT INTO mail_runtime_state (singleton) VALUES (TRUE);

-- Configuration versions and test evidence are append-only even though the
-- runtime role receives generic table privileges after migration.
CREATE FUNCTION protect_mail_config_version_history() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.created_by IS NOT NULL
       AND NEW.created_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.revision IS NOT DISTINCT FROM OLD.revision
       AND NEW.host IS NOT DISTINCT FROM OLD.host
       AND NEW.port IS NOT DISTINCT FROM OLD.port
       AND NEW.username IS NOT DISTINCT FROM OLD.username
       AND NEW.password_ciphertext IS NOT DISTINCT FROM OLD.password_ciphertext
       AND NEW.tls_mode IS NOT DISTINCT FROM OLD.tls_mode
       AND NEW.from_address IS NOT DISTINCT FROM OLD.from_address
       AND NEW.from_name IS NOT DISTINCT FROM OLD.from_name
       AND NEW.public_base_url IS NOT DISTINCT FROM OLD.public_base_url
       AND NEW.connect_timeout_ms IS NOT DISTINCT FROM OLD.connect_timeout_ms
       AND NEW.send_timeout_ms IS NOT DISTINCT FROM OLD.send_timeout_ms
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE FUNCTION protect_mail_config_test_history() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.tested_by IS NOT NULL
       AND NEW.tested_by IS NULL
       AND NEW.id IS NOT DISTINCT FROM OLD.id
       AND NEW.version_id IS NOT DISTINCT FROM OLD.version_id
       AND NEW.recipient_hash IS NOT DISTINCT FROM OLD.recipient_hash
       AND NEW.result IS NOT DISTINCT FROM OLD.result
       AND NEW.error_category IS NOT DISTINCT FROM OLD.error_category
       AND NEW.created_at IS NOT DISTINCT FROM OLD.created_at THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER mail_config_versions_append_only
    BEFORE UPDATE OR DELETE ON mail_config_versions
    FOR EACH ROW EXECUTE FUNCTION protect_mail_config_version_history();

CREATE TRIGGER mail_config_tests_append_only
    BEFORE UPDATE OR DELETE ON mail_config_tests
    FOR EACH ROW EXECUTE FUNCTION protect_mail_config_test_history();
