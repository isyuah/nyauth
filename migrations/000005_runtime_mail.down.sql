UPDATE email_outbox
SET status='expired', encrypted_message='', last_error=NULL,
    locked_at=NULL, locked_by=NULL, updated_at=NOW()
WHERE status='rejected';
DROP INDEX IF EXISTS idx_email_outbox_active_expiry;
ALTER TABLE email_outbox DROP CONSTRAINT email_outbox_status_valid;
ALTER TABLE email_outbox ADD CONSTRAINT email_outbox_status_valid
    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'expired'));

DROP TRIGGER IF EXISTS mail_config_tests_append_only ON mail_config_tests;
DROP TRIGGER IF EXISTS mail_config_versions_append_only ON mail_config_versions;
DROP TABLE IF EXISTS mail_runtime_state;
DROP TABLE IF EXISTS mail_config_tests;
DROP TABLE IF EXISTS mail_config_versions;
DROP FUNCTION IF EXISTS protect_mail_config_test_history();
DROP FUNCTION IF EXISTS protect_mail_config_version_history();
