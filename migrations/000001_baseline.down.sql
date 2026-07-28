-- Nyauth 0.3.0-rc.1 release baseline rollback.

-- Folded from 000010_admin_user_insights.down.sql
DROP INDEX IF EXISTS idx_audit_logs_target_created;
DROP INDEX IF EXISTS idx_users_created_by;

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_created_by_fkey,
    DROP CONSTRAINT IF EXISTS users_created_by_not_self,
    DROP CONSTRAINT IF EXISTS users_created_by_source_valid,
    DROP CONSTRAINT IF EXISTS users_creation_source_valid,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS creation_source;

-- Folded from 000009_avatar_media.down.sql
ALTER TABLE oauth_providers DROP CONSTRAINT IF EXISTS oauth_providers_generic_avatar_allowlist_required;
ALTER TABLE oauth_providers DROP CONSTRAINT IF EXISTS oauth_providers_avatar_allowed_hosts_no_null;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS avatar_allowed_hosts;
ALTER TABLE oauth_providers DROP COLUMN IF EXISTS import_avatar;

DROP TABLE IF EXISTS provider_avatar_import_jobs;

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_current_avatar_fk;
ALTER TABLE users ADD COLUMN avatar_url TEXT;
ALTER TABLE users DROP COLUMN IF EXISTS current_avatar_id;

DROP TABLE IF EXISTS user_avatars;

-- Folded from 000008_passkeys.down.sql
-- Version 7 does not understand the Passkey enrollment switch. Remove only
-- that JSON member while preserving the TOTP and administrator MFA policy.
UPDATE runtime_settings
SET value = value - 'passkeys_enabled', updated_at = NOW()
WHERE key = 'security';

DROP TABLE IF EXISTS user_passkey_credentials;
DROP TABLE IF EXISTS user_passkey_handles;

-- Folded from 000007_totp_mfa.down.sql
-- Security policy storage is introduced by Phase T even though it lives in
-- the shared runtime_settings table. Version 6 must not retain a policy that
-- depends on MFA tables which no longer exist.
DELETE FROM runtime_settings WHERE key = 'security';

DROP TABLE IF EXISTS user_recovery_codes;
DROP TABLE IF EXISTS user_totp_credentials;

-- Folded from 000006_registration_mail_stats.down.sql
DROP INDEX IF EXISTS idx_email_outbox_active_created;

ALTER TABLE system_stats_snapshot
    DROP CONSTRAINT IF EXISTS system_stats_snapshot_smtp_circuit_valid,
    DROP CONSTRAINT IF EXISTS system_stats_snapshot_registration_mail_nonnegative,
    DROP COLUMN IF EXISTS smtp_circuit_state,
    DROP COLUMN IF EXISTS mail_failures_24h,
    DROP COLUMN IF EXISTS mail_backlog,
    DROP COLUMN IF EXISTS registration_completed_30d,
    DROP COLUMN IF EXISTS registration_started_30d,
    DROP COLUMN IF EXISTS completed_registrations_7d,
    DROP COLUMN IF EXISTS pending_registrations;

DROP TABLE IF EXISTS stats_observability_state;
DROP TABLE IF EXISTS mail_failure_stats_minute;
DROP TABLE IF EXISTS mail_stats_daily;
DROP TABLE IF EXISTS registration_stats_daily;

-- Folded from 000005_runtime_mail.down.sql
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

-- Folded from 000004_invites.down.sql
DROP TABLE IF EXISTS self_registrations;
DROP TABLE IF EXISTS invites;

-- Folded from 000003_client_access_policy.down.sql
DROP TABLE IF EXISTS client_access_users;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS access_policy;

-- Folded from 000002_runtime_settings.down.sql
DROP TABLE IF EXISTS runtime_settings;

-- Folded from 000001_baseline.down.sql
DROP TABLE IF EXISTS login_stats_daily;
DROP TABLE IF EXISTS system_stats_snapshot;
DROP TABLE IF EXISTS audit_event_outbox;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS email_outbox;
DROP TABLE IF EXISTS account_action_tokens;
DROP TABLE IF EXISTS oauth_authorizations;
DROP TABLE IF EXISTS identities;
DROP TABLE IF EXISTS oauth_providers;
DROP TABLE IF EXISTS jwk_keys;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS users;
