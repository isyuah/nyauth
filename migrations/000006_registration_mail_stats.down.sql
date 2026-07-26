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
