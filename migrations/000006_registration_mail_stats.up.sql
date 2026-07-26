-- Low-cardinality registration and email observability aggregates.
-- NOTE: fold into the 000001 baseline when cutting the 0.3.0 release.
CREATE TABLE registration_stats_daily (
    day DATE PRIMARY KEY,
    registrations_started BIGINT NOT NULL DEFAULT 0,
    registrations_completed BIGINT NOT NULL DEFAULT 0,
    registrations_expired BIGINT NOT NULL DEFAULT 0,
    invites_reserved BIGINT NOT NULL DEFAULT 0,
    invites_consumed BIGINT NOT NULL DEFAULT 0,
    invites_released BIGINT NOT NULL DEFAULT 0,
    cohort_started BIGINT NOT NULL DEFAULT 0,
    cohort_completed BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT registration_stats_daily_nonnegative CHECK (
        registrations_started >= 0
        AND registrations_completed >= 0
        AND registrations_expired >= 0
        AND invites_reserved >= 0
        AND invites_consumed >= 0
        AND invites_released >= 0
        AND cohort_started >= 0
        AND cohort_completed >= 0
    )
);

CREATE TABLE mail_stats_daily (
    day DATE PRIMARY KEY,
    enqueued BIGINT NOT NULL DEFAULT 0,
    sent BIGINT NOT NULL DEFAULT 0,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    rejected BIGINT NOT NULL DEFAULT 0,
    expired BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_stats_daily_nonnegative CHECK (
        enqueued >= 0
        AND sent >= 0
        AND failed_attempts >= 0
        AND rejected >= 0
        AND expired >= 0
        AND rejected <= failed_attempts
    )
);

-- A minute bucket keeps the rolling 24-hour failure count accurate to within
-- one minute without retaining one row per delivery attempt.
CREATE TABLE mail_failure_stats_minute (
    minute TIMESTAMPTZ PRIMARY KEY,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT mail_failure_stats_minute_aligned CHECK (
        minute = date_trunc('minute', minute)
    ),
    CONSTRAINT mail_failure_stats_minute_nonnegative CHECK (failed_attempts >= 0)
);

-- Schema 5 has only final outbox state and cannot reconstruct historical
-- delivery attempts after retries or user deletion. Expose this boundary
-- instead of presenting unavailable pre-migration history as observed zeros.
CREATE TABLE stats_observability_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE,
    mail_stats_available_from TIMESTAMPTZ NOT NULL,
    CONSTRAINT stats_observability_state_singleton CHECK (singleton)
);
INSERT INTO stats_observability_state (singleton, mail_stats_available_from)
VALUES (TRUE, NOW());

ALTER TABLE system_stats_snapshot
    ADD COLUMN pending_registrations BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN completed_registrations_7d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN registration_started_30d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN registration_completed_30d BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN mail_backlog BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN mail_failures_24h BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN smtp_circuit_state VARCHAR(16) NOT NULL DEFAULT 'closed';

ALTER TABLE system_stats_snapshot
    ADD CONSTRAINT system_stats_snapshot_registration_mail_nonnegative CHECK (
        pending_registrations >= 0
        AND completed_registrations_7d >= 0
        AND registration_started_30d >= 0
        AND registration_completed_30d >= 0
        AND registration_completed_30d <= registration_started_30d
        AND mail_backlog >= 0
        AND mail_failures_24h >= 0
    ),
    ADD CONSTRAINT system_stats_snapshot_smtp_circuit_valid CHECK (
        smtp_circuit_state IN ('closed', 'open')
    );

CREATE INDEX idx_email_outbox_active_created
    ON email_outbox (created_at)
    WHERE status IN ('pending', 'failed', 'sending');

-- Registration lifecycle rows retain enough timestamps to backfill their
-- event and cohort aggregates exactly. Mail delivery attempts do not, so mail
-- aggregates intentionally begin at stats_observability_state's timestamp.
INSERT INTO registration_stats_daily (
    day, registrations_started, invites_reserved, cohort_started, updated_at
)
SELECT
    (created_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (
        WHERE invite_id IS NOT NULL
          AND (status IN ('pending', 'released') OR completed_at > created_at)
    ),
    COUNT(*),
    NOW()
FROM self_registrations
GROUP BY (created_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_started = registration_stats_daily.registrations_started + EXCLUDED.registrations_started,
    invites_reserved = registration_stats_daily.invites_reserved + EXCLUDED.invites_reserved,
    cohort_started = registration_stats_daily.cohort_started + EXCLUDED.cohort_started,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (
    day, registrations_completed, invites_consumed, updated_at
)
SELECT
    (completed_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (WHERE invite_id IS NOT NULL),
    NOW()
FROM self_registrations
WHERE status = 'completed'
GROUP BY (completed_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_completed = registration_stats_daily.registrations_completed + EXCLUDED.registrations_completed,
    invites_consumed = registration_stats_daily.invites_consumed + EXCLUDED.invites_consumed,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (day, cohort_completed, updated_at)
SELECT
    (created_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    NOW()
FROM self_registrations
WHERE status = 'completed'
GROUP BY (created_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    cohort_completed = registration_stats_daily.cohort_completed + EXCLUDED.cohort_completed,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (
    day, registrations_expired, invites_released, updated_at
)
SELECT
    (expires_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    COUNT(*) FILTER (WHERE invite_id IS NOT NULL),
    NOW()
FROM self_registrations
WHERE status = 'released' AND release_reason = 'expired'
GROUP BY (expires_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    registrations_expired = registration_stats_daily.registrations_expired + EXCLUDED.registrations_expired,
    invites_released = registration_stats_daily.invites_released + EXCLUDED.invites_released,
    updated_at = EXCLUDED.updated_at;

INSERT INTO registration_stats_daily (day, invites_released, updated_at)
SELECT
    (released_at AT TIME ZONE 'UTC')::date,
    COUNT(*),
    NOW()
FROM self_registrations
WHERE status = 'released'
  AND release_reason <> 'expired'
  AND invite_id IS NOT NULL
GROUP BY (released_at AT TIME ZONE 'UTC')::date
ON CONFLICT (day) DO UPDATE SET
    invites_released = registration_stats_daily.invites_released + EXCLUDED.invites_released,
    updated_at = EXCLUDED.updated_at;
