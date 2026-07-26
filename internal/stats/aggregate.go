package stats

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type RegistrationDailyDelta struct {
	RegistrationsStarted   int64
	RegistrationsCompleted int64
	RegistrationsExpired   int64
	InvitesReserved        int64
	InvitesConsumed        int64
	InvitesReleased        int64
	CohortStarted          int64
	CohortCompleted        int64
}

func AddRegistrationDailyTx(ctx context.Context, tx pgx.Tx, eventAt time.Time, delta RegistrationDailyDelta) error {
	if tx == nil || eventAt.IsZero() {
		return fmt.Errorf("registration statistics transaction and timestamp are required")
	}
	if !validRegistrationDelta(delta) {
		return fmt.Errorf("registration statistics delta must be nonnegative")
	}
	if registrationDeltaTotal(delta) == 0 {
		return nil
	}
	day := utcDay(eventAt)
	_, err := tx.Exec(ctx, `
		INSERT INTO registration_stats_daily (
			day,registrations_started,registrations_completed,registrations_expired,
			invites_reserved,invites_consumed,invites_released,
			cohort_started,cohort_completed,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (day) DO UPDATE SET
			registrations_started=registration_stats_daily.registrations_started+EXCLUDED.registrations_started,
			registrations_completed=registration_stats_daily.registrations_completed+EXCLUDED.registrations_completed,
			registrations_expired=registration_stats_daily.registrations_expired+EXCLUDED.registrations_expired,
			invites_reserved=registration_stats_daily.invites_reserved+EXCLUDED.invites_reserved,
			invites_consumed=registration_stats_daily.invites_consumed+EXCLUDED.invites_consumed,
			invites_released=registration_stats_daily.invites_released+EXCLUDED.invites_released,
			cohort_started=registration_stats_daily.cohort_started+EXCLUDED.cohort_started,
			cohort_completed=registration_stats_daily.cohort_completed+EXCLUDED.cohort_completed,
			updated_at=EXCLUDED.updated_at
	`, day, delta.RegistrationsStarted, delta.RegistrationsCompleted, delta.RegistrationsExpired,
		delta.InvitesReserved, delta.InvitesConsumed, delta.InvitesReleased,
		delta.CohortStarted, delta.CohortCompleted, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("updating registration daily statistics: %w", err)
	}
	return nil
}

type MailDailyDelta struct {
	Enqueued       int64
	Sent           int64
	FailedAttempts int64
	Rejected       int64
	Expired        int64
}

func AddMailDailyTx(ctx context.Context, tx pgx.Tx, eventAt time.Time, delta MailDailyDelta) error {
	if tx == nil || eventAt.IsZero() {
		return fmt.Errorf("mail statistics transaction and timestamp are required")
	}
	if !validMailDelta(delta) {
		return fmt.Errorf("mail statistics delta must be nonnegative and rejected cannot exceed failures")
	}
	if mailDeltaTotal(delta) == 0 {
		return nil
	}
	day := utcDay(eventAt)
	_, err := tx.Exec(ctx, `
		INSERT INTO mail_stats_daily (
			day,enqueued,sent,failed_attempts,rejected,expired,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (day) DO UPDATE SET
			enqueued=mail_stats_daily.enqueued+EXCLUDED.enqueued,
			sent=mail_stats_daily.sent+EXCLUDED.sent,
			failed_attempts=mail_stats_daily.failed_attempts+EXCLUDED.failed_attempts,
			rejected=mail_stats_daily.rejected+EXCLUDED.rejected,
			expired=mail_stats_daily.expired+EXCLUDED.expired,
			updated_at=EXCLUDED.updated_at
	`, day, delta.Enqueued, delta.Sent, delta.FailedAttempts, delta.Rejected, delta.Expired, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("updating mail daily statistics: %w", err)
	}
	return nil
}

func AddMailFailureMinuteTx(ctx context.Context, tx pgx.Tx, failedAt time.Time, attempts int64) error {
	if tx == nil || failedAt.IsZero() || attempts < 1 {
		return fmt.Errorf("mail failure statistics require a transaction, timestamp, and positive attempt count")
	}
	minute := failedAt.UTC().Truncate(time.Minute)
	_, err := tx.Exec(ctx, `
		INSERT INTO mail_failure_stats_minute (minute,failed_attempts,updated_at)
		VALUES ($1,$2,$3)
		ON CONFLICT (minute) DO UPDATE SET
			failed_attempts=mail_failure_stats_minute.failed_attempts+EXCLUDED.failed_attempts,
			updated_at=EXCLUDED.updated_at
	`, minute, attempts, time.Now().UTC())
	if err != nil {
		return fmt.Errorf("updating mail failure minute statistics: %w", err)
	}
	return nil
}

func validRegistrationDelta(delta RegistrationDailyDelta) bool {
	return delta.RegistrationsStarted >= 0 && delta.RegistrationsCompleted >= 0 &&
		delta.RegistrationsExpired >= 0 && delta.InvitesReserved >= 0 &&
		delta.InvitesConsumed >= 0 && delta.InvitesReleased >= 0 &&
		delta.CohortStarted >= 0 && delta.CohortCompleted >= 0
}

func registrationDeltaTotal(delta RegistrationDailyDelta) int64 {
	return delta.RegistrationsStarted + delta.RegistrationsCompleted + delta.RegistrationsExpired +
		delta.InvitesReserved + delta.InvitesConsumed + delta.InvitesReleased +
		delta.CohortStarted + delta.CohortCompleted
}

func validMailDelta(delta MailDailyDelta) bool {
	return delta.Enqueued >= 0 && delta.Sent >= 0 && delta.FailedAttempts >= 0 &&
		delta.Rejected >= 0 && delta.Expired >= 0 && delta.Rejected <= delta.FailedAttempts
}

func mailDeltaTotal(delta MailDailyDelta) int64 {
	return delta.Enqueued + delta.Sent + delta.FailedAttempts + delta.Rejected + delta.Expired
}
