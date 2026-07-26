// Package registration owns the durable lifecycle of public self-registration
// records and invitation reservations.
package registration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	registrationstats "github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	StatusPending   = "pending"
	StatusCompleted = "completed"
	StatusReleased  = "released"

	ReleaseReasonExpired      = "expired"
	ReleaseReasonAdminDeleted = "admin_deleted"
)

var ErrInviteInvalid = errors.New("invite code is invalid or no longer usable")

// AuditContext carries request metadata for lifecycle events. ActorID may be
// nil for background maintenance.
type AuditContext struct {
	ActorID   *uuid.UUID
	ActorName string
	IPAddress string
	UserAgent string
}

// Transition identifies a registration row changed by a lifecycle operation.
type Transition struct {
	RegistrationID uuid.UUID
	InviteID       *uuid.UUID
	CreatedAt      time.Time
	Changed        bool
}

// ReserveInviteTx locks a usable invite and verifies capacity. The lock is
// held until the caller inserts the registration row and commits, serializing
// contenders for the final available slot.
func ReserveInviteTx(ctx context.Context, tx pgx.Tx, codeHash string, now time.Time) (*uuid.UUID, error) {
	var inviteID uuid.UUID
	var maxUses int
	err := tx.QueryRow(ctx, `
		SELECT id,max_uses FROM invites
		WHERE code_hash=$1 AND revoked_at IS NULL AND expires_at>$2
		FOR UPDATE
	`, codeHash, now.UTC()).Scan(&inviteID, &maxUses)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrInviteInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("locking invite: %w", err)
	}

	var occupied int
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM self_registrations
		WHERE invite_id=$1 AND status IN ('pending','completed')
	`, inviteID).Scan(&occupied); err != nil {
		return nil, fmt.Errorf("counting invite reservations: %w", err)
	}
	if occupied >= maxUses {
		return nil, ErrInviteInvalid
	}
	return &inviteID, nil
}

// InsertTx persists the lifecycle record after the caller has inserted the
// corresponding user in the same transaction.
func InsertTx(
	ctx context.Context,
	tx pgx.Tx,
	registrationID, userID uuid.UUID,
	inviteID *uuid.UUID,
	status string,
	expiresAt, now time.Time,
) error {
	var completedAt *time.Time
	if status == StatusCompleted {
		completed := now.UTC()
		completedAt = &completed
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO self_registrations (
			id,user_id,invite_id,status,expires_at,completed_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
	`, registrationID, userID, inviteID, status, expiresAt.UTC(), completedAt, now.UTC())
	if err != nil {
		return fmt.Errorf("inserting self-registration: %w", err)
	}
	delta := registrationstats.RegistrationDailyDelta{
		RegistrationsStarted: 1,
		CohortStarted:        1,
	}
	if inviteID != nil && status == StatusPending {
		delta.InvitesReserved = 1
	}
	if status == StatusCompleted {
		delta.RegistrationsCompleted = 1
		delta.CohortCompleted = 1
		if inviteID != nil {
			delta.InvitesConsumed = 1
		}
	}
	if err := registrationstats.AddRegistrationDailyTx(ctx, tx, now, delta); err != nil {
		return fmt.Errorf("recording self-registration statistics: %w", err)
	}
	return nil
}

// CompleteForUserTx converts a pending reservation into a consumed
// registration. Email verification observes the persisted deadline, while an
// explicit administrator activation may complete an expired reservation.
func CompleteForUserTx(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	now time.Time,
	allowExpired bool,
	source string,
	actor AuditContext,
) (Transition, error) {
	var result Transition
	err := tx.QueryRow(ctx, `
		UPDATE self_registrations
		SET status='completed',completed_at=$2,updated_at=$2
		WHERE user_id=$1 AND status='pending' AND ($3 OR expires_at>$2)
		RETURNING id,invite_id,created_at
	`, userID, now.UTC(), allowExpired).Scan(&result.RegistrationID, &result.InviteID, &result.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, nil
	}
	if err != nil {
		return Transition{}, fmt.Errorf("completing self-registration: %w", err)
	}
	result.Changed = true
	completionDelta := registrationstats.RegistrationDailyDelta{RegistrationsCompleted: 1}
	if result.InviteID != nil {
		completionDelta.InvitesConsumed = 1
	}
	if err := registrationstats.AddRegistrationDailyTx(ctx, tx, now, completionDelta); err != nil {
		return Transition{}, fmt.Errorf("recording completed registration statistics: %w", err)
	}
	if err := registrationstats.AddRegistrationDailyTx(ctx, tx, result.CreatedAt, registrationstats.RegistrationDailyDelta{
		CohortCompleted: 1,
	}); err != nil {
		return Transition{}, fmt.Errorf("recording registration cohort completion: %w", err)
	}
	if result.InviteID != nil {
		if err := enqueueInviteEventTx(ctx, tx, models.AuditInviteConsumed, *result.InviteID, result.RegistrationID, userID, source, "", actor, now); err != nil {
			return Transition{}, err
		}
	}
	return result, nil
}

// ReleaseForUserTx releases an unconsumed reservation before the user is
// deleted. Completed registrations are intentionally left untouched.
func ReleaseForUserTx(
	ctx context.Context,
	tx pgx.Tx,
	userID uuid.UUID,
	now time.Time,
	reason, source string,
	actor AuditContext,
) (Transition, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 64 {
		return Transition{}, fmt.Errorf("registration release reason is invalid")
	}
	var result Transition
	err := tx.QueryRow(ctx, `
		UPDATE self_registrations
		SET status='released',released_at=$2,release_reason=$3,updated_at=$2
		WHERE user_id=$1 AND status='pending'
		RETURNING id,invite_id
	`, userID, now.UTC(), reason).Scan(&result.RegistrationID, &result.InviteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Transition{}, nil
	}
	if err != nil {
		return Transition{}, fmt.Errorf("releasing self-registration: %w", err)
	}
	result.Changed = true
	if result.InviteID != nil {
		if err := registrationstats.AddRegistrationDailyTx(ctx, tx, now, registrationstats.RegistrationDailyDelta{
			InvitesReleased: 1,
		}); err != nil {
			return Transition{}, fmt.Errorf("recording released invite statistics: %w", err)
		}
	}
	if result.InviteID != nil {
		if err := enqueueInviteEventTx(ctx, tx, models.AuditInviteReleased, *result.InviteID, result.RegistrationID, userID, source, reason, actor, now); err != nil {
			return Transition{}, err
		}
	}
	return result, nil
}

func enqueueInviteEventTx(
	ctx context.Context,
	tx pgx.Tx,
	event string,
	inviteID, registrationID, userID uuid.UUID,
	source, reason string,
	actor AuditContext,
	now time.Time,
) error {
	details := map[string]any{
		"registration_id": registrationID.String(),
		"user_id":         userID.String(),
		"source":          source,
	}
	if reason != "" {
		details["release_reason"] = reason
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, event, actor.ActorID, actor.ActorName, "invite", inviteID.String(),
		"success", "low", actor.IPAddress, actor.UserAgent, details, now,
	); err != nil {
		return fmt.Errorf("auditing registration invite transition: %w", err)
	}
	return nil
}
