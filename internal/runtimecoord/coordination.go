// Package runtimecoord owns the PostgreSQL coordination primitives shared by
// self-registration and runtime mail. Keeping these locks in a dependency-free
// package prevents the registration, settings, account, and mailruntime
// packages from depending on each other merely to agree on lock ordering.
package runtimecoord

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	MailModeFallback = "fallback"
	MailModeActive   = "active"
	MailModeDisabled = "disabled"
	CircuitClosed    = "closed"

	// registrationMailLockKey is process-independent and intentionally scoped
	// to the invariant between self-registration and runtime SMTP state.
	registrationMailLockKey int64 = 0x4e5941555448
	// securityPolicyLockKey protects the invariant between the runtime MFA
	// policy, administrator role changes, and removal of administrator factors.
	securityPolicyLockKey int64 = 0x4e59414d4641
	// adminInvariantLockKey serializes transactions that check or change the
	// "at least one active administrator" invariant without blocking ordinary
	// writes to the users table.
	adminInvariantLockKey int64 = 0x4e594141444d
)

var (
	ErrMailRuntimeStateMissing = errors.New("mail runtime singleton state is missing")
	ErrMailDeliveryGateChanged = errors.New("mail delivery state changed")
	ErrMailCircuitOpen         = errors.New("mail delivery circuit is open")
)

// MailDeliveryGate identifies the exact persisted sender state represented by
// a process-local sender snapshot. VersionID is nil only for fallback mode.
type MailDeliveryGate struct {
	Mode      string
	VersionID *uuid.UUID
}

// LockRegistrationShared allows registrations to proceed concurrently while
// excluding registration-policy changes and SMTP disable operations.
func LockRegistrationShared(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, registrationMailLockKey); err != nil {
		return fmt.Errorf("locking registration and mail coordination shared: %w", err)
	}
	return nil
}

// LockRegistrationExclusive serializes changes that alter whether public
// registration and mail may be enabled together.
func LockRegistrationExclusive(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, registrationMailLockKey); err != nil {
		return fmt.Errorf("locking registration and mail coordination exclusive: %w", err)
	}
	return nil
}

// LockSecurityShared permits ordinary factor and role operations to proceed
// concurrently while excluding a security-policy transition.
func LockSecurityShared(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, securityPolicyLockKey); err != nil {
		return fmt.Errorf("locking security policy shared: %w", err)
	}
	return nil
}

// LockSecurityExclusive serializes a runtime security-policy transition with
// administrator role changes and factor removal.
func LockSecurityExclusive(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, securityPolicyLockKey); err != nil {
		return fmt.Errorf("locking security policy exclusive: %w", err)
	}
	return nil
}

// LockAdminInvariant serializes admin status/role mutations, deletions, and
// bootstrap so the active-administrator count cannot be raced, while leaving
// ordinary users-table writes (logins, registrations) unblocked.
func LockAdminInvariant(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, adminInvariantLockKey); err != nil {
		return fmt.Errorf("locking administrator invariant: %w", err)
	}
	return nil
}

// RequireMailDeliveryGate locks the singleton mail row for shared access and
// verifies that the persisted state still represents the supplied local sender
// and has a closed circuit. The row lock is held until the caller commits.
func RequireMailDeliveryGate(ctx context.Context, tx pgx.Tx, expected MailDeliveryGate) error {
	mode, versionID, circuitState, err := lockMailStateShared(ctx, tx)
	if err != nil {
		return err
	}
	if circuitState != CircuitClosed {
		return ErrMailCircuitOpen
	}
	if mode != expected.Mode || !sameVersion(versionID, expected.VersionID) {
		return ErrMailDeliveryGateChanged
	}
	switch expected.Mode {
	case MailModeFallback:
		if expected.VersionID != nil {
			return ErrMailDeliveryGateChanged
		}
	case MailModeActive:
		if expected.VersionID == nil {
			return ErrMailDeliveryGateChanged
		}
	default:
		return ErrMailDeliveryGateChanged
	}
	return nil
}

// MailConfigured locks and reads the authoritative mail state. Fallback
// configuration is process-local, so callers explicitly supply whether this
// instance has a bootstrap fallback configured.
func MailConfigured(ctx context.Context, tx pgx.Tx, fallbackConfigured bool) (bool, error) {
	mode, versionID, _, err := lockMailStateShared(ctx, tx)
	if err != nil {
		return false, err
	}
	switch mode {
	case MailModeFallback:
		return fallbackConfigured && versionID == nil, nil
	case MailModeActive:
		return versionID != nil, nil
	case MailModeDisabled:
		return false, nil
	default:
		return false, nil
	}
}

func lockMailStateShared(ctx context.Context, tx pgx.Tx) (string, *uuid.UUID, string, error) {
	var mode, circuitState string
	var versionID *uuid.UUID
	err := tx.QueryRow(ctx, `
		SELECT mode,active_version_id,circuit_state
		FROM mail_runtime_state
		WHERE singleton=TRUE
		FOR SHARE
	`).Scan(&mode, &versionID, &circuitState)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, "", ErrMailRuntimeStateMissing
	}
	if err != nil {
		return "", nil, "", fmt.Errorf("locking mail runtime state shared: %w", err)
	}
	return mode, versionID, circuitState, nil
}

func sameVersion(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
