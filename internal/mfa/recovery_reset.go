package mfa

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

type RecoveryResetScope string

const (
	RecoveryResetAll      RecoveryResetScope = "all"
	RecoveryResetTOTP     RecoveryResetScope = "totp"
	RecoveryResetPasskeys RecoveryResetScope = "passkeys"
)

var (
	ErrRecoveryTargetNotFound      = errors.New("MFA recovery target not found")
	ErrRecoveryNoFactors           = errors.New("selected MFA factors are not enrolled")
	ErrRecoveryPrimaryMethodNeeded = errors.New("reset would remove the last primary authentication method")
	ErrRecoveryAdminPolicyConflict = errors.New("administrator MFA policy would still prevent login")
)

type RecoveryResetInput struct {
	UserID                     uuid.UUID
	Username                   string
	Scope                      RecoveryResetScope
	Reason                     string
	DisableAdminMFARequirement bool
	ActorName                  string
	Now                        time.Time
}

type RecoveryResetReport struct {
	UserID                      uuid.UUID          `json:"user_id"`
	Username                    string             `json:"username"`
	Scope                       RecoveryResetScope `json:"scope"`
	RemovedTOTPCredentials      int64              `json:"removed_totp_credentials"`
	RemovedRecoveryCodes        int64              `json:"removed_recovery_codes"`
	RemovedPasskeys             int64              `json:"removed_passkeys"`
	PreservedPasskeyHandles     int64              `json:"preserved_passkey_handles"`
	AuthVersion                 int64              `json:"auth_version"`
	SessionVersion              int64              `json:"session_version"`
	AdminMFARequirementDisabled bool               `json:"admin_mfa_requirement_disabled"`
	SecurityRevision            int64              `json:"security_revision,omitempty"`
}

func ParseRecoveryResetScope(value string) (RecoveryResetScope, error) {
	scope := RecoveryResetScope(strings.ToLower(strings.TrimSpace(value)))
	switch scope {
	case RecoveryResetAll, RecoveryResetTOTP, RecoveryResetPasskeys:
		return scope, nil
	default:
		return "", fmt.Errorf("MFA reset scope must be all, totp, or passkeys")
	}
}

// ResetForRecovery is the audited break-glass path for an operator who cannot
// use the normal recently-authenticated MFA management endpoints.
func ResetForRecovery(ctx context.Context, db *pgxpool.Pool, input RecoveryResetInput) (RecoveryResetReport, error) {
	if db == nil {
		return RecoveryResetReport{}, fmt.Errorf("MFA recovery database is required")
	}
	scope, err := ParseRecoveryResetScope(string(input.Scope))
	if err != nil {
		return RecoveryResetReport{}, err
	}
	input.Scope = scope
	input.Username = strings.TrimSpace(input.Username)
	input.Reason = strings.TrimSpace(input.Reason)
	input.ActorName = strings.TrimSpace(input.ActorName)
	if (input.UserID == uuid.Nil) == (input.Username == "") {
		return RecoveryResetReport{}, fmt.Errorf("exactly one MFA recovery target is required")
	}
	if len(input.Reason) < 3 || len(input.Reason) > 500 {
		return RecoveryResetReport{}, fmt.Errorf("MFA recovery reason must contain 3 to 500 characters")
	}
	if input.ActorName == "" || len(input.ActorName) > 128 {
		return RecoveryResetReport{}, fmt.Errorf("valid MFA recovery actor name is required")
	}
	if input.Now.IsZero() {
		input.Now = time.Now().UTC()
	} else {
		input.Now = input.Now.UTC()
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return RecoveryResetReport{}, fmt.Errorf("starting MFA recovery reset: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockSecurityExclusive(ctx, tx); err != nil {
		return RecoveryResetReport{}, err
	}

	target, err := lockRecoveryTarget(ctx, tx, input)
	if err != nil {
		return RecoveryResetReport{}, err
	}
	counts, err := loadRecoveryFactorCounts(ctx, tx, target.id)
	if err != nil {
		return RecoveryResetReport{}, err
	}
	removeTOTP := input.Scope == RecoveryResetAll || input.Scope == RecoveryResetTOTP
	removePasskeys := input.Scope == RecoveryResetAll || input.Scope == RecoveryResetPasskeys
	if (removeTOTP && !removePasskeys && counts.totp == 0) ||
		(removePasskeys && !removeTOTP && counts.passkeys == 0) ||
		(removeTOTP && removePasskeys && counts.totp == 0 && counts.passkeys == 0) {
		return RecoveryResetReport{}, ErrRecoveryNoFactors
	}

	remainingPasskeys := counts.passkeys
	if removePasskeys {
		remainingPasskeys = 0
	}
	if !target.hasPassword && !target.hasEnabledIdentity && remainingPasskeys == 0 {
		return RecoveryResetReport{}, ErrRecoveryPrimaryMethodNeeded
	}
	remainingConfirmedTOTP := counts.confirmedTOTP
	if removeTOTP {
		remainingConfirmedTOTP = false
	}
	security, err := settings.LoadSecurityTx(ctx, tx)
	if err != nil {
		return RecoveryResetReport{}, err
	}
	report := RecoveryResetReport{
		UserID: target.id, Username: target.username, Scope: input.Scope,
		SessionVersion: target.sessionVersion,
	}
	if target.role == "admin" && target.status == "active" && security.RequireMFAForAdmins &&
		!remainingConfirmedTOTP && remainingPasskeys == 0 {
		if !input.DisableAdminMFARequirement {
			return RecoveryResetReport{}, ErrRecoveryAdminPolicyConflict
		}
		revision, err := disableAdminMFARequirementForRecovery(ctx, tx, input.ActorName, input.Reason, input.Now)
		if err != nil {
			return RecoveryResetReport{}, err
		}
		report.AdminMFARequirementDisabled = true
		report.SecurityRevision = revision
	}

	if removeTOTP {
		result, err := tx.Exec(ctx, `DELETE FROM user_totp_credentials WHERE user_id=$1`, target.id)
		if err != nil {
			return RecoveryResetReport{}, fmt.Errorf("removing TOTP during recovery: %w", err)
		}
		report.RemovedTOTPCredentials = result.RowsAffected()
		report.RemovedRecoveryCodes = counts.recoveryCodes
	}
	if removePasskeys {
		result, err := tx.Exec(ctx, `DELETE FROM user_passkey_credentials WHERE user_id=$1`, target.id)
		if err != nil {
			return RecoveryResetReport{}, fmt.Errorf("removing Passkeys during recovery: %w", err)
		}
		report.RemovedPasskeys = result.RowsAffected()
	}
	if err := tx.QueryRow(ctx, `
		UPDATE users SET auth_version=auth_version+1,updated_at=$2
		WHERE id=$1
		RETURNING auth_version,session_version
	`, target.id, input.Now).Scan(&report.AuthVersion, &report.SessionVersion); err != nil {
		return RecoveryResetReport{}, fmt.Errorf("advancing authentication version after MFA recovery: %w", err)
	}
	if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM user_passkey_handles WHERE user_id=$1`, target.id).Scan(&report.PreservedPasskeyHandles); err != nil {
		return RecoveryResetReport{}, fmt.Errorf("counting preserved Passkey handles: %w", err)
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, models.AuditMFARecoveryReset, nil, input.ActorName,
		"user", target.id.String(), "success", "critical", "", "",
		map[string]any{
			"reason": input.Reason, "scope": input.Scope,
			"removed_totp_credentials":       report.RemovedTOTPCredentials,
			"removed_recovery_codes":         report.RemovedRecoveryCodes,
			"removed_passkeys":               report.RemovedPasskeys,
			"admin_mfa_requirement_disabled": report.AdminMFARequirementDisabled,
		}, input.Now,
	); err != nil {
		return RecoveryResetReport{}, fmt.Errorf("auditing MFA recovery reset: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return RecoveryResetReport{}, fmt.Errorf("committing MFA recovery reset: %w", err)
	}
	return report, nil
}

type recoveryTarget struct {
	id                 uuid.UUID
	username           string
	role               string
	status             string
	authVersion        int64
	sessionVersion     int64
	hasPassword        bool
	hasEnabledIdentity bool
}

func lockRecoveryTarget(ctx context.Context, tx pgx.Tx, input RecoveryResetInput) (recoveryTarget, error) {
	query := `
		SELECT u.id,u.username,u.role,u.status,u.auth_version,u.session_version,
			u.password_hash IS NOT NULL,
			EXISTS (
				SELECT 1 FROM identities AS identity
				JOIN oauth_providers AS provider ON provider.name=identity.provider
				WHERE identity.user_id=u.id AND provider.enabled
			)
		FROM users AS u
		WHERE u.id=$1
		FOR UPDATE
	`
	argument := any(input.UserID)
	if input.UserID == uuid.Nil {
		query = strings.Replace(query, "u.id=$1", "u.username=$1", 1)
		argument = input.Username
	}
	var target recoveryTarget
	err := tx.QueryRow(ctx, query, argument).Scan(
		&target.id, &target.username, &target.role, &target.status,
		&target.authVersion, &target.sessionVersion, &target.hasPassword, &target.hasEnabledIdentity,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return recoveryTarget{}, ErrRecoveryTargetNotFound
	}
	if err != nil {
		return recoveryTarget{}, fmt.Errorf("locking MFA recovery target: %w", err)
	}
	return target, nil
}

type recoveryFactorCounts struct {
	totp          int64
	recoveryCodes int64
	passkeys      int64
	confirmedTOTP bool
}

func loadRecoveryFactorCounts(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (recoveryFactorCounts, error) {
	var counts recoveryFactorCounts
	err := tx.QueryRow(ctx, `
		SELECT
			(SELECT COUNT(*) FROM user_totp_credentials WHERE user_id=$1),
			(SELECT COUNT(*) FROM user_recovery_codes WHERE user_id=$1),
			(SELECT COUNT(*) FROM user_passkey_credentials WHERE user_id=$1),
			EXISTS (SELECT 1 FROM user_totp_credentials WHERE user_id=$1 AND confirmed_at IS NOT NULL)
	`, userID).Scan(&counts.totp, &counts.recoveryCodes, &counts.passkeys, &counts.confirmedTOTP)
	if err != nil {
		return recoveryFactorCounts{}, fmt.Errorf("loading MFA recovery factor counts: %w", err)
	}
	return counts, nil
}

func disableAdminMFARequirementForRecovery(
	ctx context.Context,
	tx pgx.Tx,
	actorName, reason string,
	now time.Time,
) (int64, error) {
	var revision int64
	err := tx.QueryRow(ctx, `
		UPDATE runtime_settings
		SET value=jsonb_set(value,'{require_mfa_for_admins}','false'::jsonb),
			revision=revision+1,updated_by=$1,updated_at=$2
		WHERE key='security' AND value->>'require_mfa_for_admins'='true'
		RETURNING revision
	`, actorName, now).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("administrator MFA policy changed during recovery")
	}
	if err != nil {
		return 0, fmt.Errorf("disabling administrator MFA requirement during recovery: %w", err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify('nyauth_settings_changed','security')`); err != nil {
		return 0, fmt.Errorf("notifying administrator MFA policy recovery: %w", err)
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, models.AuditSettingsUpdated, nil, actorName,
		"settings", "security", "success", "critical", "", "",
		map[string]any{
			"revision": revision, "require_mfa_for_admins": false,
			"reason": reason, "change_source": "mfa_break_glass",
		}, now,
	); err != nil {
		return 0, fmt.Errorf("auditing administrator MFA policy recovery: %w", err)
	}
	return revision, nil
}
