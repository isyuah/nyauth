package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (m *Manager) SetProtection(
	ctx context.Context,
	value Protection,
	expectedRevision int64,
	updatedBy string,
	disableConfirmation string,
	mutation audit.MutationAudit,
) (int64, error) {
	if err := ValidateProtection(value); err != nil {
		return 0, err
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return 0, errors.New("runtime settings storage is unavailable")
	}
	if err := mutation.ValidateEvent(models.AuditSettingsUpdated); err != nil {
		return 0, fmt.Errorf("validating protection settings audit: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0, fmt.Errorf("encoding protection settings: %w", err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting protection settings transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockClientQuotaExclusive(ctx, tx); err != nil {
		return 0, err
	}
	previous, _, err := loadProtectionTx(ctx, tx)
	if err != nil {
		return 0, err
	}
	if ProtectionDisables(previous, value) && disableConfirmation != ProtectionDisableConfirmation {
		return 0, ErrProtectionDisableConfirmation
	}
	revision, err := storeSettingTx(ctx, tx, protectionKey, encoded, expectedRevision, updatedBy)
	if err != nil {
		return 0, err
	}
	mutation = mutation.WithTarget("settings", protectionKey).WithDetails(map[string]any{
		"revision":                   revision,
		"login_enabled":              value.Login.Enabled,
		"account_enabled":            value.Account.Enabled,
		"avatar_enabled":             value.Avatar.Enabled,
		"mail_enabled":               value.Mail.Enabled,
		"owned_client_default_limit": value.OwnedClientDefaultLimit,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing protection settings: %w", err)
	}
	if err := notifySettingTx(ctx, tx, protectionKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing protection settings: %w", err)
	}
	m.protection.Store(&Versioned[Protection]{Revision: revision, Value: value})
	return revision, nil
}

func (m *Manager) SetLifecycle(
	ctx context.Context,
	value Lifecycle,
	expectedRevision int64,
	updatedBy string,
	retentionConfirmation string,
	mutation audit.MutationAudit,
) (int64, error) {
	if err := ValidateLifecycle(value); err != nil {
		return 0, err
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return 0, errors.New("runtime settings storage is unavailable")
	}
	if err := mutation.ValidateEvent(models.AuditSettingsUpdated); err != nil {
		return 0, fmt.Errorf("validating lifecycle settings audit: %w", err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0, fmt.Errorf("encoding lifecycle settings: %w", err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting lifecycle settings transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	previous, _, err := loadLifecycleTx(ctx, tx, m.lifecycleDefaults())
	if err != nil {
		return 0, err
	}
	if value.AuditRetentionDays < previous.AuditRetentionDays &&
		retentionConfirmation != RetentionConfirmation(value.AuditRetentionDays) {
		return 0, ErrRetentionConfirmation
	}
	revision, err := storeSettingTx(ctx, tx, lifecycleKey, encoded, expectedRevision, updatedBy)
	if err != nil {
		return 0, err
	}
	mutation = mutation.WithTarget("settings", lifecycleKey).WithDetails(map[string]any{
		"revision":                     revision,
		"session_absolute_ttl":         value.SessionAbsoluteTTL,
		"session_idle_ttl":             value.SessionIdleTTL,
		"max_concurrent_sessions":      value.MaxConcurrentSessions,
		"recent_authentication_ttl":    value.RecentAuthenticationTTL,
		"access_credential_lifetime":   value.AccessTokenTTL,
		"refresh_credential_lifetime":  value.RefreshTokenTTL,
		"authorization_grant_lifetime": value.AuthorizationCodeTTL,
		"audit_retention_days":         value.AuditRetentionDays,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing lifecycle settings: %w", err)
	}
	if err := notifySettingTx(ctx, tx, lifecycleKey); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing lifecycle settings: %w", err)
	}
	m.lifecycle.Store(&Versioned[Lifecycle]{Revision: revision, Value: value})
	return revision, nil
}

func (m *Manager) storeAudited(
	ctx context.Context,
	key string,
	value any,
	expectedRevision int64,
	updatedBy string,
	mutation audit.MutationAudit,
	details map[string]any,
) (int64, error) {
	if m.db == nil {
		return 0, errors.New("runtime settings storage is unavailable")
	}
	if err := mutation.ValidateEvent(models.AuditSettingsUpdated); err != nil {
		return 0, fmt.Errorf("validating %s settings audit: %w", key, err)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return 0, fmt.Errorf("encoding %s settings: %w", key, err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("starting %s settings transaction: %w", key, err)
	}
	defer tx.Rollback(ctx)
	revision, err := storeSettingTx(ctx, tx, key, encoded, expectedRevision, updatedBy)
	if err != nil {
		return 0, err
	}
	if details == nil {
		details = make(map[string]any)
	}
	details["revision"] = revision
	mutation = mutation.WithTarget("settings", key).WithDetails(details)
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return 0, fmt.Errorf("auditing %s settings: %w", key, err)
	}
	if err := notifySettingTx(ctx, tx, key); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("committing %s settings: %w", key, err)
	}
	return revision, nil
}

func storeSettingTx(
	ctx context.Context,
	tx pgx.Tx,
	key string,
	encoded []byte,
	expectedRevision int64,
	updatedBy string,
) (int64, error) {
	if expectedRevision < 0 {
		return 0, fmt.Errorf("expected_revision must not be negative")
	}
	var revision int64
	if expectedRevision == 0 {
		err := tx.QueryRow(ctx, `
			INSERT INTO runtime_settings (key,value,revision,updated_by,updated_at)
			VALUES ($1,$2,1,$3,now())
			ON CONFLICT (key) DO NOTHING
			RETURNING revision
		`, key, encoded, updatedBy).Scan(&revision)
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrRevisionConflict
		}
		if err != nil {
			return 0, fmt.Errorf("storing %s settings: %w", key, err)
		}
		return revision, nil
	}
	err := tx.QueryRow(ctx, `
		UPDATE runtime_settings
		SET value=$2,revision=revision+1,updated_by=$3,updated_at=now()
		WHERE key=$1 AND revision=$4
		RETURNING revision
	`, key, encoded, updatedBy, expectedRevision).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("storing %s settings: %w", key, err)
	}
	return revision, nil
}

func notifySettingTx(ctx context.Context, tx pgx.Tx, key string) error {
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notificationChannel, key); err != nil {
		return fmt.Errorf("notifying %s settings change: %w", key, err)
	}
	return nil
}

func loadProtectionTx(ctx context.Context, tx pgx.Tx) (Protection, int64, error) {
	value := DefaultProtection()
	var raw []byte
	var revision int64
	err := tx.QueryRow(ctx, `SELECT value,revision FROM runtime_settings WHERE key=$1`, protectionKey).Scan(&raw, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, 0, nil
	}
	if err != nil {
		return Protection{}, 0, fmt.Errorf("loading protection settings: %w", err)
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return Protection{}, 0, fmt.Errorf("decoding protection settings: %w", err)
	}
	if err := ValidateProtection(value); err != nil {
		return Protection{}, 0, err
	}
	return value, revision, nil
}

func loadLifecycleTx(ctx context.Context, tx pgx.Tx, defaults Lifecycle) (Lifecycle, int64, error) {
	value := defaults
	var raw []byte
	var revision int64
	err := tx.QueryRow(ctx, `SELECT value,revision FROM runtime_settings WHERE key=$1`, lifecycleKey).Scan(&raw, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, 0, nil
	}
	if err != nil {
		return Lifecycle{}, 0, fmt.Errorf("loading lifecycle settings: %w", err)
	}
	value, err = decodeLifecycle(raw, defaults)
	if err != nil {
		return Lifecycle{}, 0, err
	}
	return value, revision, nil
}

// ResolveAuditRetention reads only the lifecycle row so maintenance does not
// depend on unrelated runtime setting groups being decodable.
func ResolveAuditRetention(
	ctx context.Context,
	db *pgxpool.Pool,
	fallback time.Duration,
) (time.Duration, error) {
	fallbackDays := int(fallback / (24 * time.Hour))
	value := DefaultLifecycle(fallbackDays)
	var raw []byte
	err := db.QueryRow(ctx, `SELECT value FROM runtime_settings WHERE key=$1`, lifecycleKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Duration(value.AuditRetentionDays) * 24 * time.Hour, nil
	}
	if err != nil {
		return 0, fmt.Errorf("loading audit retention policy: %w", err)
	}
	value, err = decodeLifecycle(raw, value)
	if err != nil {
		return 0, fmt.Errorf("decoding audit retention policy: %w", err)
	}
	return time.Duration(value.AuditRetentionDays) * 24 * time.Hour, nil
}
