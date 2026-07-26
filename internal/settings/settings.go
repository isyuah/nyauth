// Package settings stores operational settings that administrators may change
// at runtime without restarting the service. Deployment-shape configuration
// (issuer, keys, connection strings) deliberately stays in the config file.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
)

const (
	brandingKey            = "branding"
	registrationKey        = "registration"
	notificationChannel    = "nyauth_settings_changed"
	reconciliationInterval = 60 * time.Second
)

var (
	ErrRegistrationChanged     = errors.New("registration settings changed")
	ErrMailConfigurationNeeded = errors.New("mail configuration is required for self-registration")
)

// Branding holds the values the web UI uses to present the deployment
// (sidebar wordmark, login heading, logo).
type Branding struct {
	Title   string `json:"title"`
	LogoURL string `json:"logo_url"`
}

// Registration modes for public self-registration.
const (
	RegistrationClosed     = "closed"
	RegistrationInviteOnly = "invite_only"
	RegistrationOpen       = "open"
)

// ValidRegistrationMode reports whether the value is a known mode.
func ValidRegistrationMode(mode string) bool {
	switch mode {
	case RegistrationClosed, RegistrationInviteOnly, RegistrationOpen:
		return true
	}
	return false
}

// Registration controls public self-registration and invite defaults.
type Registration struct {
	Mode                     string   `json:"mode"`
	RequireEmailVerification bool     `json:"require_email_verification"`
	AllowedEmailDomains      []string `json:"allowed_email_domains"`
	PendingRegistrationTTL   string   `json:"pending_registration_ttl"`
	InviteDefaultTTL         string   `json:"invite_default_ttl"`
	InviteDefaultMaxUses     int      `json:"invite_default_max_uses"`
}

// DefaultRegistration returns the safe out-of-the-box registration settings:
// self-registration disabled, verification required once it is opened.
func DefaultRegistration() Registration {
	return Registration{
		Mode:                     RegistrationClosed,
		RequireEmailVerification: true,
		AllowedEmailDomains:      []string{},
		PendingRegistrationTTL:   "72h",
		InviteDefaultTTL:         "168h",
		InviteDefaultMaxUses:     1,
	}
}

// Manager caches the current settings snapshot and keeps it consistent across
// instances with the same LISTEN/NOTIFY + reconciliation pattern the provider
// manager uses. Config values act as defaults when nothing is stored yet.
type Manager struct {
	db               *pgxpool.Pool
	brandingDefaults Branding
	branding         atomic.Pointer[Branding]
	registration     atomic.Pointer[Registration]
	loadMu           sync.Mutex
}

func NewManager(db *pgxpool.Pool, brandingDefaults Branding) *Manager {
	return &Manager{db: db, brandingDefaults: brandingDefaults}
}

// Branding returns the stored branding, or the config defaults before the
// first successful load and when nothing has been stored.
func (m *Manager) Branding() Branding {
	if snapshot := m.branding.Load(); snapshot != nil {
		return *snapshot
	}
	return m.brandingDefaults
}

// Registration returns the stored registration settings or the safe defaults.
func (m *Manager) Registration() Registration {
	if snapshot := m.registration.Load(); snapshot != nil {
		return *snapshot
	}
	return DefaultRegistration()
}

// Load refreshes every settings group from the database. Missing rows reset
// the corresponding group to its defaults so deletes propagate too.
func (m *Manager) Load(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return nil
	}
	rows, err := m.db.Query(ctx, `SELECT key, value FROM runtime_settings WHERE key = ANY($1)`,
		[]string{brandingKey, registrationKey})
	if err != nil {
		return fmt.Errorf("loading runtime settings: %w", err)
	}
	defer rows.Close()
	stored := map[string][]byte{}
	for rows.Next() {
		var key string
		var value []byte
		if err := rows.Scan(&key, &value); err != nil {
			return fmt.Errorf("scanning runtime setting: %w", err)
		}
		stored[key] = value
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading runtime settings: %w", err)
	}

	if raw, ok := stored[brandingKey]; ok {
		branding := m.brandingDefaults
		if err := json.Unmarshal(raw, &branding); err != nil {
			return fmt.Errorf("decoding stored branding: %w", err)
		}
		m.branding.Store(&branding)
	} else {
		m.branding.Store(nil)
	}

	if raw, ok := stored[registrationKey]; ok {
		registration := DefaultRegistration()
		if err := json.Unmarshal(raw, &registration); err != nil {
			return fmt.Errorf("decoding stored registration settings: %w", err)
		}
		m.registration.Store(&registration)
	} else {
		m.registration.Store(nil)
	}
	return nil
}

// SetBranding persists the branding, refreshes the local snapshot, and
// notifies other instances. Validation is the caller's responsibility.
func (m *Manager) SetBranding(ctx context.Context, branding Branding, updatedBy string) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if err := m.store(ctx, brandingKey, branding, updatedBy); err != nil {
		return err
	}
	m.branding.Store(&branding)
	m.notify(ctx, brandingKey)
	return nil
}

// SetRegistration persists the registration settings, refreshes the local
// snapshot, and notifies other instances. Validation is the caller's
// responsibility.
func (m *Manager) SetRegistration(
	ctx context.Context,
	registration Registration,
	updatedBy string,
	fallbackMailConfigured bool,
) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	if m.db == nil {
		return errors.New("runtime settings storage is unavailable")
	}
	encoded, err := json.Marshal(registration)
	if err != nil {
		return fmt.Errorf("encoding %s settings: %w", registrationKey, err)
	}
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("starting registration settings transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return err
	}
	if registration.Mode != RegistrationClosed {
		configured, configuredErr := runtimecoord.MailConfigured(ctx, tx, fallbackMailConfigured)
		if configuredErr != nil {
			return configuredErr
		}
		if !configured {
			return ErrMailConfigurationNeeded
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO runtime_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
	`, registrationKey, encoded, updatedBy); err != nil {
		return fmt.Errorf("storing %s settings: %w", registrationKey, err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, notificationChannel, registrationKey); err != nil {
		return fmt.Errorf("notifying registration settings change: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing registration settings: %w", err)
	}
	m.registration.Store(&registration)
	return nil
}

// LoadRegistrationTx reads and locks the authoritative registration policy.
// A missing row represents the safe defaults, and the coordination advisory
// lock prevents a concurrent first insert from bypassing this observation.
func LoadRegistrationTx(ctx context.Context, tx pgx.Tx) (Registration, error) {
	registration := DefaultRegistration()
	var raw []byte
	err := tx.QueryRow(ctx, `
		SELECT value FROM runtime_settings
		WHERE key=$1
		FOR SHARE
	`, registrationKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration, nil
	}
	if err != nil {
		return Registration{}, fmt.Errorf("locking registration settings: %w", err)
	}
	if err := json.Unmarshal(raw, &registration); err != nil {
		return Registration{}, fmt.Errorf("decoding stored registration settings: %w", err)
	}
	return registration, nil
}

// RequireRegistrationTx verifies that a request still uses the complete
// authoritative policy that was validated by the HTTP layer.
func RequireRegistrationTx(ctx context.Context, tx pgx.Tx, expected Registration) error {
	current, err := LoadRegistrationTx(ctx, tx)
	if err != nil {
		return err
	}
	if !sameRegistration(current, expected) {
		return ErrRegistrationChanged
	}
	return nil
}

func sameRegistration(left, right Registration) bool {
	return left.Mode == right.Mode &&
		left.RequireEmailVerification == right.RequireEmailVerification &&
		slices.Equal(left.AllowedEmailDomains, right.AllowedEmailDomains) &&
		left.PendingRegistrationTTL == right.PendingRegistrationTTL &&
		left.InviteDefaultTTL == right.InviteDefaultTTL &&
		left.InviteDefaultMaxUses == right.InviteDefaultMaxUses
}

func (m *Manager) store(ctx context.Context, key string, value any, updatedBy string) error {
	if m.db == nil {
		return errors.New("runtime settings storage is unavailable")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encoding %s settings: %w", key, err)
	}
	_, err = m.db.Exec(ctx, `
		INSERT INTO runtime_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
	`, key, encoded, updatedBy)
	if err != nil {
		return fmt.Errorf("storing %s settings: %w", key, err)
	}
	return nil
}

func (m *Manager) notify(ctx context.Context, key string) {
	if _, err := m.db.Exec(ctx, `SELECT pg_notify($1, $2)`, notificationChannel, key); err != nil {
		slog.ErrorContext(ctx, "settings change notification failed", "key", key, "error", err)
	}
}

// StartSynchronization keeps the snapshot consistent across instances:
// LISTEN/NOTIFY for low latency, periodic reconciliation for dropped
// notifications and reconnects.
func (m *Manager) StartSynchronization(ctx context.Context) {
	if m == nil || m.db == nil {
		return
	}
	go m.listenForChanges(ctx)
	go m.reconcile(ctx)
}

func (m *Manager) reconcile(ctx context.Context) {
	ticker := time.NewTicker(reconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "settings reconciliation failed", "error", err)
			}
		}
	}
}

func (m *Manager) listenForChanges(ctx context.Context) {
	for ctx.Err() == nil {
		connection, err := m.db.Acquire(ctx)
		if err != nil {
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		if _, err = connection.Exec(ctx, `LISTEN nyauth_settings_changed`); err != nil {
			connection.Release()
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			if err = m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "settings notification reload failed", "error", err)
			}
		}
		connection.Release()
		if ctx.Err() == nil {
			m.waitBeforeReconnect(ctx, err)
		}
	}
}

func (m *Manager) waitBeforeReconnect(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		slog.WarnContext(ctx, "settings notification listener disconnected", "error", err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
