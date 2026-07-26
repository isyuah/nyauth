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
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	brandingKey            = "branding"
	notificationChannel    = "nyauth_settings_changed"
	reconciliationInterval = 60 * time.Second
)

// Branding is the first runtime-settings consumer: the values the web UI uses
// to present the deployment (sidebar wordmark, login heading, logo).
type Branding struct {
	Title   string `json:"title"`
	LogoURL string `json:"logo_url"`
}

// Manager caches the current settings snapshot and keeps it consistent across
// instances with the same LISTEN/NOTIFY + reconciliation pattern the provider
// manager uses. Config values act as defaults when nothing is stored yet.
type Manager struct {
	db       *pgxpool.Pool
	defaults Branding
	snapshot atomic.Pointer[Branding]
}

func NewManager(db *pgxpool.Pool, defaults Branding) *Manager {
	return &Manager{db: db, defaults: defaults}
}

// Branding returns the stored branding, or the config defaults before the
// first successful load and when nothing has been stored.
func (m *Manager) Branding() Branding {
	if snapshot := m.snapshot.Load(); snapshot != nil {
		return *snapshot
	}
	return m.defaults
}

func (m *Manager) Load(ctx context.Context) error {
	if m.db == nil {
		return nil
	}
	var raw []byte
	err := m.db.QueryRow(ctx, `SELECT value FROM runtime_settings WHERE key = $1`, brandingKey).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		m.snapshot.Store(nil)
		return nil
	}
	if err != nil {
		return fmt.Errorf("loading runtime settings: %w", err)
	}
	stored := m.defaults
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("decoding stored branding: %w", err)
	}
	m.snapshot.Store(&stored)
	return nil
}

// SetBranding persists the branding, refreshes the local snapshot, and
// notifies other instances. Validation is the caller's responsibility.
func (m *Manager) SetBranding(ctx context.Context, branding Branding, updatedBy string) error {
	if m.db == nil {
		return errors.New("runtime settings storage is unavailable")
	}
	encoded, err := json.Marshal(branding)
	if err != nil {
		return fmt.Errorf("encoding branding: %w", err)
	}
	_, err = m.db.Exec(ctx, `
		INSERT INTO runtime_settings (key, value, updated_by, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (key) DO UPDATE SET
			value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at
	`, brandingKey, encoded, updatedBy)
	if err != nil {
		return fmt.Errorf("storing branding: %w", err)
	}
	m.snapshot.Store(&branding)
	if _, err := m.db.Exec(ctx, `SELECT pg_notify($1, $2)`, notificationChannel, brandingKey); err != nil {
		slog.ErrorContext(ctx, "settings change notification failed", "error", err)
	}
	return nil
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
