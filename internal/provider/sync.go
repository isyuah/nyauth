package provider

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

const providerReconciliationInterval = 60 * time.Second

// StartSynchronization keeps dynamic provider snapshots consistent across
// application instances. LISTEN/NOTIFY provides low-latency invalidation while
// reconciliation repairs dropped notifications and temporary disconnects.
func (m *Manager) StartSynchronization(ctx context.Context) {
	if m == nil || m.db == nil {
		return
	}
	go m.listenForChanges(ctx)
	go m.reconcileProviders(ctx)
}

func (m *Manager) reconcileProviders(ctx context.Context) {
	m.reconcileProvidersAtInterval(ctx, providerReconciliationInterval)
}

func (m *Manager) reconcileProvidersAtInterval(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.LoadDynamic(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "provider reconciliation failed", "error", err)
			}
		}
	}
}

func (m *Manager) listenForChanges(ctx context.Context) {
	m.listenForChangesWithReady(ctx, nil)
}

func (m *Manager) listenForChangesWithReady(ctx context.Context, ready chan<- struct{}) {
	for ctx.Err() == nil {
		started := time.Now()
		connection, err := m.db.Acquire(ctx)
		if err != nil {
			m.recordTelemetry(ctx, "synchronization", "failure", "listener_connect_failed", time.Since(started))
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		_, err = connection.Exec(ctx, `LISTEN nyauth_provider_changed`)
		if err != nil {
			m.recordTelemetry(ctx, "synchronization", "failure", "listener_subscribe_failed", time.Since(started))
			connection.Release()
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		if ready != nil {
			select {
			case ready <- struct{}{}:
			default:
			}
			ready = nil
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				if !errors.Is(err, context.Canceled) {
					m.recordTelemetry(ctx, "synchronization", "failure", "listener_disconnected", time.Since(started))
				}
				break
			}
			if err = m.LoadDynamic(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "provider notification reload failed", "error", err)
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
		slog.WarnContext(ctx, "provider notification listener disconnected", "error", err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}
