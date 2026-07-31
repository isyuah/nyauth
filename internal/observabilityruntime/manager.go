package observabilityruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type ManagerOptions struct {
	Fallback               *Config
	Production             bool
	ReconciliationInterval time.Duration
	Apply                  func(context.Context, *Config) error
	OnError                func(error)
}

type RuntimeStatus struct {
	Mode          string     `json:"mode"`
	Configured    bool       `json:"configured"`
	VersionID     *uuid.UUID `json:"version_id"`
	StateRevision int64      `json:"state_revision"`
}

type managerSnapshot struct{ effective EffectiveConfig }

type Manager struct {
	store                  *Store
	fallback               *Config
	production             bool
	reconciliationInterval time.Duration
	apply                  func(context.Context, *Config) error
	onError                func(error)
	loadMu                 sync.Mutex
	snapshot               atomic.Pointer[managerSnapshot]
}

func NewManager(store *Store, options ManagerOptions) (*Manager, error) {
	if store == nil {
		return nil, ErrStoreUnavailable
	}
	if options.Apply == nil {
		return nil, fmt.Errorf("%w: exporter apply callback is required", ErrInvalidConfig)
	}
	if options.ReconciliationInterval == 0 {
		options.ReconciliationInterval = DefaultReconciliationInterval
	}
	if options.ReconciliationInterval <= 0 {
		return nil, fmt.Errorf("%w: reconciliation interval must be positive", ErrInvalidConfig)
	}
	var fallback *Config
	if options.Fallback != nil {
		settings, err := ValidateSettings(options.Fallback.Settings, options.Production)
		if err != nil {
			return nil, fmt.Errorf("validating OTLP fallback: %w", err)
		}
		if err := ValidateAuthorization(options.Fallback.Authorization); err != nil {
			return nil, err
		}
		copyValue := *options.Fallback
		copyValue.Settings = settings
		fallback = &copyValue
	}
	return &Manager{store: store, fallback: fallback, production: options.Production, reconciliationInterval: options.ReconciliationInterval, apply: options.Apply, onError: options.OnError}, nil
}

func (m *Manager) Store() *Store {
	if m == nil {
		return nil
	}
	return m.store
}
func (m *Manager) LoadState(ctx context.Context) (State, error) { return m.store.LoadState(ctx) }
func (m *Manager) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	return m.store.LoadVersion(ctx, id)
}
func (m *Manager) LoadLatestTest(ctx context.Context, versionID uuid.UUID) (*TestRecord, error) {
	return m.store.LoadLatestTest(ctx, versionID)
}

func (m *Manager) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	input.Fallback = m.fallback
	return m.store.CreateCandidate(ctx, input)
}
func (m *Manager) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	return m.store.RecordTest(ctx, input)
}
func (m *Manager) Activate(ctx context.Context, input VersionMutationInput) (State, error) {
	return m.store.Activate(ctx, input)
}
func (m *Manager) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	return m.store.Rollback(ctx, input)
}
func (m *Manager) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	return m.store.Disable(ctx, input)
}

// Load preserves the last exporter on transient database failures. A stored
// active configuration that cannot be decrypted or validated fails closed so
// metrics are never sent to a stale destination after an explicit activation.
func (m *Manager) Load(ctx context.Context) error {
	if m == nil || m.store == nil {
		return ErrStoreUnavailable
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	effective, err := m.store.LoadEffectiveConfig(ctx, m.fallback)
	if err != nil {
		if errors.Is(err, ErrInvalidConfig) {
			_ = m.apply(ctx, nil)
			m.snapshot.Store(&managerSnapshot{effective: effective})
		}
		return err
	}
	current := m.snapshot.Load()
	if current != nil && current.effective.StateRevision >= effective.StateRevision {
		return nil
	}
	applyNeeded := current == nil || current.effective.Mode != effective.Mode || !sameVersion(current.effective, effective)
	if applyNeeded {
		var config *Config
		if effective.Config != nil {
			validated, validateErr := ValidateSettings(effective.Config.Settings, m.production)
			if validateErr != nil {
				_ = m.apply(ctx, nil)
				return validateErr
			}
			copyValue := *effective.Config
			copyValue.Settings = validated
			config = &copyValue
		}
		if err := m.apply(ctx, config); err != nil {
			return fmt.Errorf("applying OTLP runtime configuration: %w", err)
		}
	}
	m.snapshot.Store(&managerSnapshot{effective: effective})
	return nil
}

func sameVersion(left, right EffectiveConfig) bool {
	if left.VersionID == nil || right.VersionID == nil {
		return left.VersionID == nil && right.VersionID == nil
	}
	return *left.VersionID == *right.VersionID
}

func (m *Manager) Effective() EffectiveConfig {
	if m == nil {
		return EffectiveConfig{Mode: ModeFallback}
	}
	if snapshot := m.snapshot.Load(); snapshot != nil {
		return snapshot.effective
	}
	return EffectiveConfig{Mode: ModeFallback, Configured: m.fallback != nil, Config: m.fallback}
}

func (m *Manager) StartSynchronization(ctx context.Context) {
	if m == nil || m.store == nil {
		return
	}
	go m.listen(ctx)
	go m.reconcile(ctx)
}

func (m *Manager) reconcile(ctx context.Context) {
	ticker := time.NewTicker(m.reconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				m.report(err)
			}
		}
	}
}

func (m *Manager) listen(ctx context.Context) {
	for ctx.Err() == nil {
		connection, err := m.store.db.Acquire(ctx)
		if err != nil {
			m.wait(ctx, err)
			continue
		}
		if _, err = connection.Exec(ctx, `LISTEN `+NotificationChannel); err != nil {
			connection.Release()
			m.wait(ctx, err)
			continue
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			if err = m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				m.report(err)
			}
		}
		connection.Release()
		if ctx.Err() == nil {
			m.wait(ctx, err)
		}
	}
}

func (m *Manager) wait(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		m.report(err)
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (m *Manager) report(err error) {
	if m.onError != nil {
		m.onError(err)
		return
	}
	slog.Error("OTLP runtime synchronization failed", "error", err)
}
