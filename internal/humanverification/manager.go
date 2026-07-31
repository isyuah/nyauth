package humanverification

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

type ManagerOptions struct {
	ExpectedHostname       string
	HTTPClient             *http.Client
	SiteverifyEndpoint     string
	ReconciliationInterval time.Duration
	OnError                func(error)
}

type PublicChallenge struct {
	Enabled    bool   `json:"enabled"`
	Required   bool   `json:"required"`
	Available  bool   `json:"available"`
	Provider   string `json:"provider,omitempty"`
	SiteKey    string `json:"site_key,omitempty"`
	WidgetMode string `json:"widget_mode,omitempty"`
	Action     string `json:"action"`
}

type RuntimeStatus struct {
	Mode          string `json:"mode"`
	Configured    bool   `json:"configured"`
	Available     bool   `json:"available"`
	Provider      string `json:"provider,omitempty"`
	StateRevision int64  `json:"state_revision"`
}

type managerSnapshot struct {
	effective EffectiveConfig
	verifier  Verifier
}

type Manager struct {
	store                  *Store
	expectedHostname       string
	httpClient             *http.Client
	siteverifyEndpoint     string
	reconciliationInterval time.Duration
	onError                func(error)
	loadMu                 sync.Mutex
	snapshot               atomic.Pointer[managerSnapshot]
}

func NewManager(store *Store, options ManagerOptions) (*Manager, error) {
	if store == nil {
		return nil, ErrStoreUnavailable
	}
	hostname := strings.ToLower(strings.TrimSpace(options.ExpectedHostname))
	if hostname == "" {
		return nil, fmt.Errorf("%w: expected hostname is required", ErrInvalidConfig)
	}
	if options.ReconciliationInterval == 0 {
		options.ReconciliationInterval = DefaultReconcilePeriod
	}
	if options.ReconciliationInterval <= 0 {
		return nil, fmt.Errorf("%w: reconciliation interval must be positive", ErrInvalidConfig)
	}
	return &Manager{
		store: store, expectedHostname: hostname, httpClient: options.HTTPClient,
		siteverifyEndpoint:     options.SiteverifyEndpoint,
		reconciliationInterval: options.ReconciliationInterval, onError: options.OnError,
	}, nil
}

func (m *Manager) Store() *Store { return m.store }

func (m *Manager) LoadState(ctx context.Context) (State, error) {
	return m.store.LoadState(ctx)
}

func (m *Manager) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	return m.store.LoadVersion(ctx, id)
}

func (m *Manager) LoadLatestTest(ctx context.Context, id uuid.UUID) (*TestRecord, error) {
	return m.store.LoadLatestTest(ctx, id)
}

func (m *Manager) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	return m.store.CreateCandidate(ctx, input)
}

func (m *Manager) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	return m.store.RecordTest(ctx, input)
}

func (m *Manager) Activate(ctx context.Context, input ActivateInput) (State, error) {
	return m.store.Activate(ctx, input)
}

func (m *Manager) UpdatePolicy(ctx context.Context, input PolicyMutationInput) (State, error) {
	return m.store.UpdatePolicy(ctx, input)
}

func (m *Manager) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	return m.store.Rollback(ctx, input)
}

func (m *Manager) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	return m.store.Disable(ctx, input)
}

func (m *Manager) Enable(ctx context.Context, input StateMutationInput) (State, error) {
	return m.store.Enable(ctx, input)
}

func (m *Manager) Load(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	effective, err := m.store.LoadEffectiveConfig(ctx)
	if err != nil {
		if effective.State.Revision > 0 {
			m.install(&managerSnapshot{effective: effective})
		}
		return err
	}
	next := &managerSnapshot{effective: effective}
	if effective.Config != nil {
		verifier, buildErr := m.buildVerifier(*effective.Config)
		if buildErr != nil {
			effective.Available = false
			next.effective = effective
			m.install(next)
			return buildErr
		}
		next.verifier = verifier
	}
	m.install(next)
	return nil
}

func (m *Manager) install(next *managerSnapshot) bool {
	current := m.snapshot.Load()
	if current != nil {
		currentRevision := current.effective.State.Revision
		nextRevision := next.effective.State.Revision
		if nextRevision < currentRevision {
			return false
		}
		if nextRevision == currentRevision {
			// A transient initial load can install a fail-closed snapshot after
			// reading the state row but before loading the active secret. Allow
			// reconciliation to recover that same revision, while never replacing
			// a healthy snapshot with a same-revision failure.
			if current.effective.Available || !next.effective.Available {
				return false
			}
		}
	}
	m.snapshot.Store(next)
	return true
}

func (m *Manager) buildVerifier(config Config) (Verifier, error) {
	switch config.Provider {
	case ProviderTurnstile:
		return NewTurnstileVerifier(TurnstileOptions{
			Secret: config.Secret, ExpectedHostname: m.expectedHostname,
			Client: m.httpClient, Endpoint: m.siteverifyEndpoint,
		})
	default:
		return nil, fmt.Errorf("%w: unsupported provider %q", ErrInvalidConfig, config.Provider)
	}
}

func (m *Manager) CandidateVerifier(ctx context.Context, id uuid.UUID) (Version, Verifier, error) {
	version, config, err := m.store.LoadVersionConfig(ctx, id)
	if err != nil {
		return Version{}, nil, err
	}
	verifier, err := m.buildVerifier(config)
	return version, verifier, err
}

func (m *Manager) Snapshot() EffectiveConfig {
	if snapshot := m.snapshot.Load(); snapshot != nil {
		return snapshot.effective
	}
	return EffectiveConfig{State: State{Mode: ModeDisabled, Policy: DefaultPolicy()}}
}

func (m *Manager) PublicChallenge(action string, loginAttempt int) PublicChallenge {
	result := PublicChallenge{Action: action}
	if !ValidAction(action) || action == ActionAdminTest {
		return result
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil || snapshot.effective.State.Mode != ModeActive {
		return result
	}
	result.Enabled = true
	result.Required = PolicyRequires(snapshot.effective.State.Policy, action, loginAttempt)
	result.Available = snapshot.effective.Available && snapshot.verifier != nil
	if snapshot.effective.Version != nil {
		result.Provider = snapshot.effective.Version.Provider
		result.SiteKey = snapshot.effective.Version.SiteKey
		result.WidgetMode = snapshot.effective.Version.WidgetMode
	}
	return result
}

func (m *Manager) Verify(ctx context.Context, input VerifyInput, loginAttempt int) error {
	snapshot := m.snapshot.Load()
	if snapshot == nil || snapshot.effective.State.Mode != ModeActive || !PolicyRequires(snapshot.effective.State.Policy, input.Action, loginAttempt) {
		return nil
	}
	if !snapshot.effective.Available || snapshot.verifier == nil {
		return ErrVerificationUnavailable
	}
	_, err := snapshot.verifier.Verify(ctx, input)
	return err
}

func (m *Manager) Status() RuntimeStatus {
	effective := m.Snapshot()
	status := RuntimeStatus{
		Mode: effective.State.Mode, Configured: effective.Configured,
		Available: effective.Available, StateRevision: effective.State.Revision,
	}
	if effective.Version != nil {
		status.Provider = effective.Version.Provider
	}
	return status
}

func (m *Manager) StartSynchronization(ctx context.Context) {
	go m.listen(ctx)
	go m.reconcile(ctx)
}

func (m *Manager) listen(ctx context.Context) {
	for ctx.Err() == nil {
		conn, err := m.store.db.Acquire(ctx)
		if err != nil {
			m.report(fmt.Errorf("acquiring human verification notification connection: %w", err))
			if !waitContext(ctx, time.Second) {
				return
			}
			continue
		}
		_, err = conn.Exec(ctx, `LISTEN `+NotificationChannel)
		if err != nil {
			conn.Release()
			m.report(fmt.Errorf("listening for human verification changes: %w", err))
			if !waitContext(ctx, time.Second) {
				return
			}
			continue
		}
		for ctx.Err() == nil {
			if _, err = conn.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			if err = m.Load(ctx); err != nil {
				m.report(fmt.Errorf("reloading human verification after notification: %w", err))
			}
		}
		conn.Release()
		if ctx.Err() == nil {
			m.report(fmt.Errorf("human verification notification listener stopped: %w", err))
			if !waitContext(ctx, time.Second) {
				return
			}
		}
	}
}

func (m *Manager) reconcile(ctx context.Context) {
	ticker := time.NewTicker(m.reconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Load(ctx); err != nil {
				m.report(fmt.Errorf("reconciling human verification state: %w", err))
			}
		}
	}
}

func (m *Manager) report(err error) {
	if err == nil || errors.Is(err, context.Canceled) {
		return
	}
	if m.onError != nil {
		m.onError(err)
		return
	}
	slog.Warn("human verification runtime synchronization failed", "error", err)
}

func waitContext(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
