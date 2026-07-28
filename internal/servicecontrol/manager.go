package servicecontrol

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
)

const (
	DefaultHeartbeatInterval      = 5 * time.Second
	DefaultReconciliationInterval = 5 * time.Second
	DefaultApplyTimeout           = 5 * time.Second
	DefaultCleanupInterval        = time.Minute
	DefaultInstanceRetention      = 5 * time.Minute
)

type ManagerOptions struct {
	InstanceID             uuid.UUID
	Version                string
	StartedAt              time.Time
	HeartbeatInterval      time.Duration
	ReconciliationInterval time.Duration
	ApplyTimeout           time.Duration
	StaleAfter             time.Duration
	CleanupInterval        time.Duration
	InstanceRetention      time.Duration
	OnError                func(error)
}

// Manager connects the process-local Controller to PostgreSQL coordination.
// Its public methods are intentionally small so HTTP handlers and workers do
// not need to know about leases, heartbeat rows, or LISTEN/NOTIFY.
type Manager struct {
	store      *Store
	controller *Controller
	options    ManagerOptions

	startMu sync.Mutex
	started bool
}

func NewManager(store *Store, controller *Controller, options ManagerOptions) (*Manager, error) {
	if store == nil || store.db == nil {
		return nil, ErrStoreUnavailable
	}
	if options.InstanceID == uuid.Nil {
		return nil, fmt.Errorf("%w: instance ID is required", ErrInvalidState)
	}
	options.Version = strings.TrimSpace(options.Version)
	if options.Version == "" || len(options.Version) > 128 {
		return nil, fmt.Errorf("%w: instance version is invalid", ErrInvalidState)
	}
	if options.StartedAt.IsZero() {
		options.StartedAt = time.Now().UTC()
	} else {
		options.StartedAt = options.StartedAt.UTC()
	}
	if options.HeartbeatInterval <= 0 {
		options.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if options.ReconciliationInterval <= 0 {
		options.ReconciliationInterval = DefaultReconciliationInterval
	}
	if options.ApplyTimeout <= 0 {
		options.ApplyTimeout = DefaultApplyTimeout
	}
	if options.StaleAfter <= 0 {
		options.StaleAfter = DefaultStaleAfter
	}
	if options.CleanupInterval <= 0 {
		options.CleanupInterval = DefaultCleanupInterval
	}
	if options.InstanceRetention <= 0 {
		options.InstanceRetention = DefaultInstanceRetention
	}
	if options.StaleAfter <= options.HeartbeatInterval || options.StaleAfter <= options.ReconciliationInterval {
		return nil, fmt.Errorf("%w: stale interval must exceed heartbeat and reconciliation intervals", ErrInvalidState)
	}
	if options.InstanceRetention <= options.StaleAfter {
		return nil, fmt.Errorf("%w: instance retention must exceed stale interval", ErrInvalidState)
	}
	if options.OnError == nil {
		options.OnError = func(err error) { slog.Error("service control synchronization failed", "error", err) }
	}
	if controller == nil {
		controller = NewController(ControllerOptions{StaleAfter: options.StaleAfter})
	}
	return &Manager{store: store, controller: controller, options: options}, nil
}

// Load reconciles the authoritative snapshot into local gates and waits for
// work admitted under the previous revision to drain until ctx is cancelled.
func (m *Manager) Load(ctx context.Context) error {
	if m == nil || m.store == nil || m.controller == nil {
		return ErrStoreUnavailable
	}
	snapshot, err := m.store.LoadSnapshot(ctx)
	if err != nil {
		return err
	}
	return m.controller.Apply(ctx, snapshot)
}

// Start performs the initial load and instance registration synchronously,
// then starts heartbeat, reconciliation, expiration and notification loops.
func (m *Manager) Start(ctx context.Context) error {
	if m == nil {
		return ErrStoreUnavailable
	}
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if m.started {
		return fmt.Errorf("%w: manager is already started", ErrInvalidState)
	}
	if err := m.Load(ctx); err != nil {
		return fmt.Errorf("initializing service control snapshot: %w", err)
	}
	loaded, applied := m.controller.Revisions()
	_, err := m.store.RegisterInstance(ctx, RegisterInstanceInput{
		ID: m.options.InstanceID, Version: m.options.Version, StartedAt: m.options.StartedAt,
		LoadedRevision: loaded, AppliedRevision: applied,
	})
	if err != nil {
		return err
	}
	m.controller.MarkHeartbeatNow()
	m.started = true
	go m.listen(ctx)
	go m.heartbeatLoop(ctx)
	go m.reconciliationLoop(ctx)
	go m.maintenanceLoop(ctx)
	go m.unregisterOnStop(ctx)
	return nil
}

func (m *Manager) Acquire(capabilities ...Capability) (func(), error) {
	if m == nil || m.controller == nil {
		return nil, &PausedError{Capabilities: capabilities, RetryAfter: time.Minute, FailClosed: true}
	}
	lease, err := m.controller.AcquireAll(capabilities...)
	if err != nil {
		return nil, err
	}
	return lease.Release, nil
}

func (m *Manager) Snapshot() Snapshot {
	if m == nil || m.controller == nil {
		return Snapshot{}
	}
	return m.controller.Snapshot()
}

func (m *Manager) Changes() <-chan struct{} {
	if m == nil || m.controller == nil {
		return nil
	}
	return m.controller.Changes()
}

// FailClosed reports whether this instance currently rejects every controlled
// capability because it cannot prove heartbeat and state freshness.
func (m *Manager) FailClosed() bool {
	return m == nil || m.controller == nil || m.controller.FailClosed()
}

func (m *Manager) Update(
	ctx context.Context,
	expectedRevision int64,
	request UpdateRequest,
	mutation audit.MutationAudit,
) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	snapshot, err := m.store.Update(ctx, UpdateInput{
		ExpectedRevision: expectedRevision, PausedCapabilities: request.PausedCapabilities,
		PublicMessage: request.PublicMessage, InternalReason: request.InternalReason,
		ExpiresAt: request.ExpiresAt, UpdatedBy: mutation.ActorID,
		UpdatedByName: mutation.ActorName, Audit: mutation,
	})
	if err != nil {
		return State{}, err
	}
	return m.publishAndWait(ctx, snapshot)
}

func (m *Manager) Reset(ctx context.Context, reason, actor string) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	snapshot, err := m.store.Reset(ctx, ResetInput{Reason: reason, ActorName: actor})
	if err != nil {
		return State{}, err
	}
	return m.publishAndWait(ctx, snapshot)
}

func (m *Manager) WaitApplied(ctx context.Context, revision int64) (ApplicationStatus, error) {
	if m == nil || m.store == nil {
		return ApplicationStatus{}, ErrStoreUnavailable
	}
	return m.store.WaitForApplied(ctx, revision, m.options.StaleAfter)
}

func (m *Manager) Status(ctx context.Context) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	return m.store.LoadState(ctx, m.options.StaleAfter)
}

func (m *Manager) Instances(ctx context.Context) ([]Instance, error) {
	state, err := m.Status(ctx)
	if err != nil {
		return nil, err
	}
	return state.Instances, nil
}

func (m *Manager) publishAndWait(parent context.Context, snapshot Snapshot) (State, error) {
	if err := m.controller.publish(snapshot); err != nil {
		return State{}, err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), m.options.ApplyTimeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last ApplicationStatus
	for {
		m.heartbeatOnce(ctx)
		status, err := m.store.ApplicationStatus(ctx, snapshot.Revision, m.options.StaleAfter)
		if err == nil {
			last = status
			if status.Applied {
				return stateFromApplication(snapshot, status), nil
			}
		} else if ctx.Err() == nil {
			m.options.OnError(fmt.Errorf("checking service control application: %w", err))
			return pendingState(snapshot, last), nil
		}
		select {
		case <-ctx.Done():
			return pendingState(snapshot, last), nil
		case <-ticker.C:
		}
	}
}

func stateFromApplication(snapshot Snapshot, status ApplicationStatus) State {
	return State{
		Snapshot: snapshot, Instances: status.Instances,
		ActiveInstances: status.ActiveInstances, AppliedInstances: status.AppliedInstances,
		Applied: status.Applied,
	}
}

func pendingState(snapshot Snapshot, status ApplicationStatus) State {
	state := stateFromApplication(snapshot, status)
	state.Applied = false
	return state
}

func (m *Manager) refresh(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, m.options.ApplyTimeout)
	defer cancel()
	snapshot, err := m.store.LoadSnapshot(ctx)
	if err != nil {
		m.options.OnError(err)
		return
	}
	if err := m.controller.publish(snapshot); err != nil && !errors.Is(err, ErrStaleRevision) {
		m.options.OnError(err)
		return
	}
	m.heartbeatOnce(ctx)
	if snapshot.ExpiresAt != nil && !snapshot.DatabaseNow.Before(*snapshot.ExpiresAt) {
		result, expireErr := m.store.TryExpire(ctx)
		if expireErr != nil {
			m.options.OnError(expireErr)
		} else if result.Expired {
			if applyErr := m.controller.publish(result.State); applyErr != nil {
				m.options.OnError(applyErr)
				return
			}
			m.heartbeatOnce(ctx)
		}
	}
}

func (m *Manager) heartbeatOnce(ctx context.Context) {
	loaded, applied := m.controller.Revisions()
	if loaded < 1 || applied < 1 {
		return
	}
	_, err := m.store.Heartbeat(ctx, HeartbeatInput{
		ID: m.options.InstanceID, LoadedRevision: loaded, AppliedRevision: applied,
	})
	if errors.Is(err, ErrInstanceNotFound) {
		_, err = m.store.RegisterInstance(ctx, RegisterInstanceInput{
			ID: m.options.InstanceID, Version: m.options.Version, StartedAt: m.options.StartedAt,
			LoadedRevision: loaded, AppliedRevision: applied,
		})
	}
	if err != nil {
		m.options.OnError(err)
		return
	}
	m.controller.MarkHeartbeatNow()
}

func (m *Manager) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(m.options.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.heartbeatOnce(ctx)
		}
	}
}

func (m *Manager) reconciliationLoop(ctx context.Context) {
	ticker := time.NewTicker(m.options.ReconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.refresh(ctx)
		}
	}
}

func (m *Manager) maintenanceLoop(ctx context.Context) {
	ticker := time.NewTicker(m.options.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := m.store.CleanupStaleInstances(ctx, m.options.InstanceRetention); err != nil {
				m.options.OnError(err)
			}
		}
	}
}

func (m *Manager) listen(ctx context.Context) {
	for ctx.Err() == nil {
		connection, err := m.store.db.Acquire(ctx)
		if err != nil {
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		if _, err = connection.Exec(ctx, `LISTEN nyauth_service_control_changed`); err != nil {
			connection.Release()
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			m.refresh(ctx)
		}
		connection.Release()
		if ctx.Err() == nil {
			m.waitBeforeReconnect(ctx, err)
		}
	}
}

func (m *Manager) waitBeforeReconnect(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		m.options.OnError(fmt.Errorf("service control notification listener disconnected: %w", err))
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (m *Manager) unregisterOnStop(ctx context.Context) {
	<-ctx.Done()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.store.UnregisterInstance(cleanupCtx, m.options.InstanceID); err != nil {
		m.options.OnError(err)
	}
}
