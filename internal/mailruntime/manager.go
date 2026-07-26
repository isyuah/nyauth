package mailruntime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
)

const defaultReconciliationInterval = time.Minute

type ManagerOptions struct {
	Fallback               *SMTPConfig
	Production             bool
	ReconciliationInterval time.Duration
	OnError                func(error)
	OnSnapshot             func(EffectiveConfig)
}

type RuntimeStatus struct {
	Mode          string     `json:"mode"`
	Configured    bool       `json:"configured"`
	Available     bool       `json:"available"`
	CircuitState  string     `json:"circuit_state"`
	VersionID     *uuid.UUID `json:"version_id"`
	StateRevision int64      `json:"state_revision"`
}

type managerSnapshot struct {
	effective EffectiveConfig
	sender    *account.SMTPSender
	delivery  account.EmailSender
	source    EffectiveSource
}

type effectiveConfigLoader func(context.Context, *SMTPConfig) (EffectiveConfig, error)

// Manager owns the process-local atomic sender snapshot and keeps it aligned
// with the HA-shared database state. The persisted Store remains the source of
// truth; environment configuration is consulted only while mode=fallback.
type Manager struct {
	store                  *Store
	loadEffectiveConfig    effectiveConfigLoader
	fallback               *SMTPConfig
	production             bool
	reconciliationInterval time.Duration
	onError                func(error)
	onSnapshot             func(EffectiveConfig)
	loadMu                 sync.Mutex
	snapshot               atomic.Pointer[managerSnapshot]
}

func NewManager(store *Store, options ManagerOptions) (*Manager, error) {
	if store == nil {
		return nil, ErrStoreUnavailable
	}
	if options.ReconciliationInterval == 0 {
		options.ReconciliationInterval = defaultReconciliationInterval
	}
	if options.ReconciliationInterval <= 0 {
		return nil, fmt.Errorf("%w: reconciliation interval must be positive", ErrInvalidConfig)
	}
	var fallback *SMTPConfig
	if options.Fallback != nil {
		copied := *options.Fallback
		fallback = &copied
	}
	return &Manager{
		store: store, loadEffectiveConfig: store.LoadEffectiveConfig,
		fallback: fallback, production: options.Production,
		reconciliationInterval: options.ReconciliationInterval,
		onError:                options.OnError, onSnapshot: options.OnSnapshot,
	}, nil
}

func (m *Manager) Store() *Store {
	if m == nil {
		return nil
	}
	return m.store
}

func (m *Manager) LoadState(ctx context.Context) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	return m.store.LoadState(ctx)
}

func (m *Manager) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	if m == nil || m.store == nil {
		return Version{}, ErrStoreUnavailable
	}
	return m.store.LoadVersion(ctx, id)
}

func (m *Manager) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	if m == nil || m.store == nil {
		return CandidateResult{}, ErrStoreUnavailable
	}
	input.Fallback = m.fallback
	return m.store.CreateCandidate(ctx, input)
}

func (m *Manager) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	if m == nil || m.store == nil {
		return TestResult{}, ErrStoreUnavailable
	}
	return m.store.RecordTest(ctx, input)
}

func (m *Manager) Activate(ctx context.Context, input VersionMutationInput) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	return m.store.Activate(ctx, input)
}

func (m *Manager) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	return m.store.Rollback(ctx, input)
}

func (m *Manager) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	if m == nil || m.store == nil {
		return State{}, ErrStoreUnavailable
	}
	return m.store.Disable(ctx, input)
}

// Load resolves, validates, and atomically installs the effective sender. A
// database read failure preserves the last known snapshot. A deterministic
// sender-construction failure installs an unavailable snapshot so an invalid
// active configuration can never silently retain the previous sender.
func (m *Manager) Load(ctx context.Context) error {
	if m == nil || m.store == nil || m.loadEffectiveConfig == nil {
		return ErrStoreUnavailable
	}
	m.loadMu.Lock()
	defer m.loadMu.Unlock()

	effective, err := m.loadEffectiveConfig(ctx, m.fallback)
	if err != nil {
		if deterministicEffectiveConfigError(err) {
			effective.Available = false
			m.install(&managerSnapshot{effective: effective, source: effectiveSource(effective)})
		}
		return err
	}
	snapshot := &managerSnapshot{effective: effective, source: effectiveSource(effective)}
	if effective.Config != nil {
		sender, buildErr := m.buildSender(*effective.Config)
		if buildErr != nil {
			effective.Available = false
			snapshot.effective = effective
			m.install(snapshot)
			return fmt.Errorf("building effective SMTP sender: %w", buildErr)
		}
		snapshot.sender = sender
		snapshot.delivery = &deliverySender{manager: m, sender: sender, source: snapshot.source}
	}
	m.install(snapshot)
	return nil
}

// install publishes only a strictly newer database state. Every persisted
// runtime-mail mutation advances StateRevision, so an equal revision is an
// idempotent reload of the state that is already installed.
func (m *Manager) install(snapshot *managerSnapshot) bool {
	current := m.snapshot.Load()
	if current != nil && snapshot.effective.StateRevision <= current.effective.StateRevision {
		return false
	}
	m.snapshot.Store(snapshot)
	if m.onSnapshot != nil {
		m.onSnapshot(snapshot.effective)
	}
	return true
}

func (m *Manager) buildSender(config SMTPConfig) (*account.SMTPSender, error) {
	if m.production {
		if config.TLSMode == TLSModePlain {
			return nil, fmt.Errorf("plain SMTP is forbidden in production")
		}
		parsed, err := url.Parse(config.PublicBaseURL)
		if err != nil || parsed.Scheme != "https" {
			return nil, fmt.Errorf("public mail URL must use HTTPS in production")
		}
	}
	return account.NewSMTPSender(account.SMTPOptions{
		Host: config.Host, Port: config.Port, Username: config.Username, Password: config.Password,
		TLSMode: config.TLSMode, FromAddress: config.FromAddress, FromName: config.FromName,
		ConnectTimeout: config.ConnectTimeout, SendTimeout: config.SendTimeout,
	})
}

// SenderForVersion constructs the exact immutable candidate sender used by a
// real test email. It does not alter the active snapshot.
func (m *Manager) SenderForVersion(ctx context.Context, id uuid.UUID) (Version, SMTPConfig, *account.SMTPSender, error) {
	version, config, err := m.store.LoadVersionConfig(ctx, id)
	if err != nil {
		return Version{}, SMTPConfig{}, nil, err
	}
	sender, err := m.buildSender(config)
	if err != nil {
		return Version{}, SMTPConfig{}, nil, err
	}
	return version, config, sender, nil
}

func (m *Manager) CurrentSender() (account.EmailSender, runtimecoord.MailDeliveryGate, bool) {
	if m == nil {
		return nil, runtimecoord.MailDeliveryGate{}, false
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil || snapshot.delivery == nil || !snapshot.effective.Available {
		return nil, runtimecoord.MailDeliveryGate{}, false
	}
	return snapshot.delivery, deliveryGate(snapshot.source), true
}

func (m *Manager) Status() RuntimeStatus {
	status := RuntimeStatus{Mode: ModeFallback, CircuitState: CircuitClosed}
	if m == nil {
		return status
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return status
	}
	return runtimeStatus(snapshot)
}

// RegistrationDeliveryState returns a gate and status derived from one atomic
// snapshot, so a registration never combines a sender identity from one
// revision with availability from another.
func (m *Manager) RegistrationDeliveryState() (runtimecoord.MailDeliveryGate, RuntimeStatus, bool) {
	status := RuntimeStatus{Mode: ModeFallback, CircuitState: CircuitClosed}
	if m == nil {
		return runtimecoord.MailDeliveryGate{}, status, false
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return runtimecoord.MailDeliveryGate{}, status, false
	}
	status = runtimeStatus(snapshot)
	available := snapshot.delivery != nil && snapshot.effective.Available
	if !available {
		return runtimecoord.MailDeliveryGate{}, status, false
	}
	return deliveryGate(snapshot.source), status, true
}

func runtimeStatus(snapshot *managerSnapshot) RuntimeStatus {
	status := RuntimeStatus{Mode: ModeFallback, CircuitState: CircuitClosed}
	status.Mode = snapshot.effective.Mode
	status.Configured = snapshot.effective.Configured
	status.Available = snapshot.sender != nil && snapshot.effective.Available
	status.CircuitState = snapshot.effective.CircuitState
	status.StateRevision = snapshot.effective.StateRevision
	if snapshot.effective.VersionID != nil {
		versionID := *snapshot.effective.VersionID
		status.VersionID = &versionID
	}
	return status
}

func deliveryGate(source EffectiveSource) runtimecoord.MailDeliveryGate {
	gate := runtimecoord.MailDeliveryGate{Mode: source.Mode}
	if source.VersionID != nil {
		versionID := *source.VersionID
		gate.VersionID = &versionID
	}
	return gate
}

func (m *Manager) FallbackConfigured() bool {
	return m != nil && m.fallback != nil
}

func (m *Manager) RefreshEmailSender(ctx context.Context) error {
	return m.Load(ctx)
}

func (m *Manager) EffectiveSettings() (*Settings, bool) {
	if m == nil {
		return nil, false
	}
	snapshot := m.snapshot.Load()
	if snapshot == nil || snapshot.effective.Config == nil {
		return nil, false
	}
	settings := snapshot.effective.Config.Settings
	return &settings, snapshot.effective.Config.Password != ""
}

func (m *Manager) StartSynchronization(ctx context.Context) {
	if m == nil || m.store == nil || m.store.db == nil {
		return
	}
	go m.listen(ctx)
	go m.reconcile(ctx)
	go m.probe(ctx)
}

func (m *Manager) listen(ctx context.Context) {
	for ctx.Err() == nil {
		connection, err := m.store.db.Acquire(ctx)
		if err != nil {
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		if _, err = connection.Exec(ctx, `LISTEN nyauth_mail_runtime_changed`); err != nil {
			connection.Release()
			m.waitBeforeReconnect(ctx, err)
			continue
		}
		for ctx.Err() == nil {
			if _, err = connection.Conn().WaitForNotification(ctx); err != nil {
				break
			}
			if loadErr := m.Load(ctx); loadErr != nil && !errors.Is(loadErr, context.Canceled) {
				m.report(fmt.Errorf("reloading mail runtime after notification: %w", loadErr))
			}
		}
		connection.Release()
		if ctx.Err() == nil {
			m.waitBeforeReconnect(ctx, err)
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
			if err := m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
				m.report(fmt.Errorf("reconciling mail runtime: %w", err))
			}
		}
	}
}

func (m *Manager) probe(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.probeOnce(ctx)
		}
	}
}

func (m *Manager) probeOnce(ctx context.Context) {
	snapshot := m.snapshot.Load()
	if snapshot == nil || snapshot.sender == nil || snapshot.effective.CircuitState != CircuitOpen {
		return
	}
	claim, err := m.store.ClaimProbe(ctx, snapshot.source)
	if err != nil {
		if !errors.Is(err, ErrProbeNotDue) && !errors.Is(err, ErrCircuitClosed) &&
			!errors.Is(err, ErrStaleEffectiveConfig) && !errors.Is(err, context.Canceled) {
			m.report(fmt.Errorf("claiming SMTP circuit probe: %w", err))
		}
		return
	}
	if !claim.Acquired {
		return
	}
	probeErr := snapshot.sender.Probe(ctx)
	outcome := ProbeOutcome{Source: snapshot.source, ExpectedRevision: claim.ExpectedRevision, Success: probeErr == nil}
	if probeErr != nil {
		outcome.Category, outcome.Reason = runtimeFailureDetails(probeErr)
		if outcome.Category == ErrorCategoryRecipient || outcome.Category == ErrorCategoryUnknown {
			outcome.Category = ErrorCategoryTransport
		}
	}
	if _, err := m.store.RecordProbeOutcome(ctx, outcome); err != nil {
		if !errors.Is(err, ErrStateConflict) && !errors.Is(err, ErrStaleEffectiveConfig) && !errors.Is(err, context.Canceled) {
			m.report(fmt.Errorf("recording SMTP circuit probe: %w", err))
		}
		return
	}
	if err := m.Load(ctx); err != nil && !errors.Is(err, context.Canceled) {
		m.report(fmt.Errorf("reloading mail runtime after probe: %w", err))
	}
}

func (m *Manager) waitBeforeReconnect(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		m.report(fmt.Errorf("mail runtime notification listener disconnected: %w", err))
	}
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (m *Manager) report(err error) {
	if err == nil {
		return
	}
	if m.onError != nil {
		m.onError(err)
		return
	}
	slog.Error("runtime mail error", "error", err)
}

type deliverySender struct {
	manager *Manager
	sender  *account.SMTPSender
	source  EffectiveSource
}

func (s *deliverySender) Send(ctx context.Context, message account.EmailMessage) error {
	err := s.sender.Send(ctx, message)
	outcome := DeliveryOutcome{Source: s.source, Success: err == nil}
	if err != nil {
		outcome.Category, outcome.Reason = runtimeFailureDetails(err)
		if outcome.Category == ErrorCategoryUnknown {
			if errors.Is(err, context.Canceled) {
				return err
			}
			outcome.Category = ErrorCategoryTransport
		}
	}
	recordContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	transition, recordErr := s.manager.store.RecordDeliveryOutcome(recordContext, outcome)
	cancel()
	if recordErr != nil {
		if !errors.Is(recordErr, ErrStaleEffectiveConfig) {
			s.manager.report(fmt.Errorf("recording SMTP delivery outcome: %w", recordErr))
		}
	} else if transition.Changed {
		loadContext, loadCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		loadErr := s.manager.Load(loadContext)
		loadCancel()
		if loadErr != nil {
			s.manager.report(fmt.Errorf("reloading mail runtime after delivery outcome: %w", loadErr))
		}
	}
	return err
}

func effectiveSource(effective EffectiveConfig) EffectiveSource {
	source := EffectiveSource{Mode: effective.Mode}
	if effective.VersionID != nil {
		versionID := *effective.VersionID
		source.VersionID = &versionID
	}
	return source
}

func runtimeFailureDetails(err error) (string, string) {
	category, permanent := account.SMTPErrorDetails(err)
	switch category {
	case account.SMTPErrorConfiguration:
		if !permanent {
			return ErrorCategoryTransport, "smtp_transport_failed"
		}
		return ErrorCategoryConfiguration, "smtp_configuration_failed"
	case account.SMTPErrorAuthentication:
		if !permanent {
			return ErrorCategoryTransport, "smtp_transport_failed"
		}
		return ErrorCategoryAuthentication, "smtp_authentication_failed"
	case account.SMTPErrorTLS:
		if !permanent {
			return ErrorCategoryTransport, "smtp_transport_failed"
		}
		return ErrorCategoryTLS, "smtp_tls_failed"
	case account.SMTPErrorTransport:
		return ErrorCategoryTransport, "smtp_transport_failed"
	case account.SMTPErrorRecipient:
		return ErrorCategoryRecipient, "smtp_recipient_failed"
	default:
		return ErrorCategoryUnknown, "smtp_unclassified_failure"
	}
}

func deterministicEffectiveConfigError(err error) bool {
	return errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrVersionNotFound)
}
