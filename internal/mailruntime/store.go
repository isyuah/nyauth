package mailruntime

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
)

type Store struct {
	db          *pgxpool.Pool
	activeKeyID string
	masterKeys  map[string][]byte
	clock       func() time.Time
}

type storedVersion struct {
	version            Version
	passwordCiphertext *string
}

type rowQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type rowScanner interface {
	Scan(...any) error
}

func NewStore(db *pgxpool.Pool, options StoreOptions) (*Store, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	options.ActiveKeyID = strings.TrimSpace(options.ActiveKeyID)
	if options.ActiveKeyID == "" {
		return nil, fmt.Errorf("%w: active envelope key ID is required", ErrInvalidConfig)
	}
	activeKey, ok := options.MasterKeys[options.ActiveKeyID]
	if !ok {
		return nil, fmt.Errorf("%w: active envelope key %q is unavailable", ErrInvalidConfig, options.ActiveKeyID)
	}
	if len(activeKey) != 32 {
		return nil, fmt.Errorf("%w: active envelope key must be exactly 32 bytes", ErrInvalidConfig)
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for keyID, key := range options.MasterKeys {
		if len(key) != 32 {
			return nil, fmt.Errorf("%w: envelope key %q must be exactly 32 bytes", ErrInvalidConfig, keyID)
		}
		keys[keyID] = append([]byte(nil), key...)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Store{db: db, activeKeyID: options.ActiveKeyID, masterKeys: keys, clock: options.Clock}, nil
}

func (s *Store) LoadState(ctx context.Context) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	state, err := scanState(s.db.QueryRow(ctx, `
		SELECT mode,active_version_id,candidate_version_id,previous_version_id,revision,
		       circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		       transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		FROM mail_runtime_state WHERE singleton=TRUE
	`))
	if err != nil {
		return State{}, fmt.Errorf("loading mail runtime state: %w", err)
	}
	return state, nil
}

func (s *Store) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	if s == nil || s.db == nil {
		return Version{}, ErrStoreUnavailable
	}
	if id == uuid.Nil {
		return Version{}, fmt.Errorf("%w: version ID is required", ErrInvalidConfig)
	}
	stored, err := loadStoredVersion(ctx, s.db, id)
	if err != nil {
		return Version{}, err
	}
	return stored.version, nil
}

// LoadVersionConfig decrypts one stored version for internal sender
// construction. SMTPConfig excludes Password from JSON, but callers must still
// keep the value out of logs and API responses.
func (s *Store) LoadVersionConfig(ctx context.Context, id uuid.UUID) (Version, SMTPConfig, error) {
	if s == nil || s.db == nil {
		return Version{}, SMTPConfig{}, ErrStoreUnavailable
	}
	if id == uuid.Nil {
		return Version{}, SMTPConfig{}, fmt.Errorf("%w: version ID is required", ErrInvalidConfig)
	}
	stored, err := loadStoredVersion(ctx, s.db, id)
	if err != nil {
		return Version{}, SMTPConfig{}, err
	}
	password, err := s.decryptPassword(stored)
	if err != nil {
		return Version{}, SMTPConfig{}, fmt.Errorf("decrypting mail configuration version: %w", err)
	}
	return stored.version, SMTPConfig{Settings: stored.version.Settings, Password: password}, nil
}

// LoadEffectiveConfig resolves exactly one of the three modes. Environment
// fallback is used only in fallback mode; active load/decryption failures never
// silently fall back, and disabled mode always returns no configuration.
func (s *Store) LoadEffectiveConfig(ctx context.Context, fallback *SMTPConfig) (EffectiveConfig, error) {
	state, err := s.LoadState(ctx)
	if err != nil {
		return EffectiveConfig{}, err
	}
	result := EffectiveConfig{
		Mode: state.Mode, StateRevision: state.Revision,
		CircuitState: state.CircuitState,
	}
	switch state.Mode {
	case ModeDisabled:
		return result, nil
	case ModeFallback:
		if fallback == nil {
			return result, nil
		}
		result.Configured = true
		normalized, err := normalizeSettings(fallback.Settings)
		if err != nil {
			return result, fmt.Errorf("validating environment mail fallback: %w", err)
		}
		config := &SMTPConfig{Settings: normalized, Password: fallback.Password}
		result.Config = config
		result.Available = state.CircuitState == CircuitClosed
		return result, nil
	case ModeActive:
		result.Configured = true
		if state.ActiveVersionID == nil {
			return result, fmt.Errorf("loading active mail configuration: %w", ErrVersionNotFound)
		}
		stored, err := loadStoredVersion(ctx, s.db, *state.ActiveVersionID)
		if err != nil {
			return result, fmt.Errorf("loading active mail configuration: %w", err)
		}
		versionID := stored.version.ID
		versionRevision := stored.version.Revision
		result.VersionID = &versionID
		result.VersionRevision = &versionRevision
		password, err := s.decryptPassword(stored)
		if err != nil {
			return result, fmt.Errorf("%w: decrypting active mail configuration: %v", ErrInvalidConfig, err)
		}
		result.Config = &SMTPConfig{Settings: stored.version.Settings, Password: password}
		result.Available = state.CircuitState == CircuitClosed
		return result, nil
	default:
		return result, fmt.Errorf("%w: unsupported mail runtime mode %q", ErrInvalidConfig, state.Mode)
	}
}

func (s *Store) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	if s == nil || s.db == nil {
		return CandidateResult{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return CandidateResult{}, fmt.Errorf("%w: expected revision must be nonnegative", ErrInvalidConfig)
	}
	if err := input.Audit.ValidateEvent(AuditSettingsSaved); err != nil {
		return CandidateResult{}, fmt.Errorf("invalid mail settings audit context: %w", err)
	}
	settings, err := normalizeSettings(input.Settings)
	if err != nil {
		return CandidateResult{}, err
	}
	if input.Password != nil && len(*input.Password) > 4096 {
		return CandidateResult{}, fmt.Errorf("%w: SMTP password is too long", ErrInvalidConfig)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("starting mail candidate transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return CandidateResult{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return CandidateResult{}, err
	}

	versionID := uuid.New()
	password, configured, err := s.resolveCandidatePassword(ctx, tx, state, input)
	if err != nil {
		return CandidateResult{}, err
	}
	var ciphertext *string
	if configured {
		encrypted, err := internalcrypto.EncryptEnvelope(
			s.masterKeys[s.activeKeyID], s.activeKeyID, PasswordEnvelopePurpose,
			[]byte(password), []byte(versionID.String()),
		)
		if err != nil {
			return CandidateResult{}, fmt.Errorf("encrypting SMTP password: %w", err)
		}
		ciphertext = &encrypted
	}

	createdAt := s.now()
	var version Version
	version.ID = versionID
	version.Settings = settings
	version.PasswordConfigured = configured
	createdBy := input.Audit.ActorID
	version.CreatedBy = &createdBy
	err = tx.QueryRow(ctx, `
		INSERT INTO mail_config_versions (
			id,host,port,username,password_ciphertext,tls_mode,from_address,from_name,
			public_base_url,connect_timeout_ms,send_timeout_ms,created_by,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING revision,created_at
	`, version.ID, settings.Host, settings.Port, settings.Username, ciphertext, settings.TLSMode,
		settings.FromAddress, settings.FromName, settings.PublicBaseURL,
		durationMilliseconds(settings.ConnectTimeout), durationMilliseconds(settings.SendTimeout),
		createdBy, createdAt).Scan(&version.Revision, &version.CreatedAt)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("inserting mail configuration candidate: %w", err)
	}

	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state
		SET candidate_version_id=$1,revision=revision+1,updated_at=$2
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, version.ID, createdAt))
	if err != nil {
		return CandidateResult{}, fmt.Errorf("publishing mail configuration candidate: %w", err)
	}
	mutation := input.Audit.WithTarget("mail_config", version.ID.String()).WithDetails(map[string]any{
		"version_revision":      version.Revision,
		"credential_configured": version.PasswordConfigured,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return CandidateResult{}, fmt.Errorf("auditing mail configuration candidate: %w", err)
	}
	if err := notifyTx(ctx, tx, "candidate", state.Revision); err != nil {
		return CandidateResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CandidateResult{}, fmt.Errorf("committing mail configuration candidate: %w", err)
	}
	return CandidateResult{Version: version, State: state}, nil
}

func (s *Store) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	if s == nil || s.db == nil {
		return TestResult{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 || input.VersionID == uuid.Nil {
		return TestResult{}, fmt.Errorf("%w: version and expected revision are required", ErrInvalidConfig)
	}
	if err := input.Audit.ValidateEvent(AuditSettingsTested); err != nil {
		return TestResult{}, fmt.Errorf("invalid mail test audit context: %w", err)
	}
	category, err := normalizeTestResult(input.Result, input.ErrorCategory)
	if err != nil {
		return TestResult{}, err
	}
	if len(input.RecipientHash) != 32 {
		return TestResult{}, fmt.Errorf("%w: recipient hash must be exactly 32 bytes", ErrInvalidConfig)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return TestResult{}, fmt.Errorf("starting mail test transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return TestResult{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return TestResult{}, err
	}
	if state.CandidateVersionID == nil {
		return TestResult{}, ErrCandidateNotFound
	}
	if *state.CandidateVersionID != input.VersionID {
		return TestResult{}, ErrCandidateChanged
	}

	record := TestRecord{
		ID: uuid.New(), VersionID: input.VersionID, Result: strings.TrimSpace(input.Result),
		ErrorCategory: category, CreatedAt: s.now(),
	}
	testedBy := input.Audit.ActorID
	record.TestedBy = &testedBy
	_, err = tx.Exec(ctx, `
		INSERT INTO mail_config_tests (
			id,version_id,recipient_hash,result,error_category,tested_by,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
	`, record.ID, record.VersionID, append([]byte(nil), input.RecipientHash...), record.Result,
		record.ErrorCategory, testedBy, record.CreatedAt)
	if err != nil {
		return TestResult{}, fmt.Errorf("recording mail configuration test: %w", err)
	}
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state SET revision=revision+1,updated_at=$1
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, record.CreatedAt))
	if err != nil {
		return TestResult{}, fmt.Errorf("advancing mail test state: %w", err)
	}
	details := map[string]any{"test_result": record.Result}
	if record.ErrorCategory != nil {
		details["error_category"] = *record.ErrorCategory
	}
	if err := audit.EnqueueMutationTx(ctx, tx,
		input.Audit.WithTarget("mail_config", record.VersionID.String()).WithDetails(details)); err != nil {
		return TestResult{}, fmt.Errorf("auditing mail configuration test: %w", err)
	}
	if err := notifyTx(ctx, tx, "tested", state.Revision); err != nil {
		return TestResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TestResult{}, fmt.Errorf("committing mail configuration test: %w", err)
	}
	return TestResult{Record: record, State: state}, nil
}

func (s *Store) Activate(ctx context.Context, input VersionMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 || input.VersionID == uuid.Nil {
		return State{}, fmt.Errorf("%w: version and expected revision are required", ErrInvalidConfig)
	}
	if err := input.Audit.ValidateEvent(AuditSettingsActivated); err != nil {
		return State{}, fmt.Errorf("invalid mail activation audit context: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, fmt.Errorf("starting mail activation transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return State{}, err
	}
	if state.CandidateVersionID == nil {
		return State{}, ErrCandidateNotFound
	}
	if *state.CandidateVersionID != input.VersionID {
		return State{}, ErrCandidateChanged
	}

	now := s.now()
	var testedAt time.Time
	err = tx.QueryRow(ctx, `
		SELECT created_at FROM mail_config_tests
		WHERE version_id=$1 AND result='success'
		ORDER BY created_at DESC LIMIT 1
	`, input.VersionID).Scan(&testedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrCandidateTestRequired
	}
	if err != nil {
		return State{}, fmt.Errorf("checking mail candidate test: %w", err)
	}
	testedAt = testedAt.UTC()
	if testedAt.After(now) {
		return State{}, ErrCandidateTestRequired
	}
	if testedAt.Before(now.Add(-CandidateTestValidity)) {
		return State{}, ErrCandidateTestExpired
	}

	previous := state.PreviousVersionID
	if state.Mode == ModeActive {
		previous = state.ActiveVersionID
	}
	wasOpen := state.CircuitState == CircuitOpen
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state
		SET mode='active',active_version_id=$1,candidate_version_id=NULL,previous_version_id=$2,
		    revision=revision+1,circuit_state='closed',circuit_open_reason=NULL,
		    circuit_open_category=NULL,circuit_opened_at=NULL,
		    transport_failure_window_started_at=NULL,transport_failure_count=0,
		    next_probe_at=NULL,updated_at=$3
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, input.VersionID, previous, now))
	if err != nil {
		return State{}, fmt.Errorf("activating mail configuration: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx,
		input.Audit.WithTarget("mail_config", input.VersionID.String()).WithDetails(map[string]any{
			"tested_at": testedAt,
		})); err != nil {
		return State{}, fmt.Errorf("auditing mail configuration activation: %w", err)
	}
	if wasOpen {
		if err := enqueueCircuitRecoveredTx(ctx, tx, input.VersionID.String(), "configuration_activated", now); err != nil {
			return State{}, err
		}
	}
	if err := notifyTx(ctx, tx, "activated", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, fmt.Errorf("committing mail configuration activation: %w", err)
	}
	return state, nil
}

func (s *Store) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return State{}, fmt.Errorf("%w: expected revision must be nonnegative", ErrInvalidConfig)
	}
	if err := input.Audit.ValidateEvent(AuditSettingsRolledBack); err != nil {
		return State{}, fmt.Errorf("invalid mail rollback audit context: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, fmt.Errorf("starting mail rollback transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return State{}, err
	}
	if state.PreviousVersionID == nil || (state.Mode != ModeActive && state.Mode != ModeDisabled) {
		return State{}, ErrNoPreviousVersion
	}
	toVersion := *state.PreviousVersionID
	var fromVersion *uuid.UUID
	var nextPrevious *uuid.UUID
	if state.Mode == ModeActive {
		if state.ActiveVersionID == nil {
			return State{}, ErrNoPreviousVersion
		}
		from := *state.ActiveVersionID
		fromVersion = &from
		nextPrevious = &from
	}
	wasOpen := state.CircuitState == CircuitOpen
	now := s.now()
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state
		SET mode='active',active_version_id=$1,previous_version_id=$2,revision=revision+1,
		    circuit_state='closed',circuit_open_reason=NULL,circuit_open_category=NULL,
		    circuit_opened_at=NULL,transport_failure_window_started_at=NULL,
		    transport_failure_count=0,next_probe_at=NULL,updated_at=$3
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, toVersion, nextPrevious, now))
	if err != nil {
		return State{}, fmt.Errorf("rolling back mail configuration: %w", err)
	}
	details := map[string]any{"from_mode": stateModeBeforeRollback(fromVersion)}
	if fromVersion != nil {
		details["from_version_id"] = fromVersion.String()
	}
	if err := audit.EnqueueMutationTx(ctx, tx,
		input.Audit.WithTarget("mail_config", toVersion.String()).WithDetails(details)); err != nil {
		return State{}, fmt.Errorf("auditing mail configuration rollback: %w", err)
	}
	if wasOpen {
		if err := enqueueCircuitRecoveredTx(ctx, tx, toVersion.String(), "configuration_rolled_back", now); err != nil {
			return State{}, err
		}
	}
	if err := notifyTx(ctx, tx, "rolled_back", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, fmt.Errorf("committing mail configuration rollback: %w", err)
	}
	return state, nil
}

func stateModeBeforeRollback(fromVersion *uuid.UUID) string {
	if fromVersion == nil {
		return ModeDisabled
	}
	return ModeActive
}

func (s *Store) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return State{}, fmt.Errorf("%w: expected revision must be nonnegative", ErrInvalidConfig)
	}
	if err := input.Audit.ValidateEvent(AuditSettingsDisabled); err != nil {
		return State{}, fmt.Errorf("invalid mail disable audit context: %w", err)
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, fmt.Errorf("starting mail disable transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return State{}, err
	}
	registrationSettings, err := settings.LoadRegistrationTx(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if registrationSettings.Mode != settings.RegistrationClosed {
		return State{}, ErrRegistrationOpen
	}
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return State{}, err
	}
	if state.Mode == ModeDisabled {
		return State{}, ErrAlreadyDisabled
	}
	previous := state.PreviousVersionID
	if state.Mode == ModeActive {
		previous = state.ActiveVersionID
	}
	now := s.now()
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE mail_runtime_state
		SET mode='disabled',active_version_id=NULL,previous_version_id=$1,
		    revision=revision+1,circuit_state='closed',circuit_open_reason=NULL,
		    circuit_open_category=NULL,circuit_opened_at=NULL,
		    transport_failure_window_started_at=NULL,transport_failure_count=0,
		    next_probe_at=NULL,updated_at=$2
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,
		          circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		          transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
	`, previous, now))
	if err != nil {
		return State{}, fmt.Errorf("disabling runtime mail: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx,
		input.Audit.WithTarget("mail_runtime", "singleton")); err != nil {
		return State{}, fmt.Errorf("auditing runtime mail disable: %w", err)
	}
	if err := notifyTx(ctx, tx, "disabled", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, fmt.Errorf("committing runtime mail disable: %w", err)
	}
	return state, nil
}

func (s *Store) resolveCandidatePassword(
	ctx context.Context,
	tx pgx.Tx,
	state State,
	input CreateCandidateInput,
) (string, bool, error) {
	if input.Password != nil {
		if *input.Password == "" {
			return "", false, nil
		}
		return *input.Password, true, nil
	}
	switch state.Mode {
	case ModeFallback:
		if input.Fallback == nil {
			return "", false, ErrPasswordInheritance
		}
		return input.Fallback.Password, input.Fallback.Password != "", nil
	case ModeActive:
		if state.ActiveVersionID == nil {
			return "", false, ErrPasswordInheritance
		}
		stored, err := loadStoredVersion(ctx, tx, *state.ActiveVersionID)
		if err != nil {
			return "", false, fmt.Errorf("loading password inheritance source: %w", err)
		}
		if stored.passwordCiphertext == nil {
			return "", false, nil
		}
		password, err := s.decryptPassword(stored)
		if err != nil {
			return "", false, fmt.Errorf("decrypting inherited SMTP password: %w", err)
		}
		return password, password != "", nil
	case ModeDisabled:
		return "", false, ErrPasswordInheritance
	default:
		return "", false, fmt.Errorf("%w: unsupported mail runtime mode %q", ErrInvalidConfig, state.Mode)
	}
}

func (s *Store) decryptPassword(stored storedVersion) (string, error) {
	if stored.passwordCiphertext == nil {
		return "", nil
	}
	plaintext, err := internalcrypto.DecryptEnvelope(
		s.masterKeys, PasswordEnvelopePurpose, *stored.passwordCiphertext,
		[]byte(stored.version.ID.String()),
	)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func loadStoredVersion(ctx context.Context, db rowQueryer, id uuid.UUID) (storedVersion, error) {
	var stored storedVersion
	stored.version.ID = id
	var connectTimeoutMS, sendTimeoutMS int64
	err := db.QueryRow(ctx, `
		SELECT revision,host,port,username,password_ciphertext,tls_mode,from_address,from_name,
		       public_base_url,connect_timeout_ms,send_timeout_ms,created_by,created_at
		FROM mail_config_versions WHERE id=$1
	`, id).Scan(
		&stored.version.Revision, &stored.version.Host, &stored.version.Port,
		&stored.version.Username, &stored.passwordCiphertext, &stored.version.TLSMode,
		&stored.version.FromAddress, &stored.version.FromName, &stored.version.PublicBaseURL,
		&connectTimeoutMS, &sendTimeoutMS, &stored.version.CreatedBy, &stored.version.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedVersion{}, ErrVersionNotFound
	}
	if err != nil {
		return storedVersion{}, fmt.Errorf("loading mail configuration version: %w", err)
	}
	stored.version.ConnectTimeout = time.Duration(connectTimeoutMS) * time.Millisecond
	stored.version.SendTimeout = time.Duration(sendTimeoutMS) * time.Millisecond
	stored.version.PasswordConfigured = stored.passwordCiphertext != nil
	stored.version.CreatedAt = stored.version.CreatedAt.UTC()
	return stored, nil
}

func lockState(ctx context.Context, tx pgx.Tx) (State, error) {
	state, err := scanState(tx.QueryRow(ctx, `
		SELECT mode,active_version_id,candidate_version_id,previous_version_id,revision,
		       circuit_state,circuit_open_reason,circuit_open_category,circuit_opened_at,
		       transport_failure_window_started_at,transport_failure_count,next_probe_at,updated_at
		FROM mail_runtime_state WHERE singleton=TRUE FOR UPDATE
	`))
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, fmt.Errorf("mail runtime singleton state is missing")
	}
	if err != nil {
		return State{}, fmt.Errorf("locking mail runtime state: %w", err)
	}
	return state, nil
}

func scanState(row rowScanner) (State, error) {
	var state State
	err := row.Scan(
		&state.Mode, &state.ActiveVersionID, &state.CandidateVersionID, &state.PreviousVersionID,
		&state.Revision, &state.CircuitState, &state.CircuitOpenReason,
		&state.CircuitOpenCategory, &state.CircuitOpenedAt,
		&state.TransportFailureWindowStarted, &state.TransportFailureCount,
		&state.NextProbeAt, &state.UpdatedAt,
	)
	if err != nil {
		return State{}, err
	}
	state.UpdatedAt = state.UpdatedAt.UTC()
	utcTimePointer(state.CircuitOpenedAt)
	utcTimePointer(state.TransportFailureWindowStarted)
	utcTimePointer(state.NextProbeAt)
	return state, nil
}

func requireRevision(state State, expected int64) error {
	if state.Revision != expected {
		return fmt.Errorf("%w: expected %d, current %d", ErrStateConflict, expected, state.Revision)
	}
	return nil
}

func notifyTx(ctx context.Context, tx pgx.Tx, kind string, revision int64) error {
	payload := fmt.Sprintf("%s:%d", kind, revision)
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1,$2)`, NotificationChannel, payload); err != nil {
		return fmt.Errorf("notifying mail runtime change: %w", err)
	}
	return nil
}

func normalizeSettings(value Settings) (Settings, error) {
	value.Host = strings.TrimSpace(value.Host)
	value.Username = strings.TrimSpace(value.Username)
	value.TLSMode = strings.ToLower(strings.TrimSpace(value.TLSMode))
	value.FromAddress = strings.TrimSpace(value.FromAddress)
	value.FromName = strings.TrimSpace(value.FromName)
	value.PublicBaseURL = strings.TrimSpace(value.PublicBaseURL)
	if value.Host == "" || len(value.Host) > 253 || containsLineBreak(value.Host) {
		return Settings{}, fmt.Errorf("%w: SMTP host is invalid", ErrInvalidConfig)
	}
	if value.Port < 1 || value.Port > 65535 {
		return Settings{}, fmt.Errorf("%w: SMTP port must be between 1 and 65535", ErrInvalidConfig)
	}
	if len(value.Username) > 320 || containsLineBreak(value.Username) {
		return Settings{}, fmt.Errorf("%w: SMTP username is invalid", ErrInvalidConfig)
	}
	switch value.TLSMode {
	case TLSModeStartTLS, TLSModeImplicit, TLSModePlain:
	default:
		return Settings{}, fmt.Errorf("%w: SMTP TLS mode is invalid", ErrInvalidConfig)
	}
	parsedAddress, err := mail.ParseAddress(value.FromAddress)
	if err != nil || parsedAddress.Address != value.FromAddress || len(value.FromAddress) > 320 || containsLineBreak(value.FromAddress) {
		return Settings{}, fmt.Errorf("%w: SMTP from address is invalid", ErrInvalidConfig)
	}
	if len(value.FromName) > 255 || containsLineBreak(value.FromName) {
		return Settings{}, fmt.Errorf("%w: SMTP from name is invalid", ErrInvalidConfig)
	}
	parsedURL, err := url.Parse(value.PublicBaseURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" ||
		parsedURL.User != nil || parsedURL.RawQuery != "" || parsedURL.Fragment != "" ||
		len(value.PublicBaseURL) > 2048 || containsLineBreak(value.PublicBaseURL) {
		return Settings{}, fmt.Errorf("%w: public base URL must be an absolute HTTP(S) URL without credentials, query, or fragment", ErrInvalidConfig)
	}
	if err := validateStoredDuration("SMTP connect timeout", value.ConnectTimeout, 100*time.Millisecond, 5*time.Minute); err != nil {
		return Settings{}, err
	}
	if err := validateStoredDuration("SMTP send timeout", value.SendTimeout, 100*time.Millisecond, 10*time.Minute); err != nil {
		return Settings{}, err
	}
	return value, nil
}

func validateStoredDuration(name string, value, minimum, maximum time.Duration) error {
	if value < minimum || value > maximum || value%time.Millisecond != 0 {
		return fmt.Errorf("%w: %s must be a whole number of milliseconds between %s and %s", ErrInvalidConfig, name, minimum, maximum)
	}
	return nil
}

func normalizeTestResult(result string, category *string) (*string, error) {
	result = strings.TrimSpace(result)
	if result == TestResultSuccess {
		if category != nil && strings.TrimSpace(*category) != "" {
			return nil, fmt.Errorf("%w: successful test cannot have an error category", ErrInvalidConfig)
		}
		return nil, nil
	}
	if result != TestResultFailure || category == nil {
		return nil, fmt.Errorf("%w: test result and error category are inconsistent", ErrInvalidConfig)
	}
	normalized := strings.ToLower(strings.TrimSpace(*category))
	if !validErrorCategory(normalized, true) {
		return nil, fmt.Errorf("%w: test error category is invalid", ErrInvalidConfig)
	}
	return &normalized, nil
}

func validErrorCategory(value string, allowRecipientAndUnknown bool) bool {
	switch value {
	case ErrorCategoryConfiguration, ErrorCategoryAuthentication, ErrorCategoryTLS, ErrorCategoryTransport:
		return true
	case ErrorCategoryRecipient, ErrorCategoryUnknown:
		return allowRecipientAndUnknown
	default:
		return false
	}
}

func containsLineBreak(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}

func durationMilliseconds(value time.Duration) int64 {
	return value.Milliseconds()
}

func (s *Store) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func utcTimePointer(value *time.Time) {
	if value != nil {
		*value = value.UTC()
	}
}
