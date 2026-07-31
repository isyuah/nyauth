package observabilityruntime

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
)

type Store struct {
	db          *pgxpool.Pool
	activeKeyID string
	masterKeys  map[string][]byte
	clock       func() time.Time
}

type storedVersion struct {
	version                 Version
	authorizationCiphertext *string
}

type rowQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func NewStore(db *pgxpool.Pool, options StoreOptions) (*Store, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	options.ActiveKeyID = strings.TrimSpace(options.ActiveKeyID)
	activeKey, ok := options.MasterKeys[options.ActiveKeyID]
	if options.ActiveKeyID == "" || !ok || len(activeKey) != 32 {
		return nil, fmt.Errorf("%w: a 32-byte active envelope key is required", ErrInvalidConfig)
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for id, key := range options.MasterKeys {
		if len(key) != 32 {
			return nil, fmt.Errorf("%w: envelope key %q must be 32 bytes", ErrInvalidConfig, id)
		}
		keys[id] = append([]byte(nil), key...)
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	return &Store{db: db, activeKeyID: options.ActiveKeyID, masterKeys: keys, clock: options.Clock}, nil
}

func ValidateSettings(value Settings, production bool) (Settings, error) {
	value.Endpoint = strings.TrimSpace(value.Endpoint)
	parsed, err := url.Parse(value.Endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return Settings{}, fmt.Errorf("%w: endpoint must be an absolute HTTP(S) URL without credentials, query, or fragment", ErrInvalidConfig)
	}
	if production && parsed.Scheme != "https" {
		return Settings{}, fmt.Errorf("%w: endpoint must use HTTPS in production", ErrInvalidConfig)
	}
	if len(value.Endpoint) > 2048 || strings.ContainsAny(value.Endpoint, "\r\n") {
		return Settings{}, fmt.Errorf("%w: endpoint is invalid", ErrInvalidConfig)
	}
	if value.ExportInterval < 10*time.Second || value.ExportInterval > time.Hour {
		return Settings{}, fmt.Errorf("%w: export_interval must be between 10s and 1h", ErrInvalidConfig)
	}
	if value.Timeout < time.Second || value.Timeout > 30*time.Second || value.Timeout > value.ExportInterval {
		return Settings{}, fmt.Errorf("%w: timeout must be between 1s and 30s and not exceed export_interval", ErrInvalidConfig)
	}
	return value, nil
}

func ValidateAuthorization(value string) error {
	if len(value) > 4096 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%w: authorization header is invalid", ErrInvalidConfig)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: authorization header contains control characters", ErrInvalidConfig)
		}
	}
	return nil
}

func (s *Store) LoadState(ctx context.Context) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	return scanState(s.db.QueryRow(ctx, `SELECT mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at FROM otlp_runtime_state WHERE singleton=TRUE`))
}

func (s *Store) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	if s == nil || s.db == nil {
		return Version{}, ErrStoreUnavailable
	}
	stored, err := loadStoredVersion(ctx, s.db, id)
	return stored.version, err
}

func (s *Store) LoadVersionConfig(ctx context.Context, id uuid.UUID) (Version, Config, error) {
	if s == nil || s.db == nil {
		return Version{}, Config{}, ErrStoreUnavailable
	}
	stored, err := loadStoredVersion(ctx, s.db, id)
	if err != nil {
		return Version{}, Config{}, err
	}
	authorization, err := s.decryptAuthorization(stored)
	if err != nil {
		return Version{}, Config{}, fmt.Errorf("decrypting OTLP authorization: %w", err)
	}
	return stored.version, Config{Settings: stored.version.Settings, Authorization: authorization}, nil
}

func (s *Store) LoadLatestTest(ctx context.Context, versionID uuid.UUID) (*TestRecord, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}
	if versionID == uuid.Nil {
		return nil, ErrCandidateNotFound
	}
	var record TestRecord
	record.VersionID = versionID
	err := s.db.QueryRow(ctx, `
		SELECT id,revision,result,error_code,tested_by,created_at
		FROM otlp_config_tests
		WHERE version_id=$1
		ORDER BY revision DESC
		LIMIT 1
	`, versionID).Scan(&record.ID, &record.Revision, &record.Result, &record.ErrorCode, &record.TestedBy, &record.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("loading latest OTLP candidate test: %w", err)
	}
	return &record, nil
}

func (s *Store) LoadEffectiveConfig(ctx context.Context, fallback *Config) (EffectiveConfig, error) {
	state, err := s.LoadState(ctx)
	if err != nil {
		return EffectiveConfig{}, err
	}
	result := EffectiveConfig{Mode: state.Mode, StateRevision: state.Revision}
	switch state.Mode {
	case ModeDisabled:
		return result, nil
	case ModeFallback:
		if fallback == nil {
			return result, nil
		}
		copyValue := *fallback
		result.Configured, result.Config = true, &copyValue
		return result, nil
	case ModeActive:
		result.Configured = true
		if state.ActiveVersionID == nil {
			return result, fmt.Errorf("%w: active version missing", ErrInvalidConfig)
		}
		_, config, err := s.LoadVersionConfig(ctx, *state.ActiveVersionID)
		if err != nil {
			return result, fmt.Errorf("%w: loading active OTLP configuration: %v", ErrInvalidConfig, err)
		}
		id := *state.ActiveVersionID
		result.VersionID, result.Config = &id, &config
		return result, nil
	default:
		return result, fmt.Errorf("%w: unsupported mode %q", ErrInvalidConfig, state.Mode)
	}
}

func (s *Store) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	if s == nil || s.db == nil {
		return CandidateResult{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return CandidateResult{}, ErrInvalidConfig
	}
	if err := input.Audit.ValidateEvent(AuditSettingsSaved); err != nil {
		return CandidateResult{}, err
	}
	settings, err := ValidateSettings(input.Settings, false)
	if err != nil {
		return CandidateResult{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("starting OTLP candidate transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return CandidateResult{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return CandidateResult{}, ErrStateConflict
	}
	authorization, err := s.resolveAuthorization(ctx, tx, state, input)
	if err != nil {
		return CandidateResult{}, err
	}
	if err := ValidateAuthorization(authorization); err != nil {
		return CandidateResult{}, err
	}

	version := Version{ID: uuid.New(), Settings: settings, AuthorizationConfigured: authorization != "", CreatedAt: s.now()}
	actorID := input.Audit.ActorID
	version.CreatedBy = &actorID
	var ciphertext *string
	if authorization != "" {
		sealed, encryptErr := internalcrypto.EncryptEnvelope(s.masterKeys[s.activeKeyID], s.activeKeyID, EnvelopePurpose, []byte(authorization), []byte(version.ID.String()))
		if encryptErr != nil {
			return CandidateResult{}, fmt.Errorf("encrypting OTLP authorization: %w", encryptErr)
		}
		ciphertext = &sealed
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO otlp_config_versions (id,endpoint,authorization_ciphertext,export_interval_ms,timeout_ms,created_by,created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING revision
	`, version.ID, version.Endpoint, ciphertext, version.ExportInterval.Milliseconds(), version.Timeout.Milliseconds(), actorID, version.CreatedAt).Scan(&version.Revision)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("storing OTLP candidate: %w", err)
	}
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE otlp_runtime_state SET candidate_version_id=$1,revision=revision+1,updated_at=$2 WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at
	`, version.ID, version.CreatedAt))
	if err != nil {
		return CandidateResult{}, fmt.Errorf("updating OTLP candidate state: %w", err)
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("telemetry_config", version.ID.String()).WithDetails(map[string]any{
		"endpoint": version.Endpoint, "export_interval": version.ExportInterval.String(), "timeout": version.Timeout.String(), "authorization_configured": version.AuthorizationConfigured,
	})); err != nil {
		return CandidateResult{}, fmt.Errorf("auditing OTLP candidate: %w", err)
	}
	if err := notifyTx(ctx, tx, "candidate", state.Revision); err != nil {
		return CandidateResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CandidateResult{}, fmt.Errorf("committing OTLP candidate: %w", err)
	}
	return CandidateResult{Version: version, State: state}, nil
}

func (s *Store) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	if s == nil || s.db == nil {
		return TestResult{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 || input.VersionID == uuid.Nil {
		return TestResult{}, ErrInvalidConfig
	}
	if err := input.Audit.ValidateEvent(AuditSettingsTested); err != nil {
		return TestResult{}, err
	}
	if input.Result != TestSuccess && input.Result != TestFailure {
		return TestResult{}, ErrInvalidConfig
	}
	if (input.Result == TestSuccess) != (input.ErrorCode == nil) {
		return TestResult{}, ErrInvalidConfig
	}
	if input.ErrorCode != nil && *input.ErrorCode != TestErrorTimeout && *input.ErrorCode != TestErrorConnectionOrCollectorRejected {
		return TestResult{}, ErrInvalidConfig
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return TestResult{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return TestResult{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return TestResult{}, ErrStateConflict
	}
	if state.CandidateVersionID == nil {
		return TestResult{}, ErrCandidateNotFound
	}
	if *state.CandidateVersionID != input.VersionID {
		return TestResult{}, ErrCandidateChanged
	}
	now := s.now()
	record := TestRecord{ID: uuid.New(), VersionID: input.VersionID, Result: input.Result, ErrorCode: input.ErrorCode, CreatedAt: now}
	actorID := input.Audit.ActorID
	record.TestedBy = &actorID
	err = tx.QueryRow(ctx, `INSERT INTO otlp_config_tests (id,version_id,result,error_code,tested_by,created_at) VALUES ($1,$2,$3,$4,$5,$6) RETURNING revision`, record.ID, record.VersionID, record.Result, record.ErrorCode, actorID, now).Scan(&record.Revision)
	if err != nil {
		return TestResult{}, fmt.Errorf("recording OTLP test: %w", err)
	}
	state, err = scanState(tx.QueryRow(ctx, `UPDATE otlp_runtime_state SET revision=revision+1,updated_at=$1 WHERE singleton=TRUE RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at`, now))
	if err != nil {
		return TestResult{}, err
	}
	details := map[string]any{"result": input.Result}
	if input.ErrorCode != nil {
		details["error_code"] = *input.ErrorCode
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("telemetry_config", input.VersionID.String()).WithDetails(details)); err != nil {
		return TestResult{}, err
	}
	if err := notifyTx(ctx, tx, "tested", state.Revision); err != nil {
		return TestResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TestResult{}, err
	}
	return TestResult{Record: record, State: state}, nil
}

func (s *Store) Activate(ctx context.Context, input VersionMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 || input.VersionID == uuid.Nil {
		return State{}, ErrInvalidConfig
	}
	if err := input.Audit.ValidateEvent(AuditSettingsActivated); err != nil {
		return State{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return State{}, ErrStateConflict
	}
	if state.CandidateVersionID == nil {
		return State{}, ErrCandidateNotFound
	}
	if *state.CandidateVersionID != input.VersionID {
		return State{}, ErrCandidateChanged
	}
	var latestResult string
	var testedAt time.Time
	err = tx.QueryRow(ctx, `SELECT result,created_at FROM otlp_config_tests WHERE version_id=$1 ORDER BY revision DESC LIMIT 1`, input.VersionID).Scan(&latestResult, &testedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, ErrCandidateTestRequired
	}
	if err != nil {
		return State{}, err
	}
	now := s.now()
	if latestResult != TestSuccess || testedAt.After(now) {
		return State{}, ErrCandidateTestRequired
	}
	if testedAt.Before(now.Add(-CandidateTestValidity)) {
		return State{}, ErrCandidateTestExpired
	}
	previous := state.PreviousVersionID
	if state.Mode == ModeActive {
		previous = state.ActiveVersionID
	}
	state, err = scanState(tx.QueryRow(ctx, `UPDATE otlp_runtime_state SET mode='active',active_version_id=$1,candidate_version_id=NULL,previous_version_id=$2,revision=revision+1,updated_at=$3 WHERE singleton=TRUE RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at`, input.VersionID, previous, now))
	if err != nil {
		return State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("telemetry_config", input.VersionID.String()).WithDetails(map[string]any{"tested_at": testedAt})); err != nil {
		return State{}, err
	}
	if err := notifyTx(ctx, tx, "activated", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *Store) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return State{}, ErrInvalidConfig
	}
	if err := input.Audit.ValidateEvent(AuditSettingsRolledBack); err != nil {
		return State{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return State{}, ErrStateConflict
	}
	if state.PreviousVersionID == nil || (state.Mode != ModeActive && state.Mode != ModeDisabled) {
		return State{}, ErrNoPreviousVersion
	}
	target := *state.PreviousVersionID
	var previous *uuid.UUID
	if state.Mode == ModeActive {
		previous = state.ActiveVersionID
	}
	now := s.now()
	state, err = scanState(tx.QueryRow(ctx, `UPDATE otlp_runtime_state SET mode='active',active_version_id=$1,previous_version_id=$2,revision=revision+1,updated_at=$3 WHERE singleton=TRUE RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at`, target, previous, now))
	if err != nil {
		return State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("telemetry_config", target.String())); err != nil {
		return State{}, err
	}
	if err := notifyTx(ctx, tx, "rolled_back", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *Store) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if input.ExpectedRevision < 0 {
		return State{}, ErrInvalidConfig
	}
	if err := input.Audit.ValidateEvent(AuditSettingsDisabled); err != nil {
		return State{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return State{}, ErrStateConflict
	}
	if state.Mode == ModeDisabled {
		return State{}, ErrAlreadyDisabled
	}
	previous := state.PreviousVersionID
	if state.Mode == ModeActive {
		previous = state.ActiveVersionID
	}
	now := s.now()
	state, err = scanState(tx.QueryRow(ctx, `UPDATE otlp_runtime_state SET mode='disabled',active_version_id=NULL,previous_version_id=$1,revision=revision+1,updated_at=$2 WHERE singleton=TRUE RETURNING mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at`, previous, now))
	if err != nil {
		return State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("telemetry_runtime", "singleton")); err != nil {
		return State{}, err
	}
	if err := notifyTx(ctx, tx, "disabled", state.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, err
	}
	return state, nil
}

func (s *Store) resolveAuthorization(ctx context.Context, tx pgx.Tx, state State, input CreateCandidateInput) (string, error) {
	if input.Authorization != nil {
		return *input.Authorization, nil
	}
	switch state.Mode {
	case ModeFallback:
		if input.Fallback == nil {
			return "", ErrAuthorizationInheritance
		}
		return input.Fallback.Authorization, nil
	case ModeActive:
		if state.ActiveVersionID == nil {
			return "", ErrAuthorizationInheritance
		}
		stored, err := loadStoredVersion(ctx, tx, *state.ActiveVersionID)
		if err != nil {
			return "", err
		}
		return s.decryptAuthorization(stored)
	case ModeDisabled:
		return "", ErrAuthorizationInheritance
	default:
		return "", ErrInvalidConfig
	}
}

func (s *Store) decryptAuthorization(stored storedVersion) (string, error) {
	if stored.authorizationCiphertext == nil {
		return "", nil
	}
	plaintext, err := internalcrypto.DecryptEnvelope(s.masterKeys, EnvelopePurpose, *stored.authorizationCiphertext, []byte(stored.version.ID.String()))
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func loadStoredVersion(ctx context.Context, queryer rowQueryer, id uuid.UUID) (storedVersion, error) {
	if id == uuid.Nil {
		return storedVersion{}, ErrCandidateNotFound
	}
	var stored storedVersion
	stored.version.ID = id
	var intervalMS, timeoutMS int64
	err := queryer.QueryRow(ctx, `SELECT revision,endpoint,authorization_ciphertext,export_interval_ms,timeout_ms,created_by,created_at FROM otlp_config_versions WHERE id=$1`, id).Scan(
		&stored.version.Revision, &stored.version.Endpoint, &stored.authorizationCiphertext, &intervalMS, &timeoutMS, &stored.version.CreatedBy, &stored.version.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedVersion{}, ErrCandidateNotFound
	}
	if err != nil {
		return storedVersion{}, err
	}
	stored.version.ExportInterval = time.Duration(intervalMS) * time.Millisecond
	stored.version.Timeout = time.Duration(timeoutMS) * time.Millisecond
	stored.version.AuthorizationConfigured = stored.authorizationCiphertext != nil
	return stored, nil
}

func scanState(row pgx.Row) (State, error) {
	var state State
	err := row.Scan(&state.Mode, &state.ActiveVersionID, &state.CandidateVersionID, &state.PreviousVersionID, &state.Revision, &state.UpdatedAt)
	if err != nil {
		return State{}, fmt.Errorf("reading OTLP runtime state: %w", err)
	}
	return state, nil
}

func lockState(ctx context.Context, tx pgx.Tx) (State, error) {
	return scanState(tx.QueryRow(ctx, `SELECT mode,active_version_id,candidate_version_id,previous_version_id,revision,updated_at FROM otlp_runtime_state WHERE singleton=TRUE FOR UPDATE`))
}

func notifyTx(ctx context.Context, tx pgx.Tx, reason string, revision int64) error {
	payload := fmt.Sprintf("%s:%d", reason, revision)
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1,$2)`, NotificationChannel, payload); err != nil {
		return fmt.Errorf("notifying OTLP runtime change: %w", err)
	}
	return nil
}

func (s *Store) now() time.Time { return s.clock().UTC() }
