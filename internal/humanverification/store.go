package humanverification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
)

type StoreOptions struct {
	ActiveKeyID string
	MasterKeys  map[string][]byte
	Clock       func() time.Time
}

type Store struct {
	db          *pgxpool.Pool
	activeKeyID string
	masterKeys  map[string][]byte
	clock       func() time.Time
}

type rowQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type storedVersion struct {
	version          Version
	secretCiphertext string
}

func NewStore(db *pgxpool.Pool, options StoreOptions) (*Store, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	options.ActiveKeyID = strings.TrimSpace(options.ActiveKeyID)
	activeKey, ok := options.MasterKeys[options.ActiveKeyID]
	if options.ActiveKeyID == "" || !ok || len(activeKey) != 32 {
		return nil, fmt.Errorf("%w: active 32-byte envelope key is required", ErrInvalidConfig)
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for id, key := range options.MasterKeys {
		if strings.TrimSpace(id) == "" || len(key) != 32 {
			return nil, fmt.Errorf("%w: every envelope key must have an ID and contain 32 bytes", ErrInvalidConfig)
		}
		keys[id] = append([]byte(nil), key...)
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
	return scanState(s.db.QueryRow(ctx, `
		SELECT mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		FROM human_verification_runtime_state WHERE singleton=TRUE
	`))
}

func (s *Store) LoadVersion(ctx context.Context, id uuid.UUID) (Version, error) {
	stored, err := s.loadStoredVersion(ctx, s.db, id)
	return stored.version, err
}

func (s *Store) LoadLatestTest(ctx context.Context, versionID uuid.UUID) (*TestRecord, error) {
	if versionID == uuid.Nil {
		return nil, ErrVersionNotFound
	}
	var record TestRecord
	err := s.db.QueryRow(ctx, `
		SELECT id,version_id,result,error_code,tested_by,created_at
		FROM human_verification_config_tests
		WHERE version_id=$1 ORDER BY created_at DESC LIMIT 1
	`, versionID).Scan(&record.ID, &record.VersionID, &record.Result, &record.ErrorCode, &record.TestedBy, &record.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &record, nil
}

func (s *Store) LoadVersionConfig(ctx context.Context, id uuid.UUID) (Version, Config, error) {
	stored, err := s.loadStoredVersion(ctx, s.db, id)
	if err != nil {
		return Version{}, Config{}, err
	}
	secret, err := s.decryptSecret(stored)
	if err != nil {
		return Version{}, Config{}, fmt.Errorf("decrypting human verification configuration: %w", err)
	}
	return stored.version, Config{Settings: stored.version.Settings, Secret: secret}, nil
}

func (s *Store) LoadEffectiveConfig(ctx context.Context) (EffectiveConfig, error) {
	state, err := s.LoadState(ctx)
	if err != nil {
		return EffectiveConfig{}, err
	}
	effective := EffectiveConfig{State: state}
	if state.Mode != ModeActive && state.Mode != ModeDisabled {
		return effective, fmt.Errorf("%w: runtime mode is inconsistent", ErrInvalidConfig)
	}
	if state.ActiveVersionID == nil {
		if state.Mode == ModeDisabled {
			return effective, nil
		}
		return effective, fmt.Errorf("%w: active state is inconsistent", ErrInvalidConfig)
	}
	version, config, err := s.LoadVersionConfig(ctx, *state.ActiveVersionID)
	effective.Configured = true
	if err != nil {
		return effective, err
	}
	effective.Available = true
	effective.Version = &version
	effective.Config = &config
	return effective, nil
}

func (s *Store) CreateCandidate(ctx context.Context, input CreateCandidateInput) (CandidateResult, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsSaved); err != nil {
		return CandidateResult{}, err
	}
	settings, err := NormalizeSettings(input.Settings)
	if err != nil {
		return CandidateResult{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("starting human verification candidate transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return CandidateResult{}, err
	}
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return CandidateResult{}, err
	}
	secret, err := s.resolveCandidateSecret(ctx, tx, state, input.Secret)
	if err != nil {
		return CandidateResult{}, err
	}
	versionID := uuid.New()
	ciphertext, err := internalcrypto.EncryptEnvelope(
		s.masterKeys[s.activeKeyID], s.activeKeyID, SecretEnvelopePurpose,
		[]byte(secret), []byte(versionID.String()),
	)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("encrypting human verification secret: %w", err)
	}
	createdAt := s.now()
	version := Version{ID: versionID, Settings: settings, SecretConfigured: true, CreatedAt: createdAt}
	createdBy := input.Audit.ActorID
	version.CreatedBy = &createdBy
	err = tx.QueryRow(ctx, `
		INSERT INTO human_verification_config_versions (
			id,provider,site_key,secret_ciphertext,widget_mode,created_by,created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING revision,created_at
	`, versionID, settings.Provider, settings.SiteKey, ciphertext, settings.WidgetMode, createdBy, createdAt).Scan(&version.Revision, &version.CreatedAt)
	if err != nil {
		return CandidateResult{}, fmt.Errorf("inserting human verification candidate: %w", err)
	}
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE human_verification_runtime_state
		SET candidate_version_id=$1,revision=revision+1,updated_at=$2
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
	`, versionID, createdAt))
	if err != nil {
		return CandidateResult{}, fmt.Errorf("publishing human verification candidate: %w", err)
	}
	mutation := input.Audit.WithTarget("human_verification_config", versionID.String()).WithDetails(map[string]any{
		"provider": settings.Provider, "widget_mode": settings.WidgetMode, "version_revision": version.Revision,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return CandidateResult{}, fmt.Errorf("auditing human verification candidate: %w", err)
	}
	if err := notifyTx(ctx, tx, state.Revision); err != nil {
		return CandidateResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return CandidateResult{}, fmt.Errorf("committing human verification candidate: %w", err)
	}
	return CandidateResult{Version: version, State: state}, nil
}

func (s *Store) RecordTest(ctx context.Context, input RecordTestInput) (TestResult, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsTested); err != nil {
		return TestResult{}, err
	}
	if input.Result != TestSuccess && input.Result != TestFailure {
		return TestResult{}, fmt.Errorf("%w: invalid test result", ErrInvalidConfig)
	}
	if (input.Result == TestSuccess) != (input.ErrorCode == nil) {
		return TestResult{}, fmt.Errorf("%w: inconsistent test result", ErrInvalidConfig)
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
	if err := requireRevision(state, input.ExpectedRevision); err != nil {
		return TestResult{}, err
	}
	if state.CandidateVersionID == nil || *state.CandidateVersionID != input.VersionID {
		return TestResult{}, ErrCandidateNotFound
	}
	now := s.now()
	record := TestRecord{ID: uuid.New(), VersionID: input.VersionID, Result: input.Result, ErrorCode: input.ErrorCode, CreatedAt: now}
	testedBy := input.Audit.ActorID
	record.TestedBy = &testedBy
	err = tx.QueryRow(ctx, `
		INSERT INTO human_verification_config_tests (id,version_id,result,error_code,tested_by,created_at)
		VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at
	`, record.ID, record.VersionID, record.Result, record.ErrorCode, testedBy, now).Scan(&record.CreatedAt)
	if err != nil {
		return TestResult{}, fmt.Errorf("recording human verification test: %w", err)
	}
	state, err = bumpState(ctx, tx, now)
	if err != nil {
		return TestResult{}, err
	}
	mutation := input.Audit.WithTarget("human_verification_config", input.VersionID.String()).WithDetails(map[string]any{
		"result": input.Result, "error_code": input.ErrorCode,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return TestResult{}, err
	}
	if err := notifyTx(ctx, tx, state.Revision); err != nil {
		return TestResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TestResult{}, err
	}
	return TestResult{Record: record, State: state}, nil
}

func (s *Store) Activate(ctx context.Context, input ActivateInput) (State, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsActivated); err != nil {
		return State{}, err
	}
	policy, err := NormalizePolicy(input.Policy)
	if err != nil {
		return State{}, err
	}
	return s.mutateState(ctx, input.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, state State, now time.Time) (State, audit.MutationAudit, error) {
		if state.CandidateVersionID == nil || *state.CandidateVersionID != input.VersionID {
			return State{}, audit.MutationAudit{}, ErrCandidateNotFound
		}
		var testedAt time.Time
		err := tx.QueryRow(ctx, `
			SELECT created_at FROM human_verification_config_tests
			WHERE version_id=$1 AND result='success'
			ORDER BY created_at DESC LIMIT 1
		`, input.VersionID).Scan(&testedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return State{}, audit.MutationAudit{}, ErrCandidateTestRequired
		}
		if err != nil {
			return State{}, audit.MutationAudit{}, err
		}
		if testedAt.Before(now.Add(-CandidateTestValidity)) {
			return State{}, audit.MutationAudit{}, ErrCandidateTestExpired
		}
		previous := state.PreviousVersionID
		if state.ActiveVersionID != nil {
			previous = state.ActiveVersionID
		}
		encodedPolicy, _ := json.Marshal(policy)
		next, err := scanState(tx.QueryRow(ctx, `
			UPDATE human_verification_runtime_state
			SET mode='active',active_version_id=$1,candidate_version_id=NULL,previous_version_id=$2,
			    policy=$3,revision=revision+1,updated_at=$4
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		`, input.VersionID, previous, encodedPolicy, now))
		mutation := input.Audit.WithTarget("human_verification_runtime", "singleton").WithDetails(map[string]any{
			"provider_version_id": input.VersionID.String(), "policy": policy,
		})
		return next, mutation, err
	})
}

func (s *Store) UpdatePolicy(ctx context.Context, input PolicyMutationInput) (State, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsUpdated); err != nil {
		return State{}, err
	}
	policy, err := NormalizePolicy(input.Policy)
	if err != nil {
		return State{}, err
	}
	return s.mutateState(ctx, input.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, _ State, now time.Time) (State, audit.MutationAudit, error) {
		encoded, _ := json.Marshal(policy)
		next, err := scanState(tx.QueryRow(ctx, `
			UPDATE human_verification_runtime_state SET policy=$1,revision=revision+1,updated_at=$2
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		`, encoded, now))
		return next, input.Audit.WithTarget("human_verification_runtime", "singleton").WithDetails(map[string]any{"policy": policy}), err
	})
}

func (s *Store) Rollback(ctx context.Context, input StateMutationInput) (State, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsRolledBack); err != nil {
		return State{}, err
	}
	return s.mutateState(ctx, input.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, state State, now time.Time) (State, audit.MutationAudit, error) {
		if state.PreviousVersionID == nil {
			return State{}, audit.MutationAudit{}, ErrNoPreviousVersion
		}
		next, err := scanState(tx.QueryRow(ctx, `
			UPDATE human_verification_runtime_state
			SET mode='active',active_version_id=$1,previous_version_id=$2,revision=revision+1,updated_at=$3
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		`, state.PreviousVersionID, state.ActiveVersionID, now))
		return next, input.Audit.WithTarget("human_verification_runtime", "singleton").WithDetails(map[string]any{"active_version_id": state.PreviousVersionID.String()}), err
	})
}

func (s *Store) Disable(ctx context.Context, input StateMutationInput) (State, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsDisabled); err != nil {
		return State{}, err
	}
	return s.mutateState(ctx, input.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, state State, now time.Time) (State, audit.MutationAudit, error) {
		if state.Mode == ModeDisabled {
			return State{}, audit.MutationAudit{}, ErrAlreadyDisabled
		}
		next, err := scanState(tx.QueryRow(ctx, `
			UPDATE human_verification_runtime_state
			SET mode='disabled',revision=revision+1,updated_at=$1
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		`, now))
		return next, input.Audit.WithTarget("human_verification_runtime", "singleton"), err
	})
}

func (s *Store) Enable(ctx context.Context, input StateMutationInput) (State, error) {
	if err := input.Audit.ValidateEvent(AuditSettingsEnabled); err != nil {
		return State{}, err
	}
	return s.mutateState(ctx, input.ExpectedRevision, func(ctx context.Context, tx pgx.Tx, state State, now time.Time) (State, audit.MutationAudit, error) {
		if state.Mode == ModeActive {
			return State{}, audit.MutationAudit{}, ErrAlreadyEnabled
		}
		if state.ActiveVersionID == nil {
			return State{}, audit.MutationAudit{}, ErrNoActiveVersion
		}
		next, err := scanState(tx.QueryRow(ctx, `
			UPDATE human_verification_runtime_state
			SET mode='active',revision=revision+1,updated_at=$1
			WHERE singleton=TRUE
			RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		`, now))
		mutation := input.Audit.WithTarget("human_verification_runtime", "singleton").WithDetails(map[string]any{
			"active_version_id": state.ActiveVersionID.String(),
		})
		return next, mutation, err
	})
}

func DisableForRecovery(ctx context.Context, db *pgxpool.Pool, reason string, now time.Time) (RecoveryDisableReport, error) {
	var err error
	reason, err = NormalizeRecoveryReason(reason)
	if err != nil {
		return RecoveryDisableReport{}, err
	}
	if db == nil {
		return RecoveryDisableReport{}, ErrStoreUnavailable
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return RecoveryDisableReport{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return RecoveryDisableReport{}, err
	}
	if state.Mode == ModeDisabled {
		return RecoveryDisableReport{State: state, Changed: false}, nil
	}
	now = now.UTC()
	state, err = scanState(tx.QueryRow(ctx, `
		UPDATE human_verification_runtime_state
		SET mode='disabled',revision=revision+1,updated_at=$1
		WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
	`, now))
	if err != nil {
		return RecoveryDisableReport{}, err
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, AuditCLIDisabled, nil, "nyauth human-verification CLI",
		"human_verification_runtime", "singleton", "success", "critical", "", "",
		map[string]any{"reason": reason, "revision": state.Revision}, now,
	); err != nil {
		return RecoveryDisableReport{}, fmt.Errorf("auditing emergency human verification disable: %w", err)
	}
	if err := notifyTx(ctx, tx, state.Revision); err != nil {
		return RecoveryDisableReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RecoveryDisableReport{}, err
	}
	return RecoveryDisableReport{State: state, Changed: true}, nil
}

type stateMutation func(context.Context, pgx.Tx, State, time.Time) (State, audit.MutationAudit, error)

func (s *Store) mutateState(ctx context.Context, expectedRevision int64, mutate stateMutation) (State, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return State{}, err
	}
	if err := requireRevision(state, expectedRevision); err != nil {
		return State{}, err
	}
	next, mutation, err := mutate(ctx, tx, state, s.now())
	if err != nil {
		return State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return State{}, err
	}
	if err := notifyTx(ctx, tx, next.Revision); err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, err
	}
	return next, nil
}

func (s *Store) resolveCandidateSecret(ctx context.Context, query rowQueryer, state State, provided *string) (string, error) {
	if provided != nil {
		secret := strings.TrimSpace(*provided)
		if err := ValidateSecret(secret); err != nil {
			return "", err
		}
		return secret, nil
	}
	inheritFrom := state.CandidateVersionID
	if inheritFrom == nil {
		inheritFrom = state.ActiveVersionID
	}
	if inheritFrom == nil {
		inheritFrom = state.PreviousVersionID
	}
	if inheritFrom == nil {
		return "", ErrSecretInheritance
	}
	stored, err := s.loadStoredVersion(ctx, query, *inheritFrom)
	if err != nil {
		return "", err
	}
	return s.decryptSecret(stored)
}

func (s *Store) loadStoredVersion(ctx context.Context, query rowQueryer, id uuid.UUID) (storedVersion, error) {
	if id == uuid.Nil {
		return storedVersion{}, ErrVersionNotFound
	}
	var stored storedVersion
	stored.version.ID = id
	err := query.QueryRow(ctx, `
		SELECT revision,provider,site_key,secret_ciphertext,widget_mode,created_by,created_at
		FROM human_verification_config_versions WHERE id=$1
	`, id).Scan(&stored.version.Revision, &stored.version.Provider, &stored.version.SiteKey,
		&stored.secretCiphertext, &stored.version.WidgetMode, &stored.version.CreatedBy, &stored.version.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return storedVersion{}, ErrVersionNotFound
	}
	if err != nil {
		return storedVersion{}, err
	}
	stored.version.SecretConfigured = stored.secretCiphertext != ""
	return stored, nil
}

func (s *Store) decryptSecret(stored storedVersion) (string, error) {
	plaintext, err := internalcrypto.DecryptEnvelope(
		s.masterKeys, SecretEnvelopePurpose, stored.secretCiphertext, []byte(stored.version.ID.String()),
	)
	if err != nil {
		return "", err
	}
	secret := string(plaintext)
	if err := ValidateSecret(secret); err != nil {
		return "", err
	}
	return secret, nil
}

func scanState(row pgx.Row) (State, error) {
	var state State
	var encoded []byte
	err := row.Scan(&state.Mode, &state.ActiveVersionID, &state.CandidateVersionID, &state.PreviousVersionID, &encoded, &state.Revision, &state.UpdatedAt)
	if err != nil {
		return State{}, fmt.Errorf("loading human verification state: %w", err)
	}
	state.Policy = DefaultPolicy()
	if err := json.Unmarshal(encoded, &state.Policy); err != nil {
		return State{}, fmt.Errorf("decoding human verification policy: %w", err)
	}
	policy, err := NormalizePolicy(state.Policy)
	if err != nil {
		return State{}, err
	}
	state.Policy = policy
	return state, nil
}

func lockState(ctx context.Context, tx pgx.Tx) (State, error) {
	return scanState(tx.QueryRow(ctx, `
		SELECT mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
		FROM human_verification_runtime_state WHERE singleton=TRUE FOR UPDATE
	`))
}

func requireRevision(state State, expected int64) error {
	if expected < 1 || state.Revision != expected {
		return ErrStateConflict
	}
	return nil
}

func bumpState(ctx context.Context, tx pgx.Tx, now time.Time) (State, error) {
	return scanState(tx.QueryRow(ctx, `
		UPDATE human_verification_runtime_state SET revision=revision+1,updated_at=$1 WHERE singleton=TRUE
		RETURNING mode,active_version_id,candidate_version_id,previous_version_id,policy,revision,updated_at
	`, now))
}

func notifyTx(ctx context.Context, tx pgx.Tx, revision int64) error {
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1,$2)`, NotificationChannel, fmt.Sprintf("%d", revision)); err != nil {
		return fmt.Errorf("notifying human verification change: %w", err)
	}
	return nil
}

func (s *Store) now() time.Time { return s.clock().UTC() }
