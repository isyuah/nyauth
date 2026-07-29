package mediaruntime

import (
	"context"
	"encoding/json"
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
	"github.com/nyasharp/nyauth/pkg/models"
)

type Store struct {
	db          *pgxpool.Pool
	activeKeyID string
	masterKeys  map[string][]byte
	now         func() time.Time
}

func NewStore(db *pgxpool.Pool, activeKeyID string, masterKeys map[string][]byte) (*Store, error) {
	key, ok := masterKeys[activeKeyID]
	if db == nil || strings.TrimSpace(activeKeyID) == "" || !ok || len(key) != 32 {
		return nil, ErrStoreUnavailable
	}
	cloned := make(map[string][]byte, len(masterKeys))
	for id, value := range masterKeys {
		if len(value) != 32 {
			return nil, fmt.Errorf("master key %q must be 32 bytes", id)
		}
		cloned[id] = append([]byte(nil), value...)
	}
	return &Store{db: db, activeKeyID: activeKeyID, masterKeys: cloned, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *Store) LoadState(ctx context.Context) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	return scanState(s.db.QueryRow(ctx, `SELECT revision,active_profile_id,candidate_profile_id,previous_profile_id,updated_by,updated_by_name,updated_at FROM media_storage_state WHERE singleton=TRUE`))
}

func (s *Store) LoadProfile(ctx context.Context, id uuid.UUID) (Profile, error) {
	stored, err := loadStoredProfile(ctx, s.db, id)
	return stored.profile, err
}

func (s *Store) LoadProfileConfig(ctx context.Context, id uuid.UUID) (ProfileConfig, error) {
	stored, err := loadStoredProfile(ctx, s.db, id)
	if err != nil {
		return ProfileConfig{}, err
	}
	credentials, err := s.decryptCredentials(stored)
	if err != nil {
		return ProfileConfig{}, fmt.Errorf("decrypting media storage credentials: %w", err)
	}
	return ProfileConfig{Profile: stored.profile, Credentials: credentials}, nil
}

func (s *Store) LoadAllProfileConfigs(ctx context.Context) ([]ProfileConfig, error) {
	rows, err := s.db.Query(ctx, `SELECT id FROM media_storage_profiles ORDER BY created_at,id`)
	if err != nil {
		return nil, fmt.Errorf("listing media storage profiles: %w", err)
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]ProfileConfig, 0, len(ids))
	for _, id := range ids {
		value, err := s.LoadProfileConfig(ctx, id)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (s *Store) CreateCandidate(ctx context.Context, input CreateCandidateInput, production bool) (Profile, State, error) {
	if err := input.Audit.ValidateEvent(models.AuditMediaSettingsSaved); err != nil {
		return Profile{}, State{}, err
	}
	settings, credentials, err := normalizeConfig(input.Settings, input.Credentials, production)
	if err != nil {
		return Profile{}, State{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Profile{}, State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return Profile{}, State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return Profile{}, State{}, ErrStateConflict
	}
	if unresolved, err := unresolvedMigrationExists(ctx, tx); err != nil {
		return Profile{}, State{}, err
	} else if unresolved {
		return Profile{}, State{}, ErrMigrationActive
	}
	id := uuid.New()
	encryptedAccess, err := s.encrypt(id, "access-key-id", credentials.AccessKeyID)
	if err != nil {
		return Profile{}, State{}, err
	}
	encryptedSecret, err := s.encrypt(id, "secret-access-key", credentials.SecretAccessKey)
	if err != nil {
		return Profile{}, State{}, err
	}
	encryptedToken := ""
	if credentials.SessionToken != "" {
		encryptedToken, err = s.encrypt(id, "session-token", credentials.SessionToken)
		if err != nil {
			return Profile{}, State{}, err
		}
	}
	now := s.now()
	profile := Profile{ID: id, Backend: "s3", Settings: settings, CredentialsConfigured: true, SessionTokenConfigured: encryptedToken != "", CreatedBy: &input.Audit.ActorID, CreatedByName: input.Audit.ActorName, CreatedAt: now}
	_, err = tx.Exec(ctx, `INSERT INTO media_storage_profiles (id,backend,endpoint,region,bucket,object_prefix,path_style,encrypted_access_key_id,encrypted_secret_access_key,encrypted_session_token,created_by,created_by_name,created_at) VALUES ($1,'s3',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, settings.Endpoint, settings.Region, settings.Bucket, settings.Prefix, settings.PathStyle, encryptedAccess, encryptedSecret, encryptedToken, input.Audit.ActorID, input.Audit.ActorName, now)
	if err != nil {
		return Profile{}, State{}, fmt.Errorf("inserting media storage profile: %w", err)
	}
	state, err = scanState(tx.QueryRow(ctx, `UPDATE media_storage_state SET candidate_profile_id=$1,revision=revision+1,updated_by=$2,updated_by_name=$3,updated_at=$4 WHERE singleton=TRUE AND revision=$5 RETURNING revision,active_profile_id,candidate_profile_id,previous_profile_id,updated_by,updated_by_name,updated_at`, id, input.Audit.ActorID, input.Audit.ActorName, now, input.ExpectedRevision))
	if err != nil {
		return Profile{}, State{}, ErrStateConflict
	}
	mutation := input.Audit.WithTarget("media_config", id.String()).WithDetails(map[string]any{"revision": state.Revision, "backend": "s3", "endpoint_configured": settings.Endpoint != "", "bucket": settings.Bucket, "prefix": settings.Prefix})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return Profile{}, State{}, err
	}
	if err := notifyTx(ctx, tx, "candidate", state.Revision); err != nil {
		return Profile{}, State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Profile{}, State{}, err
	}
	return profile, state, nil
}

func (s *Store) RecordTest(ctx context.Context, input TestCandidateInput, result, category, safeError string) (Profile, State, error) {
	if err := input.Audit.ValidateEvent(models.AuditMediaSettingsTested); err != nil {
		return Profile{}, State{}, err
	}
	if result != "success" && result != "failure" {
		return Profile{}, State{}, ErrInvalidConfig
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Profile{}, State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return Profile{}, State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return Profile{}, State{}, ErrStateConflict
	}
	if state.CandidateProfileID == nil {
		return Profile{}, State{}, ErrCandidateNotFound
	}
	if *state.CandidateProfileID != input.ProfileID {
		return Profile{}, State{}, ErrCandidateChanged
	}
	if unresolved, err := unresolvedMigrationExists(ctx, tx); err != nil {
		return Profile{}, State{}, err
	} else if unresolved {
		return Profile{}, State{}, ErrMigrationActive
	}
	now := s.now()
	_, err = tx.Exec(ctx, `UPDATE media_storage_profiles SET tested_at=$2,test_result=$3,test_error_category=$4,test_error=$5 WHERE id=$1`, input.ProfileID, now, result, nullableText(category), nullableText(safeError))
	if err != nil {
		return Profile{}, State{}, err
	}
	state, err = scanState(tx.QueryRow(ctx, `UPDATE media_storage_state SET revision=revision+1,updated_by=$1,updated_by_name=$2,updated_at=$3 WHERE singleton=TRUE RETURNING revision,active_profile_id,candidate_profile_id,previous_profile_id,updated_by,updated_by_name,updated_at`, input.Audit.ActorID, input.Audit.ActorName, now))
	if err != nil {
		return Profile{}, State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("media_config", input.ProfileID.String()).WithDetails(map[string]any{"test_result": result, "error_category": category})); err != nil {
		return Profile{}, State{}, err
	}
	if err := notifyTx(ctx, tx, "tested", state.Revision); err != nil {
		return Profile{}, State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Profile{}, State{}, err
	}
	profile, err := s.LoadProfile(ctx, input.ProfileID)
	return profile, state, err
}

func (s *Store) StartMigration(ctx context.Context, input StartMigrationInput) (Migration, State, error) {
	if err := input.Audit.ValidateEvent(models.AuditMediaMigrationStarted); err != nil {
		return Migration{}, State{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Migration{}, State{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return Migration{}, State{}, err
	}
	if state.Revision != input.ExpectedRevision {
		return Migration{}, State{}, ErrStateConflict
	}
	if state.CandidateProfileID == nil {
		return Migration{}, State{}, ErrCandidateNotFound
	}
	if *state.CandidateProfileID != input.ProfileID {
		return Migration{}, State{}, ErrCandidateChanged
	}
	var controlRevision int64
	var mediaPaused bool
	if err := tx.QueryRow(ctx, `
		SELECT state.revision,EXISTS(
			SELECT 1 FROM service_control_pauses pause
			WHERE pause.singleton=TRUE AND pause.capability='media_writes'
		)
		FROM service_control_state state WHERE state.singleton=TRUE
	`).Scan(&controlRevision, &mediaPaused); err != nil {
		return Migration{}, State{}, fmt.Errorf("checking media migration service control: %w", err)
	}
	if !mediaPaused || controlRevision != input.ServiceControlRevision {
		return Migration{}, State{}, ErrMigrationNotPaused
	}
	var unprepared int64
	if err := tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM media_storage_instances
		WHERE heartbeat_at > NOW()-INTERVAL '15 seconds'
		  AND (prepared_profile_id IS DISTINCT FROM $1 OR loaded_revision < $2)
	`, input.ProfileID, input.ExpectedRevision).Scan(&unprepared); err != nil {
		return Migration{}, State{}, fmt.Errorf("checking prepared media instances: %w", err)
	}
	if unprepared > 0 {
		return Migration{}, State{}, ErrInstancesNotReady
	}
	var testedAt time.Time
	err = tx.QueryRow(ctx, `SELECT tested_at FROM media_storage_profiles WHERE id=$1 AND test_result='success'`, input.ProfileID).Scan(&testedAt)
	if errors.Is(err, pgx.ErrNoRows) || testedAt.Before(s.now().Add(-CandidateTestValidity)) {
		return Migration{}, State{}, ErrCandidateTestRequired
	}
	if err != nil {
		return Migration{}, State{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM media_storage_migrations WHERE status<>'completed')`).Scan(&exists); err != nil {
		return Migration{}, State{}, err
	}
	if exists {
		return Migration{}, State{}, ErrMigrationActive
	}
	id, now := uuid.New(), s.now()
	previousJSON, _ := json.Marshal(input.ServiceControlPrevious)
	_, err = tx.Exec(ctx, `INSERT INTO media_storage_migrations (id,source_profile_id,source_backend,target_profile_id,status,service_control_revision,service_control_previous,created_by,created_by_name,created_at,updated_at) VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8,$9,$9)`, id, state.ActiveProfileID, input.SourceBackend, input.ProfileID, input.ServiceControlRevision, previousJSON, input.Audit.ActorID, input.Audit.ActorName, now)
	if err != nil {
		return Migration{}, State{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO media_storage_migration_items (migration_id,avatar_id,source_profile_id,source_backend,target_profile_id,status,updated_at) SELECT $1,id,storage_profile_id,storage_backend,$2,'pending',$3 FROM user_avatars WHERE storage_deleted_at IS NULL AND storage_profile_id IS NOT DISTINCT FROM $4`, id, input.ProfileID, now, state.ActiveProfileID)
	if err != nil {
		return Migration{}, State{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE media_storage_migrations SET total_count=(SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1) WHERE id=$1`, id); err != nil {
		return Migration{}, State{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("media_migration", id.String()).WithDetails(map[string]any{"source_profile_id": state.ActiveProfileID, "target_profile_id": input.ProfileID, "service_control_revision": input.ServiceControlRevision})); err != nil {
		return Migration{}, State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Migration{}, State{}, err
	}
	migration, err := s.LoadMigration(ctx, id)
	return migration, state, err
}

func (s *Store) RetryMigration(ctx context.Context, input RetryMigrationInput) (Migration, error) {
	if err := input.Audit.ValidateEvent(models.AuditMediaMigrationRetried); err != nil {
		return Migration{}, err
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Migration{}, err
	}
	defer tx.Rollback(ctx)
	state, err := lockState(ctx, tx)
	if err != nil {
		return Migration{}, err
	}
	var targetProfileID uuid.UUID
	var previousControlRevision *int64
	if err := tx.QueryRow(ctx, `SELECT target_profile_id,service_control_revision FROM media_storage_migrations WHERE id=$1 AND status='failed' FOR UPDATE`, input.MigrationID).Scan(&targetProfileID, &previousControlRevision); errors.Is(err, pgx.ErrNoRows) {
		return Migration{}, ErrMigrationNotFound
	} else if err != nil {
		return Migration{}, err
	}
	if state.CandidateProfileID == nil || *state.CandidateProfileID != targetProfileID {
		return Migration{}, ErrCandidateChanged
	}
	var controlRevision int64
	var mediaPaused bool
	if err := tx.QueryRow(ctx, `
		SELECT state.revision,EXISTS(
			SELECT 1 FROM service_control_pauses pause
			WHERE pause.singleton=TRUE AND pause.capability='media_writes'
		)
		FROM service_control_state state WHERE state.singleton=TRUE
	`).Scan(&controlRevision, &mediaPaused); err != nil {
		return Migration{}, fmt.Errorf("checking media migration retry service control: %w", err)
	}
	if !mediaPaused || controlRevision != input.ServiceControlRevision {
		return Migration{}, ErrMigrationNotPaused
	}
	previousJSON, err := json.Marshal(input.ServiceControlPrevious)
	if err != nil {
		return Migration{}, ErrInvalidConfig
	}
	now := s.now()
	tag, err := tx.Exec(ctx, `
		UPDATE media_storage_migrations SET
			status='pending',failed_count=0,failed_at=NULL,last_error=NULL,updated_at=$2,
			service_control_revision=$3,
			service_control_previous=CASE WHEN service_control_revision IS DISTINCT FROM $3 THEN $4 ELSE service_control_previous END
		WHERE id=$1 AND status='failed'
	`, input.MigrationID, now, input.ServiceControlRevision, previousJSON)
	if err != nil || tag.RowsAffected() != 1 {
		return Migration{}, ErrMigrationNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE media_storage_migration_items SET status='pending',locked_at=NULL,locked_by=NULL,last_error=NULL,updated_at=$2 WHERE migration_id=$1 AND status='failed'`, input.MigrationID, now); err != nil {
		return Migration{}, err
	}
	if err := audit.EnqueueMutationTx(ctx, tx, input.Audit.WithTarget("media_migration", input.MigrationID.String()).WithDetails(map[string]any{"service_control_revision": input.ServiceControlRevision, "service_control_changed": previousControlRevision == nil || *previousControlRevision != input.ServiceControlRevision})); err != nil {
		return Migration{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Migration{}, err
	}
	return s.LoadMigration(ctx, input.MigrationID)
}

func unresolvedMigrationExists(ctx context.Context, tx pgx.Tx) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM media_storage_migrations WHERE status<>'completed')`).Scan(&exists)
	return exists, err
}

func (s *Store) LoadMigration(ctx context.Context, id uuid.UUID) (Migration, error) {
	return scanMigration(s.db.QueryRow(ctx, migrationSelect+` WHERE id=$1`, id))
}

func (s *Store) LoadLatestMigration(ctx context.Context) (*Migration, error) {
	value, err := scanMigration(s.db.QueryRow(ctx, migrationSelect+` ORDER BY created_at DESC LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func (s *Store) LoadActiveMigration(ctx context.Context) (*Migration, error) {
	value, err := scanMigration(s.db.QueryRow(ctx, migrationSelect+` WHERE status IN ('pending','running','applying') ORDER BY created_at LIMIT 1`))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &value, nil
}

type storedProfile struct {
	profile               Profile
	access, secret, token string
}

func loadStoredProfile(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, id uuid.UUID) (storedProfile, error) {
	var value storedProfile
	err := q.QueryRow(ctx, `SELECT id,backend,endpoint,region,bucket,object_prefix,path_style,encrypted_access_key_id,encrypted_secret_access_key,encrypted_session_token,created_by,created_by_name,created_at,tested_at,test_result,test_error_category,test_error FROM media_storage_profiles WHERE id=$1`, id).Scan(&value.profile.ID, &value.profile.Backend, &value.profile.Settings.Endpoint, &value.profile.Settings.Region, &value.profile.Settings.Bucket, &value.profile.Settings.Prefix, &value.profile.Settings.PathStyle, &value.access, &value.secret, &value.token, &value.profile.CreatedBy, &value.profile.CreatedByName, &value.profile.CreatedAt, &value.profile.TestedAt, &value.profile.TestResult, &value.profile.TestErrorCategory, &value.profile.TestError)
	if errors.Is(err, pgx.ErrNoRows) {
		return value, ErrCandidateNotFound
	}
	if err != nil {
		return value, err
	}
	value.profile.CredentialsConfigured = value.access != "" && value.secret != ""
	value.profile.SessionTokenConfigured = value.token != ""
	return value, nil
}

func (s *Store) encrypt(id uuid.UUID, field, value string) (string, error) {
	return internalcrypto.EncryptEnvelope(s.masterKeys[s.activeKeyID], s.activeKeyID, CredentialPurpose, []byte(value), []byte(id.String()+":"+field))
}
func (s *Store) decryptCredentials(value storedProfile) (Credentials, error) {
	decrypt := func(field, ciphertext string) (string, error) {
		if ciphertext == "" {
			return "", nil
		}
		raw, err := internalcrypto.DecryptEnvelope(s.masterKeys, CredentialPurpose, ciphertext, []byte(value.profile.ID.String()+":"+field))
		return string(raw), err
	}
	access, err := decrypt("access-key-id", value.access)
	if err != nil {
		return Credentials{}, err
	}
	secret, err := decrypt("secret-access-key", value.secret)
	if err != nil {
		return Credentials{}, err
	}
	token, err := decrypt("session-token", value.token)
	return Credentials{AccessKeyID: access, SecretAccessKey: secret, SessionToken: token}, err
}

func normalizeConfig(settings ProfileSettings, credentials Credentials, production bool) (ProfileSettings, Credentials, error) {
	settings.Endpoint = strings.TrimSpace(settings.Endpoint)
	settings.Region = strings.TrimSpace(settings.Region)
	settings.Bucket = strings.TrimSpace(settings.Bucket)
	settings.Prefix = strings.Trim(strings.TrimSpace(strings.ReplaceAll(settings.Prefix, "\\", "/")), "/")
	credentials.AccessKeyID = strings.TrimSpace(credentials.AccessKeyID)
	credentials.SecretAccessKey = strings.TrimSpace(credentials.SecretAccessKey)
	credentials.SessionToken = strings.TrimSpace(credentials.SessionToken)
	if settings.Region == "" || settings.Bucket == "" || credentials.AccessKeyID == "" || credentials.SecretAccessKey == "" || len(settings.Region) > 128 || len(settings.Bucket) > 255 || len(settings.Prefix) > 512 || len(credentials.AccessKeyID) > 4096 || len(credentials.SecretAccessKey) > 4096 || len(credentials.SessionToken) > 8192 || strings.Contains(settings.Bucket, "/") || strings.Contains(settings.Prefix, "..") {
		return settings, credentials, ErrInvalidConfig
	}
	if strings.ContainsAny(credentials.AccessKeyID+credentials.SecretAccessKey+credentials.SessionToken, "\r\n") {
		return settings, credentials, ErrInvalidConfig
	}
	if settings.Endpoint != "" {
		parsed, err := url.Parse(settings.Endpoint)
		if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || (production && parsed.Scheme != "https") {
			return settings, credentials, ErrInvalidConfig
		}
	}
	return settings, credentials, nil
}

func lockState(ctx context.Context, tx pgx.Tx) (State, error) {
	return scanState(tx.QueryRow(ctx, `SELECT revision,active_profile_id,candidate_profile_id,previous_profile_id,updated_by,updated_by_name,updated_at FROM media_storage_state WHERE singleton=TRUE FOR UPDATE`))
}
func scanState(row pgx.Row) (State, error) {
	var v State
	err := row.Scan(&v.Revision, &v.ActiveProfileID, &v.CandidateProfileID, &v.PreviousProfileID, &v.UpdatedBy, &v.UpdatedByName, &v.UpdatedAt)
	return v, err
}

const migrationSelect = `SELECT id,source_profile_id,source_backend,target_profile_id,status,total_count,copied_count,completed_count,failed_count,service_control_revision,service_control_previous,created_by,created_by_name,created_at,started_at,completed_at,failed_at,last_error,updated_at FROM media_storage_migrations`

func scanMigration(row pgx.Row) (Migration, error) {
	var v Migration
	var previous []byte
	err := row.Scan(&v.ID, &v.SourceProfileID, &v.SourceBackend, &v.TargetProfileID, &v.Status, &v.TotalCount, &v.CopiedCount, &v.CompletedCount, &v.FailedCount, &v.ServiceControlRevision, &previous, &v.CreatedBy, &v.CreatedByName, &v.CreatedAt, &v.StartedAt, &v.CompletedAt, &v.FailedAt, &v.LastError, &v.UpdatedAt)
	if err == nil && len(previous) > 0 {
		_ = json.Unmarshal(previous, &v.ServiceControlPrevious)
	}
	return v, err
}
func notifyTx(ctx context.Context, tx pgx.Tx, kind string, revision int64) error {
	payload := fmt.Sprintf("%s:%d", kind, revision)
	_, err := tx.Exec(ctx, `SELECT pg_notify($1,$2)`, NotificationChannel, payload)
	return err
}
func nullableText(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
