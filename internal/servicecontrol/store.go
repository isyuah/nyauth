package servicecontrol

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
)

const expirationAdvisoryLockKey int64 = 5645628061713812556

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) (*Store, error) {
	if db == nil {
		return nil, ErrStoreUnavailable
	}
	return &Store{db: db}, nil
}

func (s *Store) LoadSnapshot(ctx context.Context) (Snapshot, error) {
	if s == nil || s.db == nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	snapshot, err := loadSnapshot(ctx, s.db)
	if err != nil {
		return Snapshot{}, fmt.Errorf("loading service control state: %w", err)
	}
	return snapshot, nil
}

func (s *Store) LoadState(ctx context.Context, staleAfter time.Duration) (State, error) {
	if s == nil || s.db == nil {
		return State{}, ErrStoreUnavailable
	}
	if staleAfter <= 0 {
		return State{}, fmt.Errorf("%w: stale interval must be positive", ErrInvalidState)
	}
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return State{}, fmt.Errorf("starting service control state read: %w", err)
	}
	defer tx.Rollback(ctx)
	snapshot, err := loadSnapshot(ctx, tx)
	if err != nil {
		return State{}, fmt.Errorf("loading service control state: %w", err)
	}
	instances, err := listActiveInstances(ctx, tx, staleAfter)
	if err != nil {
		return State{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return State{}, fmt.Errorf("committing service control state read: %w", err)
	}
	status := applicationStatus(snapshot.Revision, instances)
	return State{
		Snapshot: snapshot, Instances: status.Instances,
		ActiveInstances: status.ActiveInstances, AppliedInstances: status.AppliedInstances,
		Applied: status.Applied,
	}, nil
}

func (s *Store) Update(ctx context.Context, input UpdateInput) (Snapshot, error) {
	if s == nil || s.db == nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	input = normalizeUpdateInput(input)
	capabilities, err := validateUpdateInput(input)
	if err != nil {
		return Snapshot{}, err
	}
	if err := input.Audit.ValidateEvent(AuditUpdated); err != nil {
		return Snapshot{}, fmt.Errorf("validating service control audit: %w", err)
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("starting service control update: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return Snapshot{}, err
	}

	current, databaseNow, err := lockSnapshot(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	if current.Revision != input.ExpectedRevision {
		return Snapshot{}, revisionConflict(input.ExpectedRevision, current.Revision)
	}
	if err := validateExpiration(input.ExpiresAt, databaseNow); err != nil {
		return Snapshot{}, err
	}
	if err := validateTargetAgainstRegistration(ctx, tx, capabilities); err != nil {
		return Snapshot{}, err
	}

	updatedAt := databaseNow.UTC()
	var expiresAt *time.Time
	if input.ExpiresAt != nil {
		expires := input.ExpiresAt.UTC()
		expiresAt = &expires
	}
	result, err := tx.Exec(ctx, `
		UPDATE service_control_state SET
			revision=revision+1, public_message=$1, internal_reason=$2,
			expires_at=$3, updated_by=$4, updated_by_name=$5, updated_at=$6
		WHERE singleton=TRUE AND revision=$7
	`, input.PublicMessage, input.InternalReason, expiresAt, input.UpdatedBy,
		input.UpdatedByName, updatedAt, input.ExpectedRevision)
	if err != nil {
		return Snapshot{}, fmt.Errorf("updating service control state: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Snapshot{}, revisionConflict(input.ExpectedRevision, current.Revision)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM service_control_pauses WHERE singleton=TRUE`); err != nil {
		return Snapshot{}, fmt.Errorf("clearing service control capabilities: %w", err)
	}
	if err := insertCapabilities(ctx, tx, capabilities); err != nil {
		return Snapshot{}, err
	}

	nextRevision := input.ExpectedRevision + 1
	mutation := input.Audit.WithTarget("settings", "operations").WithDetails(map[string]any{
		"previous_revision":   current.Revision,
		"revision":            nextRevision,
		"paused_capabilities": capabilities,
		"public_message":      input.PublicMessage,
		"internal_reason":     input.InternalReason,
		"expires_at":          expiresAt,
	})
	if err := audit.EnqueueMutationTx(ctx, tx, mutation); err != nil {
		return Snapshot{}, fmt.Errorf("auditing service control update: %w", err)
	}
	if err := notifyTx(ctx, tx, nextRevision); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Snapshot{}, fmt.Errorf("committing service control update: %w", err)
	}
	updatedBy := input.UpdatedBy
	updatedByName := input.UpdatedByName
	return Snapshot{
		Revision: nextRevision, PausedCapabilities: capabilities,
		PublicMessage: input.PublicMessage, InternalReason: input.InternalReason,
		ExpiresAt: expiresAt, UpdatedBy: &updatedBy, UpdatedByName: &updatedByName,
		UpdatedAt: updatedAt, DatabaseNow: databaseNow, ObservedAt: time.Now().UTC(),
	}, nil
}

// Reset is the CLI break-glass mutation. It deliberately has no user actor,
// but records a durable system audit event containing the mandatory reason.
func (s *Store) Reset(ctx context.Context, input ResetInput) (Snapshot, error) {
	if s == nil || s.db == nil {
		return Snapshot{}, ErrStoreUnavailable
	}
	input.Reason = strings.TrimSpace(input.Reason)
	input.ActorName = strings.TrimSpace(input.ActorName)
	if err := validateText(input.Reason, 3, 500, "reset reason"); err != nil {
		return Snapshot{}, err
	}
	if input.ActorName == "" {
		input.ActorName = "nyauth service-control CLI"
	}
	if err := validateText(input.ActorName, 1, 255, "reset actor name"); err != nil {
		return Snapshot{}, err
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("starting service control reset: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return Snapshot{}, err
	}
	current, databaseNow, err := lockSnapshot(ctx, tx)
	if err != nil {
		return Snapshot{}, err
	}
	if err := validateTargetAgainstRegistration(ctx, tx, nil); err != nil {
		return Snapshot{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM service_control_pauses WHERE singleton=TRUE`); err != nil {
		return Snapshot{}, fmt.Errorf("clearing service control capabilities: %w", err)
	}
	nextRevision := current.Revision + 1
	if _, err := tx.Exec(ctx, `
		UPDATE service_control_state SET revision=$1,public_message='',internal_reason='',
			expires_at=NULL,updated_by=NULL,updated_by_name=$2,updated_at=$3
		WHERE singleton=TRUE AND revision=$4
	`, nextRevision, input.ActorName, databaseNow, current.Revision); err != nil {
		return Snapshot{}, fmt.Errorf("resetting service control state: %w", err)
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, AuditCLIReset, nil, input.ActorName, "settings", "operations",
		"success", "critical", "", "", map[string]any{
			"reason": input.Reason, "previous_revision": current.Revision,
			"revision": nextRevision, "previous_paused_capabilities": current.PausedCapabilities,
		}, databaseNow,
	); err != nil {
		return Snapshot{}, fmt.Errorf("auditing service control reset: %w", err)
	}
	if err := notifyTx(ctx, tx, nextRevision); err != nil {
		return Snapshot{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Snapshot{}, fmt.Errorf("committing service control reset: %w", err)
	}
	actorName := input.ActorName
	return Snapshot{
		Revision: nextRevision, PausedCapabilities: []Capability{},
		UpdatedByName: &actorName, UpdatedAt: databaseNow.UTC(),
		DatabaseNow: databaseNow.UTC(), ObservedAt: time.Now().UTC(),
	}, nil
}

// TryExpire elects one transaction as expiration leader. The state revision
// and expiry timestamp are compared again in the UPDATE so exactly one audit
// event can commit even if leadership changes between rounds.
func (s *Store) TryExpire(ctx context.Context) (ExpireResult, error) {
	if s == nil || s.db == nil {
		return ExpireResult{}, ErrStoreUnavailable
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return ExpireResult{}, fmt.Errorf("starting service control expiration: %w", err)
	}
	defer tx.Rollback(ctx)
	if err := runtimecoord.LockRegistrationExclusive(ctx, tx); err != nil {
		return ExpireResult{}, err
	}
	var leader bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, expirationAdvisoryLockKey).Scan(&leader); err != nil {
		return ExpireResult{}, fmt.Errorf("electing service control expiration leader: %w", err)
	}
	if !leader {
		return ExpireResult{Leader: false}, nil
	}
	current, databaseNow, err := lockSnapshot(ctx, tx)
	if err != nil {
		return ExpireResult{}, err
	}
	if current.ExpiresAt == nil || databaseNow.Before(*current.ExpiresAt) {
		if err := tx.Commit(ctx); err != nil {
			return ExpireResult{}, fmt.Errorf("committing service control expiration check: %w", err)
		}
		return ExpireResult{Leader: true, State: current}, nil
	}
	if err := validateTargetAgainstRegistration(ctx, tx, nil); err != nil {
		return ExpireResult{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM service_control_pauses WHERE singleton=TRUE`); err != nil {
		return ExpireResult{}, fmt.Errorf("clearing expired service control capabilities: %w", err)
	}
	nextRevision := current.Revision + 1
	result, err := tx.Exec(ctx, `
		UPDATE service_control_state SET revision=$1,public_message='',internal_reason='',
			expires_at=NULL,updated_by=NULL,updated_by_name='automatic expiration',updated_at=$2
		WHERE singleton=TRUE AND revision=$3 AND expires_at IS NOT DISTINCT FROM $4
	`, nextRevision, databaseNow, current.Revision, current.ExpiresAt)
	if err != nil {
		return ExpireResult{}, fmt.Errorf("expiring service control state: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ExpireResult{}, revisionConflict(current.Revision, current.Revision+1)
	}
	if err := audit.EnqueueTargetResultTx(
		ctx, tx, AuditExpired, nil, "service-control scheduler", "settings", "operations",
		"success", "high", "", "", map[string]any{
			"previous_revision": current.Revision, "revision": nextRevision,
			"previous_paused_capabilities": current.PausedCapabilities,
		}, databaseNow,
	); err != nil {
		return ExpireResult{}, fmt.Errorf("auditing service control expiration: %w", err)
	}
	if err := notifyTx(ctx, tx, nextRevision); err != nil {
		return ExpireResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ExpireResult{}, fmt.Errorf("committing service control expiration: %w", err)
	}
	actorName := "automatic expiration"
	return ExpireResult{Leader: true, Expired: true, State: Snapshot{
		Revision: nextRevision, PausedCapabilities: []Capability{},
		UpdatedByName: &actorName, UpdatedAt: databaseNow.UTC(),
		DatabaseNow: databaseNow.UTC(), ObservedAt: time.Now().UTC(),
	}}, nil
}

func (s *Store) RegisterInstance(ctx context.Context, input RegisterInstanceInput) (time.Time, error) {
	if s == nil || s.db == nil {
		return time.Time{}, ErrStoreUnavailable
	}
	input.Version = strings.TrimSpace(input.Version)
	if input.ID == uuid.Nil || input.StartedAt.IsZero() || input.Version == "" || len(input.Version) > 128 ||
		input.LoadedRevision < 1 || input.AppliedRevision < 1 || input.AppliedRevision > input.LoadedRevision {
		return time.Time{}, fmt.Errorf("%w: invalid instance registration", ErrInvalidState)
	}
	var heartbeatAt time.Time
	err := s.db.QueryRow(ctx, `
		INSERT INTO service_control_instances (
			instance_id,version,started_at,heartbeat_at,loaded_revision,applied_revision
		) VALUES ($1,$2,$3,now(),$4,$5)
		ON CONFLICT (instance_id) DO UPDATE SET
			version=EXCLUDED.version,started_at=EXCLUDED.started_at,heartbeat_at=now(),
			loaded_revision=EXCLUDED.loaded_revision,applied_revision=EXCLUDED.applied_revision
		RETURNING heartbeat_at
	`, input.ID, input.Version, input.StartedAt.UTC(), input.LoadedRevision, input.AppliedRevision).Scan(&heartbeatAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("registering service control instance: %w", err)
	}
	return heartbeatAt.UTC(), nil
}

func (s *Store) Heartbeat(ctx context.Context, input HeartbeatInput) (time.Time, error) {
	if s == nil || s.db == nil {
		return time.Time{}, ErrStoreUnavailable
	}
	if input.ID == uuid.Nil || input.LoadedRevision < 1 || input.AppliedRevision < 1 || input.AppliedRevision > input.LoadedRevision {
		return time.Time{}, fmt.Errorf("%w: invalid instance heartbeat", ErrInvalidState)
	}
	var heartbeatAt time.Time
	err := s.db.QueryRow(ctx, `
		UPDATE service_control_instances SET
			heartbeat_at=now(),loaded_revision=$2,applied_revision=$3
		WHERE instance_id=$1
		RETURNING heartbeat_at
	`, input.ID, input.LoadedRevision, input.AppliedRevision).Scan(&heartbeatAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrInstanceNotFound
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("updating service control instance heartbeat: %w", err)
	}
	return heartbeatAt.UTC(), nil
}

// ConfirmApplied advances an instance's applied revision after its local
// gates drain. It is idempotent and never lowers a newer confirmation.
func (s *Store) ConfirmApplied(ctx context.Context, id uuid.UUID, revision int64) (time.Time, error) {
	if s == nil || s.db == nil {
		return time.Time{}, ErrStoreUnavailable
	}
	if id == uuid.Nil || revision < 1 {
		return time.Time{}, fmt.Errorf("%w: invalid instance confirmation", ErrInvalidState)
	}
	var heartbeatAt time.Time
	err := s.db.QueryRow(ctx, `
		UPDATE service_control_instances SET
			heartbeat_at=now(),applied_revision=GREATEST(applied_revision,$2)
		WHERE instance_id=$1 AND loaded_revision >= $2
		RETURNING heartbeat_at
	`, id, revision).Scan(&heartbeatAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if existsErr := s.db.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM service_control_instances WHERE instance_id=$1)
		`, id).Scan(&exists); existsErr != nil {
			return time.Time{}, fmt.Errorf("checking service control instance confirmation: %w", existsErr)
		}
		if !exists {
			return time.Time{}, ErrInstanceNotFound
		}
		return time.Time{}, fmt.Errorf("%w: instance has not loaded revision %d", ErrInvalidState, revision)
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("confirming service control instance revision: %w", err)
	}
	return heartbeatAt.UTC(), nil
}

func (s *Store) UnregisterInstance(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.db == nil {
		return ErrStoreUnavailable
	}
	if id == uuid.Nil {
		return fmt.Errorf("%w: instance ID is required", ErrInvalidState)
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM service_control_instances WHERE instance_id=$1`, id); err != nil {
		return fmt.Errorf("unregistering service control instance: %w", err)
	}
	return nil
}

func (s *Store) ApplicationStatus(ctx context.Context, revision int64, staleAfter time.Duration) (ApplicationStatus, error) {
	if s == nil || s.db == nil {
		return ApplicationStatus{}, ErrStoreUnavailable
	}
	if revision < 1 || staleAfter <= 0 {
		return ApplicationStatus{}, fmt.Errorf("%w: invalid application status query", ErrInvalidState)
	}
	instances, err := listActiveInstances(ctx, s.db, staleAfter)
	if err != nil {
		return ApplicationStatus{}, err
	}
	return applicationStatus(revision, instances), nil
}

func (s *Store) WaitForApplied(ctx context.Context, revision int64, staleAfter time.Duration) (ApplicationStatus, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := s.ApplicationStatus(ctx, revision, staleAfter)
		if err != nil {
			return ApplicationStatus{}, err
		}
		if status.Applied {
			return status, nil
		}
		select {
		case <-ctx.Done():
			return status, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (s *Store) CleanupStaleInstances(ctx context.Context, staleFor time.Duration) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrStoreUnavailable
	}
	if staleFor <= 0 {
		return 0, fmt.Errorf("%w: cleanup age must be positive", ErrInvalidState)
	}
	result, err := s.db.Exec(ctx, `
		DELETE FROM service_control_instances
		WHERE heartbeat_at < now() - make_interval(secs => $1)
	`, staleFor.Seconds())
	if err != nil {
		return 0, fmt.Errorf("cleaning stale service control instances: %w", err)
	}
	return result.RowsAffected(), nil
}

type snapshotQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type instanceQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func loadSnapshot(ctx context.Context, queryer snapshotQueryer) (Snapshot, error) {
	var snapshot Snapshot
	var storedCapabilities []string
	err := queryer.QueryRow(ctx, `
		SELECT state.revision,state.public_message,state.internal_reason,state.expires_at,
		       state.updated_by,state.updated_by_name,state.updated_at,clock_timestamp(),
		       COALESCE(array_agg(pauses.capability ORDER BY pauses.capability)
		           FILTER (WHERE pauses.capability IS NOT NULL), '{}'::text[])
		FROM service_control_state AS state
		LEFT JOIN service_control_pauses AS pauses ON pauses.singleton=state.singleton
		WHERE state.singleton=TRUE
		GROUP BY state.singleton
	`).Scan(
		&snapshot.Revision, &snapshot.PublicMessage, &snapshot.InternalReason,
		&snapshot.ExpiresAt, &snapshot.UpdatedBy, &snapshot.UpdatedByName,
		&snapshot.UpdatedAt, &snapshot.DatabaseNow, &storedCapabilities,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("%w: singleton state is missing", ErrInvalidState)
	}
	if err != nil {
		return Snapshot{}, err
	}
	capabilities := make([]Capability, 0, len(storedCapabilities))
	for _, stored := range storedCapabilities {
		capability, err := ParseCapability(stored)
		if err != nil {
			return Snapshot{}, fmt.Errorf("reading persisted capability: %w", err)
		}
		capabilities = append(capabilities, capability)
	}
	normalized, err := NormalizeCapabilities(capabilities)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.PausedCapabilities = normalized
	snapshot.ObservedAt = time.Now().UTC()
	return cloneSnapshot(snapshot), nil
}

func lockSnapshot(ctx context.Context, tx pgx.Tx) (Snapshot, time.Time, error) {
	var snapshot Snapshot
	var databaseNow time.Time
	err := tx.QueryRow(ctx, `
		SELECT revision,public_message,internal_reason,expires_at,
		       updated_by,updated_by_name,updated_at,clock_timestamp()
		FROM service_control_state WHERE singleton=TRUE FOR UPDATE
	`).Scan(
		&snapshot.Revision, &snapshot.PublicMessage, &snapshot.InternalReason,
		&snapshot.ExpiresAt, &snapshot.UpdatedBy, &snapshot.UpdatedByName,
		&snapshot.UpdatedAt, &databaseNow,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, time.Time{}, fmt.Errorf("%w: singleton state is missing", ErrInvalidState)
	}
	if err != nil {
		return Snapshot{}, time.Time{}, fmt.Errorf("locking service control state: %w", err)
	}
	rows, err := tx.Query(ctx, `SELECT capability FROM service_control_pauses WHERE singleton=TRUE ORDER BY capability`)
	if err != nil {
		return Snapshot{}, time.Time{}, fmt.Errorf("locking service control capabilities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			return Snapshot{}, time.Time{}, fmt.Errorf("reading service control capability: %w", err)
		}
		capability, err := ParseCapability(stored)
		if err != nil {
			return Snapshot{}, time.Time{}, err
		}
		snapshot.PausedCapabilities = append(snapshot.PausedCapabilities, capability)
	}
	if err := rows.Err(); err != nil {
		return Snapshot{}, time.Time{}, fmt.Errorf("reading service control capabilities: %w", err)
	}
	normalized, err := NormalizeCapabilities(snapshot.PausedCapabilities)
	if err != nil {
		return Snapshot{}, time.Time{}, err
	}
	snapshot.PausedCapabilities = normalized
	snapshot.DatabaseNow = databaseNow.UTC()
	snapshot.ObservedAt = time.Now().UTC()
	return cloneSnapshot(snapshot), databaseNow.UTC(), nil
}

func listActiveInstances(ctx context.Context, queryer instanceQueryer, staleAfter time.Duration) ([]Instance, error) {
	rows, err := queryer.Query(ctx, `
		SELECT instance_id,version,started_at,heartbeat_at,loaded_revision,applied_revision
		FROM service_control_instances
		WHERE heartbeat_at >= now() - make_interval(secs => $1)
		ORDER BY started_at,instance_id
	`, staleAfter.Seconds())
	if err != nil {
		return nil, fmt.Errorf("listing active service control instances: %w", err)
	}
	defer rows.Close()
	instances := make([]Instance, 0)
	for rows.Next() {
		var instance Instance
		if err := rows.Scan(
			&instance.ID, &instance.Version, &instance.StartedAt, &instance.HeartbeatAt,
			&instance.LoadedRevision, &instance.AppliedRevision,
		); err != nil {
			return nil, fmt.Errorf("reading service control instance: %w", err)
		}
		instance.StartedAt = instance.StartedAt.UTC()
		instance.HeartbeatAt = instance.HeartbeatAt.UTC()
		instances = append(instances, instance)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing active service control instances: %w", err)
	}
	return instances, nil
}

func applicationStatus(revision int64, instances []Instance) ApplicationStatus {
	status := ApplicationStatus{
		Revision: revision, Instances: append([]Instance(nil), instances...),
		ActiveInstances: len(instances), Applied: true,
	}
	for _, instance := range instances {
		if instance.LoadedRevision >= revision && instance.AppliedRevision >= revision {
			status.AppliedInstances++
		} else {
			status.Applied = false
		}
	}
	return status
}

func validateUpdateInput(input UpdateInput) ([]Capability, error) {
	if input.ExpectedRevision < 1 {
		return nil, fmt.Errorf("%w: expected revision must be positive", ErrInvalidState)
	}
	if input.UpdatedBy == uuid.Nil {
		return nil, fmt.Errorf("%w: updater is required", ErrInvalidState)
	}
	if err := validateText(input.UpdatedByName, 1, 255, "updater name"); err != nil {
		return nil, err
	}
	if err := validateText(input.PublicMessage, 0, 240, "public message"); err != nil {
		return nil, err
	}
	capabilities, err := NormalizeCapabilities(input.PausedCapabilities)
	if err != nil {
		return nil, err
	}
	minimumReasonLength := 0
	if len(capabilities) > 0 {
		minimumReasonLength = 3
	}
	if err := validateText(input.InternalReason, minimumReasonLength, 500, "internal reason"); err != nil {
		return nil, err
	}
	if containsCapability(capabilities, CapabilityAuthIssuance) &&
		!containsCapability(capabilities, CapabilitySelfRegistration) {
		return nil, fmt.Errorf("%w: auth_issuance requires self_registration", ErrDependencyViolation)
	}
	return capabilities, nil
}

func normalizeUpdateInput(input UpdateInput) UpdateInput {
	input.PublicMessage = strings.TrimSpace(input.PublicMessage)
	input.InternalReason = strings.TrimSpace(input.InternalReason)
	input.UpdatedByName = strings.TrimSpace(input.UpdatedByName)
	return input
}

func validateExpiration(expiresAt *time.Time, now time.Time) error {
	if expiresAt == nil {
		return nil
	}
	remaining := expiresAt.UTC().Sub(now.UTC())
	if remaining < time.Minute || remaining > 30*24*time.Hour {
		return fmt.Errorf("%w: expiration must be between 1 minute and 30 days", ErrInvalidState)
	}
	return nil
}

func validateText(value string, minimum, maximum int, field string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidState, field)
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum {
		return fmt.Errorf("%w: %s must contain %d to %d characters", ErrInvalidState, field, minimum, maximum)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%w: %s contains control characters", ErrInvalidState, field)
		}
	}
	return nil
}

func loadRegistrationMode(ctx context.Context, tx pgx.Tx) (string, error) {
	var mode string
	err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT value->>'mode' FROM runtime_settings WHERE key='registration'),'closed')
	`).Scan(&mode)
	if err != nil {
		return "", fmt.Errorf("loading registration mode for service control: %w", err)
	}
	mode = strings.TrimSpace(mode)
	if mode == "" {
		mode = "closed"
	}
	return mode, nil
}

func validateTargetAgainstRegistration(ctx context.Context, tx pgx.Tx, capabilities []Capability) error {
	if containsCapability(capabilities, CapabilityAuthIssuance) &&
		!containsCapability(capabilities, CapabilitySelfRegistration) {
		return fmt.Errorf("%w: auth_issuance requires self_registration", ErrDependencyViolation)
	}
	if !containsCapability(capabilities, CapabilityMailDelivery) ||
		containsCapability(capabilities, CapabilitySelfRegistration) {
		return nil
	}
	mode, err := loadRegistrationMode(ctx, tx)
	if err != nil {
		return err
	}
	if mode != "closed" {
		return fmt.Errorf("%w: mail_delivery requires self_registration while registration is %s", ErrDependencyViolation, mode)
	}
	return nil
}

func insertCapabilities(ctx context.Context, tx pgx.Tx, capabilities []Capability) error {
	for _, capability := range capabilities {
		if _, err := tx.Exec(ctx, `
			INSERT INTO service_control_pauses (capability,singleton) VALUES ($1,TRUE)
		`, capability); err != nil {
			return fmt.Errorf("storing paused service capability %q: %w", capability, err)
		}
	}
	return nil
}

func notifyTx(ctx context.Context, tx pgx.Tx, revision int64) error {
	if _, err := tx.Exec(ctx, `SELECT pg_notify($1,$2)`, NotificationChannel, fmt.Sprintf("%d", revision)); err != nil {
		return fmt.Errorf("notifying service control change: %w", err)
	}
	return nil
}

func revisionConflict(expected, current int64) error {
	return fmt.Errorf("%w: expected %d, current %d", ErrRevisionConflict, expected, current)
}
