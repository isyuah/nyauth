package mediaruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/pkg/models"
)

const migrationClaimLease = 15 * time.Minute

type MigrationWorkItem struct {
	MigrationID     uuid.UUID
	AvatarID        uuid.UUID
	SourceProfileID *uuid.UUID
	SourceBackend   avatar.StorageBackend
	TargetProfileID *uuid.UUID
	TargetBackend   avatar.StorageBackend
	Status          string
	AttemptCount    int
	Variants        []models.AvatarVariant
}

func (s *Store) ActiveMigrationExists(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM media_storage_migrations WHERE status<>'completed')`).Scan(&exists)
	return exists, err
}

func (s *Store) ClaimMigrationItem(ctx context.Context, worker string, now time.Time) (*MigrationWorkItem, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var item MigrationWorkItem
	var raw []byte
	err = tx.QueryRow(ctx, `
		WITH active AS (
			SELECT id FROM media_storage_migrations WHERE status IN ('pending','running') ORDER BY created_at LIMIT 1 FOR UPDATE
		), candidate AS (
			SELECT item.migration_id,item.avatar_id FROM media_storage_migration_items item JOIN active ON active.id=item.migration_id
			WHERE item.status IN ('pending','switched','failed') OR (item.status='copying' AND item.locked_at <= $2)
			ORDER BY CASE item.status WHEN 'switched' THEN 0 WHEN 'pending' THEN 1 WHEN 'failed' THEN 2 ELSE 3 END,item.updated_at,item.avatar_id
			LIMIT 1 FOR UPDATE OF item SKIP LOCKED
		), claimed AS (
			UPDATE media_storage_migration_items item SET
				status=CASE WHEN item.status='switched' THEN 'switched' ELSE 'copying' END,
				locked_at=CASE WHEN item.status='switched' THEN NULL ELSE $1::timestamptz END,
				locked_by=CASE WHEN item.status='switched' THEN NULL ELSE $3::text END,
				attempt_count=CASE WHEN item.status='switched' THEN item.attempt_count ELSE item.attempt_count+1 END,
				updated_at=$1
			FROM candidate WHERE item.migration_id=candidate.migration_id AND item.avatar_id=candidate.avatar_id
			RETURNING item.*
		)
		SELECT claimed.migration_id,claimed.avatar_id,claimed.source_profile_id,claimed.source_backend,claimed.target_profile_id,claimed.target_backend,claimed.status,claimed.attempt_count,avatar.variants
		FROM claimed JOIN user_avatars avatar ON avatar.id=claimed.avatar_id
	`, now.UTC(), now.UTC().Add(-migrationClaimLease), worker).Scan(&item.MigrationID, &item.AvatarID, &item.SourceProfileID, &item.SourceBackend, &item.TargetProfileID, &item.TargetBackend, &item.Status, &item.AttemptCount, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claiming media migration item: %w", err)
	}
	if err := json.Unmarshal(raw, &item.Variants); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE media_storage_migrations SET status='running',started_at=COALESCE(started_at,$2),updated_at=$2 WHERE id=$1`, item.MigrationID, now.UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *Store) MarkItemSwitched(ctx context.Context, item MigrationWorkItem, worker string, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE user_avatars SET storage_backend=$3,storage_profile_id=$4,updated_at=$5 WHERE id=$1 AND storage_profile_id IS NOT DISTINCT FROM $2 AND storage_deleted_at IS NULL`, item.AvatarID, item.SourceProfileID, item.TargetBackend, item.TargetProfileID, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("avatar storage ownership changed during migration")
	}
	tag, err = tx.Exec(ctx, `UPDATE media_storage_migration_items SET status='switched',copied_at=$5,switched_at=$5,locked_at=NULL,locked_by=NULL,last_error=NULL,updated_at=$5 WHERE migration_id=$1 AND avatar_id=$2 AND status='copying' AND locked_by=$3 AND attempt_count=$4`, item.MigrationID, item.AvatarID, worker, item.AttemptCount, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("media migration claim was lost")
	}
	if _, err = tx.Exec(ctx, `UPDATE media_storage_migrations SET copied_count=(SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1 AND status IN ('switched','completed')),failed_count=(SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1 AND status='failed'),updated_at=$2 WHERE id=$1`, item.MigrationID, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CompleteItem(ctx context.Context, item MigrationWorkItem, now time.Time) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE media_storage_migration_items SET status='completed',completed_at=$3,last_error=NULL,updated_at=$3 WHERE migration_id=$1 AND avatar_id=$2 AND status='switched'`, item.MigrationID, item.AvatarID, now.UTC())
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("media migration item is not switched")
	}
	if _, err = tx.Exec(ctx, `UPDATE media_storage_migrations SET completed_count=(SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1 AND status='completed'),updated_at=$2 WHERE id=$1`, item.MigrationID, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FailItem(ctx context.Context, item MigrationWorkItem, worker string, cause error, now time.Time) error {
	message := "media storage operation failed"
	if cause != nil {
		message = cause.Error()
	}
	if len(message) > 500 {
		message = message[:500]
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE media_storage_migration_items SET status='failed',locked_at=NULL,locked_by=NULL,last_error=$5,updated_at=$6 WHERE migration_id=$1 AND avatar_id=$2 AND status='copying' AND locked_by=$3 AND attempt_count=$4`, item.MigrationID, item.AvatarID, worker, item.AttemptCount, message, now.UTC())
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE media_storage_migrations SET status='failed',failed_count=(SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1 AND status='failed'),failed_at=$2,last_error=$3,updated_at=$2 WHERE id=$1`, item.MigrationID, now.UTC(), message)
	if err != nil {
		return err
	}
	var actorID *uuid.UUID
	var actorName string
	if err = tx.QueryRow(ctx, `SELECT created_by,created_by_name FROM media_storage_migrations WHERE id=$1`, item.MigrationID).Scan(&actorID, &actorName); err != nil {
		return err
	}
	if err = audit.EnqueueTargetResultTx(ctx, tx, models.AuditMediaMigrationFailed, actorID, actorName, "media_migration", item.MigrationID.String(), "failure", "high", "", "", map[string]any{"avatar_id": item.AvatarID.String(), "error": "storage_operation_failed"}, now.UTC()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) FinalizeMigration(ctx context.Context, migrationID uuid.UUID, now time.Time) (Migration, State, bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Migration{}, State{}, false, err
	}
	defer tx.Rollback(ctx)
	migration, err := scanMigration(tx.QueryRow(ctx, migrationSelect+` WHERE id=$1 FOR UPDATE`, migrationID))
	if err != nil {
		return Migration{}, State{}, false, err
	}
	if migration.Status == "applying" {
		state, err := lockState(ctx, tx)
		if err != nil {
			return Migration{}, State{}, false, err
		}
		if !sameProfileID(state.ActiveProfileID, migration.TargetProfileID) {
			return Migration{}, State{}, false, ErrCandidateChanged
		}
		var unprepared int64
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(*) FROM media_storage_instances
			WHERE heartbeat_at > NOW()-INTERVAL '15 seconds' AND loaded_revision < $1
		`, state.Revision).Scan(&unprepared); err != nil {
			return Migration{}, State{}, false, err
		}
		if unprepared > 0 {
			return migration, state, false, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE media_storage_migrations SET status='completed',completed_count=total_count,completed_at=$2,updated_at=$2,last_error=NULL WHERE id=$1 AND status='applying'`, migrationID, now.UTC()); err != nil {
			return Migration{}, State{}, false, err
		}
		if err := audit.EnqueueTargetResultTx(ctx, tx, models.AuditMediaMigrationFinished, migration.CreatedBy, migration.CreatedByName, "media_migration", migrationID.String(), "success", "high", "", "", map[string]any{"source_profile_id": migration.SourceProfileID, "source_backend": migration.SourceBackend, "target_profile_id": migration.TargetProfileID, "target_backend": migration.TargetBackend, "objects": migration.TotalCount}, now.UTC()); err != nil {
			return Migration{}, State{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Migration{}, State{}, false, err
		}
		migration, err = s.LoadMigration(ctx, migrationID)
		return migration, state, true, err
	}
	if migration.Status != "running" && migration.Status != "pending" {
		return migration, State{}, false, nil
	}
	var remaining int64
	if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM media_storage_migration_items WHERE migration_id=$1 AND status<>'completed'`, migrationID).Scan(&remaining); err != nil {
		return Migration{}, State{}, false, err
	}
	if remaining > 0 {
		return migration, State{}, false, nil
	}
	state, err := lockState(ctx, tx)
	if err != nil {
		return Migration{}, State{}, false, err
	}
	if !sameProfileID(state.ActiveProfileID, migration.SourceProfileID) {
		return Migration{}, State{}, false, ErrCandidateChanged
	}
	if migration.TargetBackend == "s3" {
		if migration.TargetProfileID == nil || !sameProfileID(state.CandidateProfileID, migration.TargetProfileID) {
			return Migration{}, State{}, false, ErrCandidateChanged
		}
	} else if migration.TargetBackend != "local" || migration.TargetProfileID != nil {
		return Migration{}, State{}, false, ErrInvalidConfig
	}
	state, err = scanState(tx.QueryRow(ctx, `UPDATE media_storage_state SET active_profile_id=$1,previous_profile_id=$2,candidate_profile_id=NULL,revision=revision+1,updated_by=$3,updated_by_name=$4,updated_at=$5 WHERE singleton=TRUE RETURNING revision,active_profile_id,candidate_profile_id,previous_profile_id,updated_by,updated_by_name,updated_at`, migration.TargetProfileID, migration.SourceProfileID, migration.CreatedBy, migration.CreatedByName, now.UTC()))
	if err != nil {
		return Migration{}, State{}, false, err
	}
	_, err = tx.Exec(ctx, `UPDATE media_storage_migrations SET status='applying',completed_count=total_count,updated_at=$2,last_error=NULL WHERE id=$1`, migrationID, now.UTC())
	if err != nil {
		return Migration{}, State{}, false, err
	}
	if err = notifyTx(ctx, tx, "activated", state.Revision); err != nil {
		return Migration{}, State{}, false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Migration{}, State{}, false, err
	}
	migration, err = s.LoadMigration(ctx, migrationID)
	return migration, state, false, err
}

func sameProfileID(left, right *uuid.UUID) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
