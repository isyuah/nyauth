package registration

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	registrationstats "github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/pkg/models"
)

const cleanupAdvisoryLockKey int64 = 0x4e594152454743 // "NYAREG"

type Store struct{ db *pgxpool.Pool }

func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

type CleanupResult struct {
	LockAcquired bool
	Released     int64
	DeletedUsers int64
	Batches      int
}

type cleanupCandidate struct {
	registrationID uuid.UUID
	userID         *uuid.UUID
	inviteID       *uuid.UUID
	expiresAt      time.Time
}

// CleanupExpired releases and removes expired pending registrations in bounded
// batches. A session advisory lock keeps an entire cleanup round single-writer
// across HA instances.
func (s *Store) CleanupExpired(ctx context.Context, now time.Time, batchSize, maxBatches int) (CleanupResult, error) {
	var result CleanupResult
	if s == nil || s.db == nil {
		return result, fmt.Errorf("registration store is unavailable")
	}
	if batchSize < 1 || batchSize > 1000 || maxBatches < 1 || maxBatches > 1000 {
		return result, fmt.Errorf("invalid registration cleanup bounds")
	}

	conn, err := s.db.Acquire(ctx)
	if err != nil {
		return result, fmt.Errorf("acquiring registration cleanup connection: %w", err)
	}
	defer conn.Release()
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, cleanupAdvisoryLockKey).Scan(&result.LockAcquired); err != nil {
		return result, fmt.Errorf("acquiring registration cleanup lock: %w", err)
	}
	if !result.LockAcquired {
		return result, nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		_ = conn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock($1)`, cleanupAdvisoryLockKey).Scan(&unlocked)
	}()

	for batch := 0; batch < maxBatches; batch++ {
		candidates, deleted, err := cleanupBatch(ctx, conn, now.UTC(), batchSize)
		if err != nil {
			return result, err
		}
		if len(candidates) == 0 {
			break
		}
		result.Batches++
		result.Released += int64(len(candidates))
		result.DeletedUsers += deleted
		if len(candidates) < batchSize {
			break
		}
	}
	return result, nil
}

func cleanupBatch(ctx context.Context, conn *pgxpool.Conn, now time.Time, batchSize int) ([]cleanupCandidate, int64, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("starting registration cleanup batch: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT id,user_id FROM self_registrations
		WHERE status='pending' AND expires_at<=$1
		ORDER BY expires_at,id
		LIMIT $2
	`, now, batchSize)
	if err != nil {
		return nil, 0, fmt.Errorf("selecting expired registrations: %w", err)
	}
	candidateIDs := make([]uuid.UUID, 0, batchSize)
	userIDs := make([]uuid.UUID, 0, batchSize)
	for rows.Next() {
		var registrationID uuid.UUID
		var userID *uuid.UUID
		if err := rows.Scan(&registrationID, &userID); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scanning expired registration: %w", err)
		}
		candidateIDs = append(candidateIDs, registrationID)
		if userID != nil {
			userIDs = append(userIDs, *userID)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, fmt.Errorf("reading expired registrations: %w", err)
	}
	rows.Close()
	if len(candidateIDs) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, 0, fmt.Errorf("committing empty registration cleanup batch: %w", err)
		}
		return nil, 0, nil
	}

	// Email verification and administrator lifecycle operations lock users
	// before self_registrations. Follow the same order here to avoid a cleanup
	// versus verification deadlock.
	if len(userIDs) > 0 {
		lockedRows, err := tx.Query(ctx, `SELECT id FROM users WHERE id=ANY($1::uuid[]) FOR UPDATE`, userIDs)
		if err != nil {
			return nil, 0, fmt.Errorf("locking expired registration users: %w", err)
		}
		for lockedRows.Next() {
			var ignored uuid.UUID
			if err := lockedRows.Scan(&ignored); err != nil {
				lockedRows.Close()
				return nil, 0, fmt.Errorf("scanning locked registration user: %w", err)
			}
		}
		if err := lockedRows.Err(); err != nil {
			lockedRows.Close()
			return nil, 0, fmt.Errorf("reading locked registration users: %w", err)
		}
		lockedRows.Close()
	}

	rows, err = tx.Query(ctx, `
		UPDATE self_registrations
		SET status='released',released_at=$1,release_reason=$2,updated_at=$1
		WHERE id=ANY($3::uuid[]) AND status='pending' AND expires_at<=$1
		RETURNING id,user_id,invite_id,expires_at
	`, now, ReleaseReasonExpired, candidateIDs)
	if err != nil {
		return nil, 0, fmt.Errorf("releasing expired registrations: %w", err)
	}
	candidates := make([]cleanupCandidate, 0, len(candidateIDs))
	userIDs = userIDs[:0]
	for rows.Next() {
		var candidate cleanupCandidate
		if err := rows.Scan(&candidate.registrationID, &candidate.userID, &candidate.inviteID, &candidate.expiresAt); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("scanning released registration: %w", err)
		}
		candidates = append(candidates, candidate)
		if candidate.userID != nil {
			userIDs = append(userIDs, *candidate.userID)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, fmt.Errorf("reading released registrations: %w", err)
	}
	rows.Close()

	type expiryDelta struct {
		eventAt time.Time
		delta   registrationstats.RegistrationDailyDelta
	}
	expiryByDay := make(map[string]expiryDelta)
	for _, candidate := range candidates {
		day := candidate.expiresAt.UTC().Format("2006-01-02")
		entry := expiryByDay[day]
		entry.eventAt = candidate.expiresAt
		entry.delta.RegistrationsExpired++
		if candidate.inviteID != nil {
			entry.delta.InvitesReleased++
		}
		expiryByDay[day] = entry
	}
	for _, entry := range expiryByDay {
		if err := registrationstats.AddRegistrationDailyTx(ctx, tx, entry.eventAt, entry.delta); err != nil {
			return nil, 0, fmt.Errorf("recording expired registration statistics: %w", err)
		}
	}

	actor := AuditContext{ActorName: "system"}
	for _, candidate := range candidates {
		if candidate.userID == nil {
			return nil, 0, fmt.Errorf("pending registration %s has no user", candidate.registrationID)
		}
		if candidate.inviteID != nil {
			if err := enqueueInviteEventTx(
				ctx, tx, models.AuditInviteReleased, *candidate.inviteID,
				candidate.registrationID, *candidate.userID, "cleanup", ReleaseReasonExpired, actor, now,
			); err != nil {
				return nil, 0, err
			}
		}
		if err := audit.EnqueueTargetResultTx(
			ctx, tx, models.AuditRegistrationExpired, nil, "system", "registration",
			candidate.registrationID.String(), "success", "low", "", "",
			map[string]any{"user_id": candidate.userID.String()}, now,
		); err != nil {
			return nil, 0, fmt.Errorf("auditing expired registration: %w", err)
		}
	}

	var deleted int64
	if len(userIDs) > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id=ANY($1::uuid[])`, userIDs)
		if err != nil {
			return nil, 0, fmt.Errorf("deleting expired registration users: %w", err)
		}
		deleted = tag.RowsAffected()
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("committing registration cleanup batch: %w", err)
	}
	return candidates, deleted, nil
}
