package securityrevocation

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Task struct {
	UserID         uuid.UUID
	Revision       int64
	AuthVersion    int64
	SessionVersion int64
	UserDeleted    bool
	Reason         string
	AttemptCount   int
}

type Store struct {
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) *Store {
	return &Store{db: db}
}

func (s *Store) Claim(ctx context.Context, workerID string, limit int, now time.Time, lease time.Duration) ([]Task, error) {
	if s == nil || s.db == nil || strings.TrimSpace(workerID) == "" || limit < 1 || lease <= 0 {
		return nil, fmt.Errorf("invalid security revocation claim")
	}
	rows, err := s.db.Query(ctx, `
		WITH candidates AS (
			SELECT user_id
			FROM security_revocation_outbox
			WHERE available_at <= $1
			  AND (locked_at IS NULL OR locked_at <= $4)
			ORDER BY available_at, updated_at, user_id
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE security_revocation_outbox AS task
		SET locked_at=$1,locked_by=$2,attempt_count=task.attempt_count+1,updated_at=$1
		FROM candidates
		WHERE task.user_id=candidates.user_id
		RETURNING task.user_id,task.revision,task.auth_version,task.session_version,
		          task.user_deleted,task.reason,task.attempt_count
	`, now.UTC(), workerID, limit, now.UTC().Add(-lease))
	if err != nil {
		return nil, fmt.Errorf("claiming security revocations: %w", err)
	}
	defer rows.Close()

	tasks := make([]Task, 0, limit)
	for rows.Next() {
		var task Task
		if err := rows.Scan(
			&task.UserID, &task.Revision, &task.AuthVersion, &task.SessionVersion,
			&task.UserDeleted, &task.Reason, &task.AttemptCount,
		); err != nil {
			return nil, fmt.Errorf("reading security revocation: %w", err)
		}
		tasks = append(tasks, task)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("claiming security revocations: %w", err)
	}
	return tasks, nil
}

// Complete deletes exactly the revision that was processed. If a trigger
// advanced the revision while Redis cleanup was in flight, the newer task is
// unlocked and retained for another pass.
func (s *Store) Complete(ctx context.Context, task Task, workerID string, now time.Time) (bool, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("starting security revocation completion: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		DELETE FROM security_revocation_outbox
		WHERE user_id=$1 AND revision=$2 AND locked_by=$3
	`, task.UserID, task.Revision, workerID)
	if err != nil {
		return false, fmt.Errorf("completing security revocation: %w", err)
	}
	completed := tag.RowsAffected() == 1
	if !completed {
		if _, err := tx.Exec(ctx, `
			UPDATE security_revocation_outbox
			SET locked_at=NULL,locked_by=NULL,available_at=LEAST(available_at,$3),updated_at=$3
			WHERE user_id=$1 AND locked_by=$2
		`, task.UserID, workerID, now.UTC()); err != nil {
			return false, fmt.Errorf("releasing superseded security revocation: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing security revocation completion: %w", err)
	}
	return completed, nil
}

func (s *Store) Retry(ctx context.Context, task Task, workerID, lastError string, retryAt, now time.Time) error {
	lastError = strings.TrimSpace(lastError)
	if len(lastError) > 1024 {
		lastError = lastError[:1024]
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE security_revocation_outbox
		SET locked_at=NULL,locked_by=NULL,last_error=$4,available_at=$5,updated_at=$6
		WHERE user_id=$1 AND revision=$2 AND locked_by=$3
	`, task.UserID, task.Revision, workerID, lastError, retryAt.UTC(), now.UTC())
	if err != nil {
		return fmt.Errorf("rescheduling security revocation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// A newer revision is already authoritative. Release its inherited lease
		// immediately instead of applying the old attempt's backoff to it.
		if _, err := s.db.Exec(ctx, `
			UPDATE security_revocation_outbox
			SET locked_at=NULL,locked_by=NULL,available_at=LEAST(available_at,$3),updated_at=$3
			WHERE user_id=$1 AND locked_by=$2
		`, task.UserID, workerID, now.UTC()); err != nil {
			return fmt.Errorf("releasing superseded failed revocation: %w", err)
		}
	}
	return nil
}
