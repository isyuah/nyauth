package avatar

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
	"github.com/nyasharp/nyauth/pkg/models"
)

const cleanupAdvisoryLockKey int64 = 0x4e594156415441 // "NYAVATA"
const cleanupClaimLease = 15 * time.Minute

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func (r *Repository) EnsureStorageBackendCompatible(ctx context.Context, backend StorageBackend) error {
	if r == nil || r.db == nil {
		return fmt.Errorf("avatar repository is unavailable")
	}
	if backend != StorageLocal && backend != StorageS3 {
		return fmt.Errorf("invalid avatar storage backend %q", backend)
	}
	var incompatible int64
	if err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_avatars
		WHERE storage_profile_id IS NULL AND storage_backend<>$1 AND storage_deleted_at IS NULL
	`, backend).Scan(&incompatible); err != nil {
		return fmt.Errorf("checking avatar storage backend compatibility: %w", err)
	}
	if incompatible > 0 {
		return fmt.Errorf("avatar storage backend cannot change while %d objects still belong to another backend; migrate or remove them before switching", incompatible)
	}
	return nil
}

func (r *Repository) Begin(ctx context.Context) (pgx.Tx, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("avatar repository is unavailable")
	}
	return r.db.Begin(ctx)
}

func (r *Repository) CreateStagingTx(ctx context.Context, tx pgx.Tx, params CreateAvatarParams, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("avatar transaction is required")
	}
	if params.ID == uuid.Nil {
		params.ID = uuid.New()
	}
	variants, err := marshalVariants(params.Variants)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO user_avatars (
			id,user_id,client_id,media_purpose,source,status,storage_backend,storage_profile_id,object_prefix,variants,content_sha256,
			original_media_type,original_width,original_height,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,'staging',$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
	`, params.ID, params.UserID, params.ClientID, params.MediaPurpose, params.Source, params.StorageBackend, params.StorageProfileID, params.ObjectPrefix, variants,
		params.ContentSHA256, params.OriginalMediaType, params.OriginalWidth, params.OriginalHeight, now.UTC())
	if err != nil {
		return fmt.Errorf("creating staging avatar record: %w", err)
	}
	return nil
}

func (r *Repository) ActivateTx(ctx context.Context, tx pgx.Tx, userID, avatarID uuid.UUID, now time.Time) error {
	return r.activateTx(ctx, tx, userID, avatarID, now, false)
}

func (r *Repository) ActivateIfUnsetTx(ctx context.Context, tx pgx.Tx, userID, avatarID uuid.UUID, now time.Time) error {
	return r.activateTx(ctx, tx, userID, avatarID, now, true)
}

func (r *Repository) activateTx(ctx context.Context, tx pgx.Tx, userID, avatarID uuid.UUID, now time.Time, requireUnset bool) error {
	if tx == nil {
		return fmt.Errorf("avatar transaction is required")
	}
	now = now.UTC()
	var currentAvatarID *uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT current_avatar_id FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&currentAvatarID); err != nil {
		return fmt.Errorf("locking avatar owner: %w", err)
	}
	if requireUnset && currentAvatarID != nil {
		return ErrAvatarAlreadySet
	}
	if _, err := tx.Exec(ctx, `
		UPDATE user_avatars
		SET status='replaced',replaced_at=$3,updated_at=$3
		WHERE user_id=$1 AND id<>$2 AND status='active'
	`, userID, avatarID, now); err != nil {
		return fmt.Errorf("replacing previous active avatar: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE user_avatars
		SET status='active',activated_at=$3,updated_at=$3,last_error=NULL,failed_at=NULL
		WHERE id=$1 AND user_id=$2 AND status='staging'
	`, avatarID, userID, now)
	if err != nil {
		return fmt.Errorf("activating avatar record: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	tag, err = tx.Exec(ctx, `UPDATE users SET current_avatar_id=$1,updated_at=$3 WHERE id=$2`, avatarID, userID, now)
	if err != nil {
		return fmt.Errorf("updating user current avatar: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) GetActiveVariant(ctx context.Context, avatarID uuid.UUID, size int, mediaPurpose string) (ActiveVariant, error) {
	var result ActiveVariant
	if r == nil || r.db == nil {
		return result, fmt.Errorf("avatar repository is unavailable")
	}
	if avatarID == uuid.Nil || !validVariantSize(size) || (mediaPurpose != "user_avatar" && mediaPurpose != "client_logo") {
		return result, ErrNotFound
	}
	var raw []byte
	if err := r.db.QueryRow(ctx, `
		SELECT storage_backend,storage_profile_id,variants
		FROM user_avatars
		WHERE id=$1 AND media_purpose=$2 AND status='active' AND storage_deleted_at IS NULL
	`, avatarID, mediaPurpose).Scan(&result.StorageBackend, &result.StorageProfileID, &raw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return result, ErrNotFound
		}
		return result, fmt.Errorf("reading active avatar variant: %w", err)
	}
	var variants []models.AvatarVariant
	if err := json.Unmarshal(raw, &variants); err != nil {
		return result, fmt.Errorf("decoding active avatar variants: %w", err)
	}
	for _, variant := range variants {
		if variant.Size == size && variant.ObjectKey != "" && variant.ContentType == ContentType {
			result.Variant = variant
			return result, nil
		}
	}
	return ActiveVariant{}, ErrNotFound
}

func (r *Repository) MarkFailedTx(ctx context.Context, tx pgx.Tx, avatarID uuid.UUID, reason string, now time.Time) error {
	if tx == nil {
		return fmt.Errorf("avatar transaction is required")
	}
	_, err := tx.Exec(ctx, `
		UPDATE user_avatars
		SET status='failed',failed_at=$2,last_error=$3,updated_at=$2
		WHERE id=$1 AND status='staging'
	`, avatarID, now.UTC(), trimError(reason))
	if err != nil {
		return fmt.Errorf("marking avatar failed: %w", err)
	}
	return nil
}

func (r *Repository) MarkFailed(ctx context.Context, avatarID uuid.UUID, reason string, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE user_avatars
		SET status='failed',failed_at=$2,last_error=$3,updated_at=$2
		WHERE id=$1 AND status='staging'
	`, avatarID, now.UTC(), trimError(reason))
	if err != nil {
		return fmt.Errorf("marking avatar failed: %w", err)
	}
	return nil
}

func (r *Repository) DeleteActiveTx(ctx context.Context, tx pgx.Tx, userID uuid.UUID, now time.Time) ([]CleanupItem, error) {
	if tx == nil {
		return nil, fmt.Errorf("avatar transaction is required")
	}
	now = now.UTC()
	if _, err := tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID); err != nil {
		return nil, fmt.Errorf("locking avatar owner: %w", err)
	}
	rows, err := tx.Query(ctx, `
		UPDATE user_avatars
		SET status='deleted',deleted_at=$2,updated_at=$2
		WHERE user_id=$1 AND status='active'
		RETURNING id,storage_backend,storage_profile_id,variants
	`, userID, now)
	if err != nil {
		return nil, fmt.Errorf("deleting active avatar record: %w", err)
	}
	items, _, err := collectCleanupItems(rows)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE users SET current_avatar_id=NULL,updated_at=$2 WHERE id=$1`, userID, now); err != nil {
		return nil, fmt.Errorf("clearing user current avatar: %w", err)
	}
	return items, nil
}

func (r *Repository) ActivateClientLogoTx(ctx context.Context, tx pgx.Tx, clientID string, logoID uuid.UUID, now time.Time) error {
	if tx == nil || strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("client logo transaction and owner are required")
	}
	now = now.UTC()
	if _, err := tx.Exec(ctx, `SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE`, clientID); err != nil {
		return fmt.Errorf("locking client logo owner: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE user_avatars SET status='replaced',replaced_at=$3,updated_at=$3
		WHERE client_id=$1 AND id<>$2 AND media_purpose='client_logo' AND status='active'
	`, clientID, logoID, now); err != nil {
		return fmt.Errorf("replacing previous active client logo: %w", err)
	}
	tag, err := tx.Exec(ctx, `
		UPDATE user_avatars SET status='active',activated_at=$3,updated_at=$3,last_error=NULL,failed_at=NULL
		WHERE id=$1 AND client_id=$2 AND media_purpose='client_logo' AND status='staging'
	`, logoID, clientID, now)
	if err != nil {
		return fmt.Errorf("activating client logo: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	tag, err = tx.Exec(ctx, `
		UPDATE oauth_clients
		SET current_logo_id=$2,identity_revision=identity_revision+1,updated_at=$3
		WHERE id=$1
	`, clientID, logoID, now)
	if err != nil {
		return fmt.Errorf("updating client current logo: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) DeleteActiveClientLogoTx(ctx context.Context, tx pgx.Tx, clientID string, now time.Time) ([]CleanupItem, error) {
	if tx == nil || strings.TrimSpace(clientID) == "" {
		return nil, fmt.Errorf("client logo transaction and owner are required")
	}
	now = now.UTC()
	if _, err := tx.Exec(ctx, `SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE`, clientID); err != nil {
		return nil, fmt.Errorf("locking client logo owner: %w", err)
	}
	rows, err := tx.Query(ctx, `
		UPDATE user_avatars SET status='deleted',deleted_at=$2,updated_at=$2
		WHERE client_id=$1 AND media_purpose='client_logo' AND status='active'
		RETURNING id,storage_backend,storage_profile_id,variants
	`, clientID, now)
	if err != nil {
		return nil, fmt.Errorf("deleting active client logo: %w", err)
	}
	items, _, err := collectCleanupItems(rows)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE oauth_clients
		SET current_logo_id=NULL,identity_revision=identity_revision+1,updated_at=$2
		WHERE id=$1 AND current_logo_id IS NOT NULL
	`, clientID, now); err != nil {
		return nil, fmt.Errorf("clearing client current logo: %w", err)
	}
	return items, nil
}

type CleanupResult struct {
	LockAcquired bool
	Rows         int64
	Batches      int
	Items        []CleanupItem
}

type CleanupItem struct {
	AvatarID         uuid.UUID
	StorageBackend   StorageBackend
	StorageProfileID *uuid.UUID
	ObjectKeys       []string
}

func (r *Repository) CleanupUnreferenced(ctx context.Context, backend StorageBackend, now time.Time, olderThan time.Duration, batchSize, maxBatches int) (CleanupResult, error) {
	var result CleanupResult
	if r == nil || r.db == nil {
		return result, fmt.Errorf("avatar repository is unavailable")
	}
	if olderThan < 0 || batchSize < 1 || batchSize > 1000 || maxBatches < 1 || maxBatches > 1000 {
		return result, fmt.Errorf("invalid avatar cleanup bounds")
	}
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return result, fmt.Errorf("acquiring avatar cleanup connection: %w", err)
	}
	defer conn.Release()
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, cleanupAdvisoryLockKey).Scan(&result.LockAcquired); err != nil {
		return result, fmt.Errorf("acquiring avatar cleanup lock: %w", err)
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
	cutoff := now.UTC().Add(-olderThan)
	claimExpiredBefore := now.UTC().Add(-cleanupClaimLease)
	for batch := 0; batch < maxBatches; batch++ {
		items, rows, err := cleanupBatch(ctx, conn, backend, cutoff, claimExpiredBefore, now.UTC(), batchSize)
		if err != nil {
			return result, err
		}
		if len(items) == 0 {
			break
		}
		result.Batches++
		result.Rows += rows
		result.Items = append(result.Items, items...)
		if rows < int64(batchSize) {
			break
		}
	}
	return result, nil
}

func (r *Repository) CountCleanupPending(ctx context.Context, backend StorageBackend) (int64, error) {
	if r == nil || r.db == nil {
		return 0, fmt.Errorf("avatar repository is unavailable")
	}
	var count int64
	if err := r.db.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_avatars
		WHERE storage_backend=$1 AND storage_deleted_at IS NULL
		  AND (status IN ('staging','replaced','failed','deleted')
		       OR (media_purpose='user_avatar' AND user_id IS NULL)
		       OR (media_purpose='client_logo' AND client_id IS NULL))
	`, backend).Scan(&count); err != nil {
		return 0, fmt.Errorf("counting avatar cleanup backlog: %w", err)
	}
	return count, nil
}

func cleanupBatch(ctx context.Context, conn *pgxpool.Conn, backend StorageBackend, cutoff, claimExpiredBefore, now time.Time, batchSize int) ([]CleanupItem, int64, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("starting avatar cleanup batch: %w", err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM user_avatars
			WHERE (status IN ('staging','replaced','failed','deleted')
			       OR (media_purpose='user_avatar' AND user_id IS NULL)
			       OR (media_purpose='client_logo' AND client_id IS NULL))
			  AND storage_backend=$5::text
			  AND storage_deleted_at IS NULL
			  AND (cleanup_claimed_at IS NULL OR cleanup_claimed_at <= $2::timestamptz)
			  AND updated_at <= $1::timestamptz
			ORDER BY updated_at,id
			LIMIT $3
			FOR UPDATE SKIP LOCKED
		)
		UPDATE user_avatars AS avatar
		SET cleanup_claimed_at=$4::timestamptz
		FROM candidates
		WHERE avatar.id=candidates.id
		RETURNING avatar.id,avatar.storage_backend,avatar.storage_profile_id,avatar.variants
	`, cutoff, claimExpiredBefore, batchSize, now, backend)
	if err != nil {
		return nil, 0, fmt.Errorf("marking avatar media for cleanup: %w", err)
	}
	items, rowCount, err := collectCleanupItems(rows)
	if err != nil {
		return nil, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, fmt.Errorf("committing avatar cleanup batch: %w", err)
	}
	if rowCount == 0 {
		return items, 0, nil
	}
	return items, rowCount, nil
}

func (r *Repository) MarkStorageDeleted(ctx context.Context, avatarID uuid.UUID, now time.Time) error {
	_, err := r.db.Exec(ctx, `
		UPDATE user_avatars
		SET storage_deleted_at=$2,cleanup_claimed_at=NULL,updated_at=$2
		WHERE id=$1 AND storage_deleted_at IS NULL
	`, avatarID, now.UTC())
	if err != nil {
		return fmt.Errorf("confirming avatar storage cleanup: %w", err)
	}
	return nil
}

func (r *Repository) ReleaseCleanupClaim(ctx context.Context, avatarID uuid.UUID) error {
	_, err := r.db.Exec(ctx, `UPDATE user_avatars SET cleanup_claimed_at=NULL WHERE id=$1 AND storage_deleted_at IS NULL`, avatarID)
	if err != nil {
		return fmt.Errorf("releasing avatar cleanup claim: %w", err)
	}
	return nil
}

func (r *Repository) CreateProviderImportJobTx(ctx context.Context, tx pgx.Tx, job models.ProviderAvatarImportJob) (uuid.UUID, error) {
	if tx == nil {
		return uuid.Nil, fmt.Errorf("avatar import transaction is required")
	}
	if job.ID == uuid.Nil {
		job.ID = uuid.New()
	}
	if job.AvailableAt.IsZero() {
		job.AvailableAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO provider_avatar_import_jobs (
			id,provider_id,user_id,encrypted_avatar_url,status,available_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,'pending',$5,$5,$5)
	`, job.ID, job.ProviderID, job.UserID, job.EncryptedAvatarURL, job.AvailableAt.UTC())
	if err != nil {
		return uuid.Nil, fmt.Errorf("creating provider avatar import job: %w", err)
	}
	return job.ID, nil
}

func (r *Repository) ClaimProviderImportJobs(ctx context.Context, worker string, now time.Time, lease time.Duration, batchSize int) ([]models.ProviderAvatarImportJob, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("avatar repository is unavailable")
	}
	if worker == "" || lease <= 0 || batchSize < 1 || batchSize > 100 {
		return nil, fmt.Errorf("invalid avatar import claim parameters")
	}
	rows, err := r.db.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM provider_avatar_import_jobs
			WHERE status IN ('pending','processing') AND available_at <= $1
			ORDER BY available_at,created_at,id
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		UPDATE provider_avatar_import_jobs AS job
		SET status='processing',locked_at=$1,locked_by=$3,attempt_count=attempt_count+1,
		    available_at=$4,updated_at=$1
		FROM candidates
		WHERE job.id=candidates.id
		RETURNING job.id,job.provider_id,job.user_id,job.encrypted_avatar_url,job.status,
		          job.attempt_count,job.available_at,job.locked_at,job.locked_by,job.completed_at,
		          job.failed_at,job.last_error,job.created_at,job.updated_at
	`, now.UTC(), batchSize, worker, now.UTC().Add(lease))
	if err != nil {
		return nil, fmt.Errorf("claiming provider avatar import jobs: %w", err)
	}
	defer rows.Close()
	return scanJobs(rows)
}

func (r *Repository) CompleteProviderImportJob(ctx context.Context, id uuid.UUID, worker string, attemptCount int, now time.Time) error {
	if strings.TrimSpace(worker) == "" || attemptCount < 1 {
		return fmt.Errorf("invalid avatar import completion claim")
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE provider_avatar_import_jobs
		SET status='completed',encrypted_avatar_url='',completed_at=$4,locked_at=NULL,locked_by=NULL,
		    last_error=NULL,updated_at=$4
		WHERE id=$1 AND status='processing' AND locked_by=$2 AND attempt_count=$3
	`, id, worker, attemptCount, now.UTC())
	if err != nil {
		return fmt.Errorf("completing provider avatar import job: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func (r *Repository) FailProviderImportJob(ctx context.Context, id uuid.UUID, worker string, attemptCount int, reason string, retryAt *time.Time, now time.Time) error {
	if strings.TrimSpace(worker) == "" || attemptCount < 1 {
		return fmt.Errorf("invalid avatar import failure claim")
	}
	status := "failed"
	encryptedClear := true
	availableAt := now.UTC()
	if retryAt != nil {
		status = "pending"
		encryptedClear = false
		availableAt = retryAt.UTC()
	}
	encryptedExpr := "encrypted_avatar_url"
	if encryptedClear {
		encryptedExpr = "''"
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE provider_avatar_import_jobs
		SET status=$4,encrypted_avatar_url=`+encryptedExpr+`,failed_at=CASE WHEN $5 THEN $6 ELSE failed_at END,
		    available_at=$7,locked_at=NULL,locked_by=NULL,last_error=$8,updated_at=$6
		WHERE id=$1 AND status='processing' AND locked_by=$2 AND attempt_count=$3
	`, id, worker, attemptCount, status, encryptedClear, now.UTC(), availableAt, trimError(reason))
	if err != nil {
		return fmt.Errorf("failing provider avatar import job: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}

func marshalVariants(variants []models.AvatarVariant) ([]byte, error) {
	if len(variants) == 0 {
		return nil, fmt.Errorf("avatar variants are required")
	}
	encoded, err := json.Marshal(variants)
	if err != nil {
		return nil, fmt.Errorf("encoding avatar variants: %w", err)
	}
	return encoded, nil
}

func collectVariantKeys(rows pgx.Rows) ([]string, int64, error) {
	defer rows.Close()
	var keys []string
	var rowCount int64
	for rows.Next() {
		rowCount++
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, fmt.Errorf("scanning avatar variants: %w", err)
		}
		var variants []models.AvatarVariant
		if err := json.Unmarshal(raw, &variants); err != nil {
			return nil, 0, fmt.Errorf("decoding avatar variants: %w", err)
		}
		for _, variant := range variants {
			if variant.ObjectKey != "" {
				keys = append(keys, variant.ObjectKey)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("reading avatar variants: %w", err)
	}
	return keys, rowCount, nil
}

func collectCleanupItems(rows pgx.Rows) ([]CleanupItem, int64, error) {
	defer rows.Close()
	items := make([]CleanupItem, 0)
	for rows.Next() {
		var item CleanupItem
		var raw []byte
		if err := rows.Scan(&item.AvatarID, &item.StorageBackend, &item.StorageProfileID, &raw); err != nil {
			return nil, 0, fmt.Errorf("scanning avatar cleanup candidate: %w", err)
		}
		var variants []models.AvatarVariant
		if err := json.Unmarshal(raw, &variants); err != nil {
			return nil, 0, fmt.Errorf("decoding avatar cleanup variants: %w", err)
		}
		for _, variant := range variants {
			if variant.ObjectKey != "" {
				item.ObjectKeys = append(item.ObjectKeys, variant.ObjectKey)
			}
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("reading avatar cleanup candidates: %w", err)
	}
	return items, int64(len(items)), nil
}

func scanJobs(rows pgx.Rows) ([]models.ProviderAvatarImportJob, error) {
	var jobs []models.ProviderAvatarImportJob
	for rows.Next() {
		var job models.ProviderAvatarImportJob
		if err := rows.Scan(
			&job.ID, &job.ProviderID, &job.UserID, &job.EncryptedAvatarURL, &job.Status,
			&job.AttemptCount, &job.AvailableAt, &job.LockedAt, &job.LockedBy, &job.CompletedAt,
			&job.FailedAt, &job.LastError, &job.CreatedAt, &job.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning provider avatar import job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading provider avatar import jobs: %w", err)
	}
	return jobs, nil
}

func trimError(reason string) string {
	if reason == "" {
		return "avatar operation failed"
	}
	const max = 512
	if len(reason) <= max {
		return reason
	}
	return reason[:max]
}

func validVariantSize(size int) bool {
	for _, candidate := range VariantSizes {
		if size == candidate {
			return true
		}
	}
	return false
}

func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrNotFound)
}
