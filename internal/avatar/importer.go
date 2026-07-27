package avatar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

const providerAvatarURLPurpose = "provider-avatar-import-url"

type ImportPolicy struct {
	Enabled      bool
	AllowedHosts []string
}

type ImportWorkerOptions struct {
	WorkerID   string
	MasterKeys map[string][]byte
	Policy     func(uuid.UUID) (ImportPolicy, bool)
	OnResult   func(context.Context, models.ProviderAvatarImportJob, string, string, time.Duration)
}

type ImportWorker struct {
	repo       *Repository
	service    *Service
	fetcher    *RemoteFetcher
	workerID   string
	masterKeys map[string][]byte
	policy     func(uuid.UUID) (ImportPolicy, bool)
	onResult   func(context.Context, models.ProviderAvatarImportJob, string, string, time.Duration)
}

func NewImportWorker(repo *Repository, service *Service, options ImportWorkerOptions) (*ImportWorker, error) {
	if repo == nil || service == nil || strings.TrimSpace(options.WorkerID) == "" || len(options.MasterKeys) == 0 || options.Policy == nil {
		return nil, fmt.Errorf("avatar import worker configuration is incomplete")
	}
	keys := make(map[string][]byte, len(options.MasterKeys))
	for id, key := range options.MasterKeys {
		keys[id] = append([]byte(nil), key...)
	}
	return &ImportWorker{
		repo: repo, service: service, fetcher: NewRemoteFetcher(), workerID: options.WorkerID,
		masterKeys: keys, policy: options.Policy, onResult: options.OnResult,
	}, nil
}

func NewProviderImportJob(masterKey []byte, keyID string, providerID, userID uuid.UUID, rawURL string, now time.Time) (*models.ProviderAvatarImportJob, error) {
	if providerID == uuid.Nil || userID == uuid.Nil || strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("provider avatar import job is incomplete")
	}
	job := &models.ProviderAvatarImportJob{
		ID: uuid.New(), ProviderID: providerID, UserID: userID,
		Status: models.ProviderAvatarImportPending, AvailableAt: now.UTC(), CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	encrypted, err := internalcrypto.EncryptEnvelope(masterKey, keyID, providerAvatarURLPurpose, []byte(rawURL), providerImportAAD(job.ID, providerID, userID))
	if err != nil {
		return nil, fmt.Errorf("encrypting provider avatar URL: %w", err)
	}
	job.EncryptedAvatarURL = encrypted
	return job, nil
}

func (w *ImportWorker) Run(ctx context.Context) error {
	if err := w.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
		slog.ErrorContext(ctx, "initial provider avatar import batch failed", "error", err)
	}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := w.RunOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
				slog.ErrorContext(ctx, "provider avatar import batch failed", "error", err)
			}
		}
	}
}

func (w *ImportWorker) RunOnce(ctx context.Context) error {
	jobs, err := w.repo.ClaimProviderImportJobs(ctx, w.workerID, time.Now().UTC(), time.Minute, 10)
	if err != nil {
		return err
	}
	var firstErr error
	for _, job := range jobs {
		if err := w.process(ctx, job); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (w *ImportWorker) process(ctx context.Context, job models.ProviderAvatarImportJob) error {
	started := time.Now()
	policy, ok := w.policy(job.ProviderID)
	if !ok || !policy.Enabled || len(policy.AllowedHosts) == 0 {
		return w.finishFailure(ctx, job, permanentImportFailure("policy_disabled", errors.New("provider avatar import policy is unavailable")), started)
	}
	plaintext, err := internalcrypto.DecryptEnvelope(w.masterKeys, providerAvatarURLPurpose, job.EncryptedAvatarURL, providerImportAAD(job.ID, job.ProviderID, job.UserID))
	if err != nil {
		return w.finishFailure(ctx, job, permanentImportFailure("decryption_failed", err), started)
	}
	jobCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	contents, err := w.fetcher.Fetch(jobCtx, string(plaintext), policy.AllowedHosts)
	if err == nil {
		_, err = w.service.UploadProviderAvatar(jobCtx, job.UserID, bytes.NewReader(contents), time.Now().UTC())
	}
	if errors.Is(err, ErrAvatarAlreadySet) {
		if completeErr := w.repo.CompleteProviderImportJob(ctx, job.ID, w.workerID, job.AttemptCount, time.Now().UTC()); completeErr != nil {
			return completeErr
		}
		w.record(ctx, job, "discarded", "avatar_already_set", time.Since(started))
		return nil
	}
	if err != nil {
		return w.finishFailure(ctx, job, classifyImageFailure(err), started)
	}
	if err := w.repo.CompleteProviderImportJob(ctx, job.ID, w.workerID, job.AttemptCount, time.Now().UTC()); err != nil {
		return err
	}
	w.record(ctx, job, "success", "none", time.Since(started))
	return nil
}

func (w *ImportWorker) finishFailure(ctx context.Context, job models.ProviderAvatarImportJob, operationErr error, started time.Time) error {
	if err := ctx.Err(); err != nil {
		// Leave the processing lease intact during shutdown. Another instance can
		// reclaim the job after the lease expires without consuming an attempt as
		// a permanent failure.
		return err
	}
	now := time.Now().UTC()
	reason := importFailureReason(operationErr)
	retryAt := providerImportRetryAt(operationErr, job.AttemptCount, now)
	if err := w.repo.FailProviderImportJob(ctx, job.ID, w.workerID, job.AttemptCount, reason, retryAt, now); err != nil {
		return err
	}
	result := "failure"
	if retryAt != nil {
		result = "retry"
	}
	w.record(ctx, job, result, reason, time.Since(started))
	return nil
}

func providerImportRetryAt(operationErr error, attemptCount int, now time.Time) *time.Time {
	var permanent *permanentImportError
	if errors.As(operationErr, &permanent) || attemptCount >= 4 {
		return nil
	}
	retryIndex := attemptCount - 1
	if retryIndex < 0 {
		retryIndex = 0
	}
	delays := [...]time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}
	if retryIndex >= len(delays) {
		return nil
	}
	next := now.Add(delays[retryIndex])
	return &next
}

func classifyImageFailure(err error) error {
	if err == nil {
		return nil
	}
	var permanent *permanentImportError
	if errors.As(err, &permanent) {
		return err
	}
	if errors.Is(err, ErrImageTooLarge) || errors.Is(err, ErrUnsupportedMedia) || errors.Is(err, ErrAnimatedWebP) || errors.Is(err, ErrInvalidDimensions) {
		return permanentImportFailure("invalid_image", err)
	}
	return err
}

func importFailureReason(err error) string {
	var permanent *permanentImportError
	if errors.As(err, &permanent) {
		return permanent.reason
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	return "remote_or_storage_unavailable"
}

func (w *ImportWorker) record(ctx context.Context, job models.ProviderAvatarImportJob, result, reason string, duration time.Duration) {
	if w.onResult != nil {
		w.onResult(ctx, job, result, reason, duration)
	}
}

func providerImportAAD(jobID, providerID, userID uuid.UUID) []byte {
	return []byte(jobID.String() + "\x00" + providerID.String() + "\x00" + userID.String())
}
