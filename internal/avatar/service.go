package avatar

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

type Service struct {
	repo         *Repository
	resolver     StoreResolver
	processor    Processor
	statusMu     sync.RWMutex
	status       RuntimeStatus
	fallbackOnly bool
}

const avatarCompensationTimeout = 15 * time.Second

type RuntimeStatus struct {
	Backend     StorageBackend `json:"backend"`
	Status      string         `json:"status"`
	Configured  bool           `json:"configured"`
	LastErrorAt *time.Time     `json:"last_error_at,omitempty"`
}

func NewService(repo *Repository, store BlobStore, processor Processor) (*Service, error) {
	service, err := NewRuntimeService(repo, StaticStoreResolver{Store: store}, processor)
	if service != nil {
		service.fallbackOnly = true
	}
	return service, err
}

func NewRuntimeService(repo *Repository, resolver StoreResolver, processor Processor) (*Service, error) {
	if repo == nil || resolver == nil {
		return nil, fmt.Errorf("avatar repository and blob store are required")
	}
	if processor.MaxBytes == 0 {
		processor = NewProcessor()
	}
	current, err := resolver.Current(context.Background())
	if err != nil || current.Store == nil {
		return nil, fmt.Errorf("resolving current avatar storage: %w", err)
	}
	return &Service{repo: repo, resolver: resolver, processor: processor, status: RuntimeStatus{Backend: current.Store.Backend(), Status: "ok", Configured: true}}, nil
}

func (s *Service) RuntimeStatus() RuntimeStatus {
	if s == nil {
		return RuntimeStatus{Status: "not_configured"}
	}
	s.statusMu.RLock()
	status := s.status
	s.statusMu.RUnlock()
	if current, err := s.resolver.Current(context.Background()); err == nil && current.Store != nil {
		status.Backend = current.Store.Backend()
		status.Configured = true
	}
	return status
}

func (s *Service) UploadUserAvatar(ctx context.Context, userID uuid.UUID, input io.Reader, now time.Time) (*models.UserAvatar, error) {
	return s.upload(ctx, userID, SourceUserUpload, input, true, now)
}

func (s *Service) UploadAdminAvatar(ctx context.Context, userID uuid.UUID, input io.Reader, now time.Time) (*models.UserAvatar, error) {
	return s.upload(ctx, userID, SourceAdminUpload, input, true, now)
}

func (s *Service) UploadProviderAvatar(ctx context.Context, userID uuid.UUID, input io.Reader, now time.Time) (*models.UserAvatar, error) {
	return s.upload(ctx, userID, SourceProviderImport, input, false, now)
}

func (s *Service) OpenActiveVariant(ctx context.Context, avatarID uuid.UUID, size int) (BlobObject, error) {
	return s.openActiveVariant(ctx, avatarID, size, "user_avatar")
}

func (s *Service) OpenActiveClientLogoVariant(ctx context.Context, logoID uuid.UUID, size int) (BlobObject, error) {
	return s.openActiveVariant(ctx, logoID, size, "client_logo")
}

func (s *Service) openActiveVariant(ctx context.Context, avatarID uuid.UUID, size int, mediaPurpose string) (BlobObject, error) {
	variant, err := s.repo.GetActiveVariant(ctx, avatarID, size, mediaPurpose)
	if err != nil {
		return BlobObject{}, err
	}
	store, err := s.resolver.Resolve(ctx, variant.StorageProfileID, variant.StorageBackend)
	if err != nil {
		return BlobObject{}, err
	}
	object, err := store.Get(ctx, variant.Variant.ObjectKey)
	if err != nil {
		s.recordStorageResult(err, time.Now().UTC())
		return BlobObject{}, err
	}
	s.recordStorageResult(nil, time.Now().UTC())
	object.ContentType = ContentType
	return object, nil
}

func (s *Service) upload(ctx context.Context, userID uuid.UUID, source Source, input io.Reader, requireSquare bool, now time.Time) (*models.UserAvatar, error) {
	if userID == uuid.Nil {
		return nil, fmt.Errorf("avatar user id is required")
	}
	var processed ProcessedImage
	var err error
	if requireSquare {
		processed, err = s.processor.ProcessUserUpload(input)
	} else {
		processed, err = s.processor.ProcessProviderImage(input)
	}
	if err != nil {
		return nil, err
	}
	storage, err := s.resolver.Current(ctx)
	if err != nil || storage.Store == nil {
		return nil, ErrStorageUnavailable
	}
	avatarID := uuid.New()
	prefix := "avatars/" + userID.String() + "/" + avatarID.String()
	variants := make([]models.AvatarVariant, 0, len(VariantSizes))
	for _, size := range VariantSizes {
		body := processed.Variants[size]
		key := objectKey(prefix, size)
		variants = append(variants, models.AvatarVariant{
			Size:        size,
			ObjectKey:   key,
			ContentType: ContentType,
			Bytes:       int64(len(body)),
		})
	}
	tx, err := s.repo.Begin(ctx)
	if err != nil {
		return nil, err
	}
	params := CreateAvatarParams{
		ID:                avatarID,
		UserID:            &userID,
		MediaPurpose:      "user_avatar",
		Source:            source,
		StorageBackend:    storage.Store.Backend(),
		StorageProfileID:  storage.ProfileID,
		ObjectPrefix:      prefix,
		Variants:          variants,
		ContentSHA256:     processed.SHA256,
		OriginalMediaType: processed.SourceMediaType,
		OriginalWidth:     processed.OriginalWidth,
		OriginalHeight:    processed.OriginalHeight,
	}
	if err := s.repo.CreateStagingTx(ctx, tx, params, now); err != nil {
		_ = tx.Rollback(ctx)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing avatar staging record: %w", err)
	}

	storedKeys := make([]string, 0, len(VariantSizes))
	for _, size := range VariantSizes {
		body := processed.Variants[size]
		key := objectKey(prefix, size)
		if err := storage.Store.Put(ctx, key, body, ContentType); err != nil {
			s.recordStorageResult(err, time.Now().UTC())
			s.compensateFailedUpload(avatarID, storedKeys, err, now)
			return nil, err
		}
		storedKeys = append(storedKeys, key)
	}
	s.recordStorageResult(nil, time.Now().UTC())

	tx, err = s.repo.Begin(ctx)
	if err != nil {
		s.compensateFailedUpload(avatarID, storedKeys, err, now)
		return nil, err
	}
	activate := s.repo.ActivateTx
	if source == SourceProviderImport {
		activate = s.repo.ActivateIfUnsetTx
	}
	if err := activate(ctx, tx, userID, avatarID, now); err != nil {
		_ = tx.Rollback(ctx)
		s.compensateFailedUpload(avatarID, storedKeys, err, now)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		s.compensateFailedUpload(avatarID, storedKeys, err, now)
		return nil, fmt.Errorf("committing avatar upload: %w", err)
	}
	return &models.UserAvatar{
		ID:                avatarID,
		UserID:            userID,
		Source:            source,
		Status:            models.AvatarStatusActive,
		StorageBackend:    storage.Store.Backend(),
		StorageProfileID:  cloneUUID(storage.ProfileID),
		ObjectPrefix:      prefix,
		Variants:          variants,
		ContentSHA256:     processed.SHA256,
		OriginalMediaType: processed.SourceMediaType,
		OriginalWidth:     processed.OriginalWidth,
		OriginalHeight:    processed.OriginalHeight,
		CreatedAt:         now.UTC(),
		UpdatedAt:         now.UTC(),
		ActivatedAt:       ptrTime(now.UTC()),
	}, nil
}

func (s *Service) UploadClientLogo(ctx context.Context, clientID string, input io.Reader, now time.Time) (uuid.UUID, error) {
	if clientID == "" {
		return uuid.Nil, fmt.Errorf("client id is required")
	}
	processed, err := s.processor.ProcessUserUpload(input)
	if err != nil {
		return uuid.Nil, err
	}
	storage, err := s.resolver.Current(ctx)
	if err != nil || storage.Store == nil {
		return uuid.Nil, ErrStorageUnavailable
	}
	logoID := uuid.New()
	prefix := "client-logos/" + clientID + "/" + logoID.String()
	variants := make([]models.AvatarVariant, 0, len(VariantSizes))
	for _, size := range VariantSizes {
		body := processed.Variants[size]
		variants = append(variants, models.AvatarVariant{Size: size, ObjectKey: objectKey(prefix, size), ContentType: ContentType, Bytes: int64(len(body))})
	}
	tx, err := s.repo.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	params := CreateAvatarParams{
		ID: logoID, ClientID: &clientID, MediaPurpose: "client_logo", Source: SourceClientUpload,
		StorageBackend: storage.Store.Backend(), StorageProfileID: storage.ProfileID, ObjectPrefix: prefix,
		Variants: variants, ContentSHA256: processed.SHA256, OriginalMediaType: processed.SourceMediaType,
		OriginalWidth: processed.OriginalWidth, OriginalHeight: processed.OriginalHeight,
	}
	if err := s.repo.CreateStagingTx(ctx, tx, params, now); err != nil {
		_ = tx.Rollback(ctx)
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, fmt.Errorf("committing client logo staging record: %w", err)
	}
	storedKeys := make([]string, 0, len(VariantSizes))
	for _, size := range VariantSizes {
		key := objectKey(prefix, size)
		if err := storage.Store.Put(ctx, key, processed.Variants[size], ContentType); err != nil {
			s.recordStorageResult(err, time.Now().UTC())
			s.compensateFailedUpload(logoID, storedKeys, err, now)
			return uuid.Nil, err
		}
		storedKeys = append(storedKeys, key)
	}
	s.recordStorageResult(nil, time.Now().UTC())
	tx, err = s.repo.Begin(ctx)
	if err != nil {
		s.compensateFailedUpload(logoID, storedKeys, err, now)
		return uuid.Nil, err
	}
	if err := s.repo.ActivateClientLogoTx(ctx, tx, clientID, logoID, now); err != nil {
		_ = tx.Rollback(ctx)
		s.compensateFailedUpload(logoID, storedKeys, err, now)
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		s.compensateFailedUpload(logoID, storedKeys, err, now)
		return uuid.Nil, fmt.Errorf("committing client logo upload: %w", err)
	}
	return logoID, nil
}

func (s *Service) DeleteClientLogo(ctx context.Context, clientID string, now time.Time) (cleanupDeferred bool, err error) {
	tx, err := s.repo.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	items, err := s.repo.DeleteActiveClientLogoTx(ctx, tx, clientID, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing client logo deletion: %w", err)
	}
	err = s.deleteItemsBestEffort(ctx, items)
	s.recordStorageResult(err, time.Now().UTC())
	return err != nil, nil
}

func (s *Service) DeleteUserAvatar(ctx context.Context, userID uuid.UUID, now time.Time) (cleanupDeferred bool, err error) {
	tx, err := s.repo.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	items, err := s.repo.DeleteActiveTx(ctx, tx, userID, now)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("committing avatar deletion: %w", err)
	}
	err = s.deleteItemsBestEffort(ctx, items)
	s.recordStorageResult(err, time.Now().UTC())
	// The database transaction is the user-visible deletion boundary. Failed
	// object removal is deferred to the HA-safe cleanup worker and must not turn
	// an already-committed deletion into a misleading API failure.
	return err != nil, nil
}

func (s *Service) Cleanup(ctx context.Context, now time.Time, olderThan time.Duration, batchSize, maxBatches int) (CleanupResult, error) {
	var result CleanupResult
	var firstErr error
	for _, backend := range []StorageBackend{StorageLocal, StorageS3} {
		partial, err := s.repo.CleanupUnreferenced(ctx, backend, now, olderThan, batchSize, maxBatches)
		if err != nil {
			return result, err
		}
		result.LockAcquired = result.LockAcquired || partial.LockAcquired
		result.Rows += partial.Rows
		result.Batches += partial.Batches
		result.Items = append(result.Items, partial.Items...)
	}
	for _, item := range result.Items {
		if s.fallbackOnly && item.StorageProfileID != nil {
			_ = s.repo.ReleaseCleanupClaim(ctx, item.AvatarID)
			result.Rows--
			continue
		}
		store, resolveErr := s.resolver.Resolve(ctx, item.StorageProfileID, item.StorageBackend)
		if resolveErr != nil {
			_ = s.repo.ReleaseCleanupClaim(ctx, item.AvatarID)
			if firstErr == nil {
				firstErr = resolveErr
			}
			continue
		}
		itemFailed := false
		for _, key := range item.ObjectKeys {
			if err := store.Delete(ctx, key); err != nil {
				itemFailed = true
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if itemFailed {
			if err := s.repo.ReleaseCleanupClaim(ctx, item.AvatarID); err != nil && firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := s.repo.MarkStorageDeleted(ctx, item.AvatarID, now); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.recordStorageResult(firstErr, time.Now().UTC())
	return result, firstErr
}

func (s *Service) deleteBestEffort(ctx context.Context, keys []string) error {
	current, err := s.resolver.Current(ctx)
	if err != nil {
		return err
	}
	return deleteKeys(ctx, current.Store, keys)
}

func (s *Service) deleteItemsBestEffort(ctx context.Context, items []CleanupItem) error {
	var first error
	for _, item := range items {
		store, err := s.resolver.Resolve(ctx, item.StorageProfileID, item.StorageBackend)
		if err == nil {
			err = deleteKeys(ctx, store, item.ObjectKeys)
		}
		if err != nil && first == nil {
			first = err
		}
	}
	return first
}

func deleteKeys(ctx context.Context, store BlobStore, keys []string) error {
	var first error
	for _, key := range keys {
		if err := store.Delete(ctx, key); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (s *Service) compensateFailedUpload(avatarID uuid.UUID, keys []string, cause error, now time.Time) {
	compensationCtx, cancel := context.WithTimeout(context.Background(), avatarCompensationTimeout)
	defer cancel()
	_ = s.repo.MarkFailed(compensationCtx, avatarID, cause.Error(), now)
	_ = s.deleteBestEffort(compensationCtx, keys)
}

func ptrTime(t time.Time) *time.Time { return &t }

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (s *Service) recordStorageResult(err error, now time.Time) {
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if err == nil {
		s.status.Status = "ok"
		s.status.LastErrorAt = nil
		return
	}
	s.status.Status = "degraded"
	value := now.UTC()
	s.status.LastErrorAt = &value
}
