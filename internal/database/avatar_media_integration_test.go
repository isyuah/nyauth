package database_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/pkg/models"
)

type failingDeleteStore struct{}

func (failingDeleteStore) Backend() avatar.StorageBackend { return avatar.StorageLocal }
func (failingDeleteStore) Put(context.Context, string, []byte, string) error {
	return errors.New("unexpected put")
}
func (failingDeleteStore) Get(context.Context, string) (avatar.BlobObject, error) {
	return avatar.BlobObject{}, errors.New("unexpected get")
}
func (failingDeleteStore) Delete(context.Context, string) error {
	return errors.New("object store unavailable")
}

type ownerDeletingStore struct {
	avatar.BlobStore
	onFirstPut func() error
	triggered  bool
}

func (s *ownerDeletingStore) Put(ctx context.Context, key string, contents []byte, contentType string) error {
	if err := s.BlobStore.Put(ctx, key, contents, contentType); err != nil {
		return err
	}
	if !s.triggered {
		s.triggered = true
		return s.onFirstPut()
	}
	return nil
}

func TestAvatarMediaLifecycleAndProviderJobConstraints(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	providerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_providers (id,name,type,client_id,client_secret,enabled,import_avatar)
		VALUES ($1,'github-test','github','client','encrypted',TRUE,TRUE)
	`, providerID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}

	userID := uuid.New()
	identityID := uuid.New()
	job, err := avatar.NewProviderImportJob(bytes.Repeat([]byte{0x42}, 32), "primary", providerID, userID, "https://avatars.githubusercontent.com/u/1", time.Now())
	if err != nil {
		t.Fatalf("NewProviderImportJob() error = %v", err)
	}
	createdUser := &models.User{
		ID: userID, Username: "provider_avatar_user", Status: models.UserStatusActive, Role: "user",
		AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	binding := &models.Identity{
		ID: identityID, UserID: userID, Provider: "github-test", ExternalID: "external-1", Metadata: map[string]string{},
	}
	if err := identity.NewStore(schema.pool).CreateUserAndIdentity(ctx, createdUser, binding, identity.CreateUserAndIdentityOptions{AvatarImportJob: job}); err != nil {
		t.Fatalf("CreateUserAndIdentity() error = %v", err)
	}

	repository := avatar.NewRepository(schema.pool)
	claimedAt := time.Now().UTC()
	claimed, err := repository.ClaimProviderImportJobs(ctx, "worker-a", claimedAt, time.Minute, 10)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("ClaimProviderImportJobs() jobs=%d error=%v", len(claimed), err)
	}
	reclaimed, err := repository.ClaimProviderImportJobs(ctx, "worker-b", claimedAt.Add(2*time.Minute), time.Minute, 10)
	if err != nil || len(reclaimed) != 1 {
		t.Fatalf("reclaim provider avatar job jobs=%d error=%v", len(reclaimed), err)
	}
	if err := repository.CompleteProviderImportJob(ctx, claimed[0].ID, "worker-a", claimed[0].AttemptCount, claimedAt.Add(2*time.Minute)); !errors.Is(err, avatar.ErrNotFound) {
		t.Fatalf("stale worker completion error = %v", err)
	}
	if err := repository.CompleteProviderImportJob(ctx, reclaimed[0].ID, "worker-b", reclaimed[0].AttemptCount, claimedAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("CompleteProviderImportJob() error = %v", err)
	}
	var status, encryptedURL string
	if err := schema.pool.QueryRow(ctx, `SELECT status,encrypted_avatar_url FROM provider_avatar_import_jobs WHERE id=$1`, job.ID).Scan(&status, &encryptedURL); err != nil {
		t.Fatalf("read completed job: %v", err)
	}
	if status != "completed" || encryptedURL != "" {
		t.Fatalf("completed job status=%q encrypted_url=%q", status, encryptedURL)
	}

	store, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore() error = %v", err)
	}
	service, err := avatar.NewService(repository, store, avatar.NewProcessor())
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if _, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC()); err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}
	var avatarID uuid.UUID
	if err := schema.pool.QueryRow(ctx, `SELECT current_avatar_id FROM users WHERE id=$1`, userID).Scan(&avatarID); err != nil {
		t.Fatalf("read current avatar: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID); err != nil {
		t.Fatalf("delete avatar owner: %v", err)
	}
	var ownerID *uuid.UUID
	if err := schema.pool.QueryRow(ctx, `SELECT user_id FROM user_avatars WHERE id=$1`, avatarID).Scan(&ownerID); err != nil {
		t.Fatalf("read orphaned avatar: %v", err)
	}
	if ownerID != nil {
		t.Fatalf("orphaned avatar owner = %v", ownerID)
	}
	result, err := service.Cleanup(ctx, time.Now().UTC().Add(time.Second), 0, 10, 2)
	if err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if !result.LockAcquired || result.Rows != 1 {
		t.Fatalf("cleanup result = %#v", result)
	}
	var storageDeleted bool
	if err := schema.pool.QueryRow(ctx, `SELECT storage_deleted_at IS NOT NULL FROM user_avatars WHERE id=$1`, avatarID).Scan(&storageDeleted); err != nil {
		t.Fatalf("read cleanup confirmation: %v", err)
	}
	if !storageDeleted {
		t.Fatal("avatar storage deletion was not confirmed")
	}
}

func TestAvatarCleanupReleasesFailedClaimForRetry(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_cleanup_retry','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repository := avatar.NewRepository(schema.pool)
	store, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := avatar.NewService(repository, store, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC())
	if err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	failingService, err := avatar.NewService(repository, failingDeleteStore{}, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failingService.Cleanup(ctx, time.Now().UTC().Add(time.Second), 0, 10, 1); err == nil {
		t.Fatal("Cleanup() unexpectedly succeeded with a failing store")
	}
	var claimedAt, deletedAt *time.Time
	if err := schema.pool.QueryRow(ctx, `SELECT cleanup_claimed_at,storage_deleted_at FROM user_avatars WHERE id=$1`, uploaded.ID).Scan(&claimedAt, &deletedAt); err != nil {
		t.Fatalf("read failed cleanup state: %v", err)
	}
	if claimedAt != nil || deletedAt != nil {
		t.Fatalf("failed cleanup state claimed=%v deleted=%v", claimedAt, deletedAt)
	}
	result, err := service.Cleanup(ctx, time.Now().UTC().Add(2*time.Second), 0, 10, 1)
	if err != nil || result.Rows != 1 {
		t.Fatalf("retry cleanup result=%#v error=%v", result, err)
	}
}

func TestAvatarDeleteCommitsLogicalRemovalWhenObjectCleanupIsDeferred(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_delete_deferred','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repository := avatar.NewRepository(schema.pool)
	localStore, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := avatar.NewService(repository, localStore, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC())
	if err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}

	failingService, err := avatar.NewService(repository, failingDeleteStore{}, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	deferred, err := failingService.DeleteUserAvatar(ctx, userID, time.Now().UTC())
	if err != nil || !deferred {
		t.Fatalf("DeleteUserAvatar() deferred=%v error=%v", deferred, err)
	}
	var currentAvatarID *uuid.UUID
	var status string
	var storageDeletedAt *time.Time
	if err := schema.pool.QueryRow(ctx, `SELECT current_avatar_id FROM users WHERE id=$1`, userID).Scan(&currentAvatarID); err != nil {
		t.Fatalf("read user avatar: %v", err)
	}
	if currentAvatarID != nil {
		t.Fatalf("current avatar remains set: %v", currentAvatarID)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT status,storage_deleted_at FROM user_avatars WHERE id=$1`, uploaded.ID).Scan(&status, &storageDeletedAt); err != nil {
		t.Fatalf("read deleted avatar: %v", err)
	}
	if status != "deleted" || storageDeletedAt != nil {
		t.Fatalf("deleted avatar state status=%s storage_deleted_at=%v", status, storageDeletedAt)
	}

	result, err := service.Cleanup(ctx, time.Now().UTC().Add(time.Second), 0, 10, 1)
	if err != nil || result.Rows != 1 {
		t.Fatalf("Cleanup() result=%#v error=%v", result, err)
	}
}

func TestAvatarCleanupClaimLeaseIsIndependentOfObjectAge(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_cleanup_lease','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repository := avatar.NewRepository(schema.pool)
	store, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := avatar.NewService(repository, store, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC())
	if err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}
	if _, err := service.DeleteUserAvatar(ctx, userID, time.Now().UTC()); err != nil {
		t.Fatalf("DeleteUserAvatar() error = %v", err)
	}
	now := time.Now().UTC()
	staleClaim := now.Add(-16 * time.Minute)
	if _, err := schema.pool.Exec(ctx, `UPDATE user_avatars SET updated_at=$2,cleanup_claimed_at=$2 WHERE id=$1`, uploaded.ID, staleClaim); err != nil {
		t.Fatalf("age cleanup claim: %v", err)
	}
	result, err := service.Cleanup(ctx, now, 15*time.Minute, 10, 1)
	if err != nil || result.Rows != 1 {
		t.Fatalf("Cleanup() result=%#v error=%v", result, err)
	}
}

func TestAvatarStorageBackendSwitchRequiresNoRemainingObjects(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_backend_switch','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repository := avatar.NewRepository(schema.pool)
	store, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := avatar.NewService(repository, store, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC()); err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}
	if err := repository.EnsureStorageBackendCompatible(ctx, avatar.StorageLocal); err != nil {
		t.Fatalf("local backend compatibility error = %v", err)
	}
	if err := repository.EnsureStorageBackendCompatible(ctx, avatar.StorageS3); err == nil {
		t.Fatal("S3 backend switch was accepted with local objects")
	}
	if _, err := service.DeleteUserAvatar(ctx, userID, time.Now().UTC()); err != nil {
		t.Fatalf("DeleteUserAvatar() error = %v", err)
	}
	if _, err := service.Cleanup(ctx, time.Now().UTC().Add(time.Second), 0, 10, 1); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if err := repository.EnsureStorageBackendCompatible(ctx, avatar.StorageS3); err != nil {
		t.Fatalf("S3 backend remained blocked after cleanup: %v", err)
	}
}

func TestAvatarActivationFailurePersistsFailedStagingRecord(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_activation_failure','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	repository := avatar.NewRepository(schema.pool)
	localStore, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &ownerDeletingStore{
		BlobStore: localStore,
		onFirstPut: func() error {
			_, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID)
			return err
		},
	}
	service, err := avatar.NewService(repository, store, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC()); err == nil {
		t.Fatal("UploadUserAvatar() unexpectedly succeeded after owner deletion")
	}
	var status string
	var ownerID *uuid.UUID
	if err := schema.pool.QueryRow(ctx, `SELECT status,user_id FROM user_avatars ORDER BY created_at DESC LIMIT 1`).Scan(&status, &ownerID); err != nil {
		t.Fatalf("read failed staging record: %v", err)
	}
	if status != "failed" || ownerID != nil {
		t.Fatalf("failed staging status=%q owner=%v", status, ownerID)
	}
}

func TestProviderAvatarImportCannotOverwriteUserAvatar(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,creation_source) VALUES ($1,'avatar_import_race','legacy')`, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	store, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := avatar.NewService(avatar.NewRepository(schema.pool), store, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	current, err := service.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC())
	if err != nil {
		t.Fatalf("UploadUserAvatar() error = %v", err)
	}
	if _, err := service.UploadProviderAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 96)), time.Now().UTC()); !errors.Is(err, avatar.ErrAvatarAlreadySet) {
		t.Fatalf("UploadProviderAvatar() error = %v", err)
	}
	var currentID uuid.UUID
	if err := schema.pool.QueryRow(ctx, `SELECT current_avatar_id FROM users WHERE id=$1`, userID).Scan(&currentID); err != nil {
		t.Fatalf("read current avatar: %v", err)
	}
	if currentID != current.ID {
		t.Fatalf("current avatar changed from %s to %s", current.ID, currentID)
	}
	var failedImports int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_avatars WHERE user_id=$1 AND source='provider_import' AND status='failed'`, userID).Scan(&failedImports); err != nil {
		t.Fatalf("count failed imports: %v", err)
	}
	if failedImports != 1 {
		t.Fatalf("failed provider imports = %d", failedImports)
	}
}

func squarePNG(t *testing.T, size int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			img.Set(x, y, color.RGBA{R: 0x7a, G: 0x5a, B: 0xff, A: 0xff})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, img); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
