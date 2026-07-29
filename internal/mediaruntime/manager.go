package mediaruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/buildinfo"
	"github.com/nyasharp/nyauth/pkg/models"
)

type snapshot struct {
	state    State
	profiles map[uuid.UUID]Profile
	stores   map[uuid.UUID]avatar.BlobStore
}

type ManagerOptions struct {
	InstanceID             uuid.UUID
	Version                string
	Production             bool
	ReconciliationInterval time.Duration
	OnError                func(error)
	OnMigrationCompleted   func(context.Context, Migration) error
}

type Manager struct {
	store                *Store
	fallback             avatar.BlobStore
	options              ManagerOptions
	snapshot             atomic.Pointer[snapshot]
	loadMu               sync.Mutex
	callbackMu           sync.RWMutex
	onMigrationCompleted func(context.Context, Migration) error
}

func NewManager(store *Store, fallback avatar.BlobStore, options ManagerOptions) (*Manager, error) {
	if store == nil || fallback == nil {
		return nil, ErrStoreUnavailable
	}
	if options.InstanceID == uuid.Nil {
		options.InstanceID = uuid.New()
	}
	if strings.TrimSpace(options.Version) == "" {
		options.Version = buildinfo.Version
	}
	if options.ReconciliationInterval <= 0 {
		options.ReconciliationInterval = 5 * time.Second
	}
	if options.OnError == nil {
		options.OnError = func(err error) { slog.Error("media runtime synchronization failed", "error", err) }
	}
	manager := &Manager{store: store, fallback: fallback, options: options, onMigrationCompleted: options.OnMigrationCompleted}
	manager.snapshot.Store(&snapshot{state: State{}, profiles: map[uuid.UUID]Profile{}, stores: map[uuid.UUID]avatar.BlobStore{}})
	return manager, nil
}

func (m *Manager) SetOnMigrationCompleted(callback func(context.Context, Migration) error) {
	m.callbackMu.Lock()
	defer m.callbackMu.Unlock()
	m.onMigrationCompleted = callback
}

func (m *Manager) ActiveMigration(ctx context.Context) (bool, error) {
	return m.store.ActiveMigrationExists(ctx)
}

func (m *Manager) Load(ctx context.Context) error {
	m.loadMu.Lock()
	defer m.loadMu.Unlock()
	state, err := m.store.LoadState(ctx)
	if err != nil {
		return err
	}
	configs, err := m.store.LoadAllProfileConfigs(ctx)
	if err != nil {
		return err
	}
	stores := make(map[uuid.UUID]avatar.BlobStore, len(configs))
	profiles := make(map[uuid.UUID]Profile, len(configs))
	for _, cfg := range configs {
		store, buildErr := avatar.NewS3Store(ctx, cfg.S3Config())
		if buildErr != nil {
			return fmt.Errorf("building media profile %s: %w", cfg.ID, buildErr)
		}
		stores[cfg.ID] = store
		profiles[cfg.ID] = cfg.Profile
	}
	m.snapshot.Store(&snapshot{state: state, profiles: profiles, stores: stores})
	_, _ = m.store.db.Exec(ctx, `UPDATE media_storage_instances SET heartbeat_at=NOW(),loaded_revision=$2,prepared_profile_id=$3 WHERE instance_id=$1`, m.options.InstanceID, state.Revision, state.CandidateProfileID)
	return nil
}

func (m *Manager) Current(ctx context.Context) (avatar.StoreRef, error) {
	snap := m.snapshot.Load()
	if snap == nil {
		return avatar.StoreRef{}, avatar.ErrStorageUnavailable
	}
	if snap.state.ActiveProfileID == nil {
		return avatar.StoreRef{Store: m.fallback}, nil
	}
	id := *snap.state.ActiveProfileID
	store, ok := snap.stores[id]
	if !ok {
		return avatar.StoreRef{}, avatar.ErrStorageUnavailable
	}
	return avatar.StoreRef{ProfileID: &id, Store: store}, nil
}

func (m *Manager) Resolve(_ context.Context, profileID *uuid.UUID, backend avatar.StorageBackend) (avatar.BlobStore, error) {
	if profileID == nil {
		if m.fallback.Backend() != backend {
			return nil, avatar.ErrStorageUnavailable
		}
		return m.fallback, nil
	}
	snap := m.snapshot.Load()
	if snap == nil {
		return nil, avatar.ErrStorageUnavailable
	}
	store, ok := snap.stores[*profileID]
	if !ok || store.Backend() != backend {
		return nil, avatar.ErrStorageUnavailable
	}
	return store, nil
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	state, err := m.store.LoadState(ctx)
	if err != nil {
		return Status{}, err
	}
	result := Status{Mode: "fallback", Revision: state.Revision, Available: true}
	if state.ActiveProfileID != nil {
		result.Mode = "dynamic"
		p, e := m.store.LoadProfile(ctx, *state.ActiveProfileID)
		if e != nil {
			return Status{}, e
		}
		result.Active = &p
	} else {
		result.Active = &Profile{Backend: string(m.fallback.Backend()), CredentialsConfigured: true}
	}
	if state.CandidateProfileID != nil {
		p, e := m.store.LoadProfile(ctx, *state.CandidateProfileID)
		if e != nil {
			return Status{}, e
		}
		result.Candidate = &p
	}
	if state.PreviousProfileID != nil {
		p, e := m.store.LoadProfile(ctx, *state.PreviousProfileID)
		if e != nil {
			return Status{}, e
		}
		result.Previous = &p
	}
	result.Migration, err = m.store.LoadLatestMigration(ctx)
	return result, err
}

func (m *Manager) CreateCandidate(ctx context.Context, input CreateCandidateInput) (Profile, State, error) {
	profile, state, err := m.store.CreateCandidate(ctx, input, m.options.Production)
	if err == nil {
		err = m.Load(ctx)
	}
	return profile, state, err
}

func (m *Manager) StartMigration(ctx context.Context, input StartMigrationInput) (Migration, State, error) {
	return m.store.StartMigration(ctx, input)
}

func (m *Manager) RetryMigration(ctx context.Context, input RetryMigrationInput) (Migration, error) {
	return m.store.RetryMigration(ctx, input)
}

func (m *Manager) TestCandidate(ctx context.Context, input TestCandidateInput) (Profile, State, error) {
	operationCtx, cancelOperation := context.WithTimeout(ctx, 10*time.Second)
	defer cancelOperation()
	config, err := m.store.LoadProfileConfig(operationCtx, input.ProfileID)
	result, category, safeError := "success", "", ""
	if err == nil {
		var store avatar.BlobStore
		store, err = avatar.NewS3Store(operationCtx, config.S3Config())
		if err == nil {
			payload := []byte("nyauth media storage test " + uuid.NewString())
			key := "runtime-tests/" + uuid.NewString() + ".bin"
			err = store.Put(operationCtx, key, payload, "application/octet-stream")
			if err == nil {
				var object avatar.BlobObject
				object, err = store.Get(operationCtx, key)
				if err == nil {
					var received []byte
					received, err = io.ReadAll(io.LimitReader(object.Body, int64(len(payload)+1)))
					closeErr := object.Body.Close()
					if err == nil {
						err = closeErr
					}
					if err == nil && !bytes.Equal(payload, received) {
						err = fmt.Errorf("test object content mismatch")
					}
				}
			}
			cleanupCtx, cancelCleanup := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
			deleteErr := store.Delete(cleanupCtx, key)
			cancelCleanup()
			if err == nil {
				err = deleteErr
			}
		}
	}
	if err != nil {
		result = "failure"
		category = storageErrorCategory(err)
		safeError = "storage connectivity test failed"
	}
	recordCtx, cancelRecord := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancelRecord()
	profile, state, recordErr := m.store.RecordTest(recordCtx, input, result, category, safeError)
	if recordErr == nil {
		recordErr = m.Load(recordCtx)
	}
	return profile, state, recordErr
}

func (m *Manager) StartSynchronization(ctx context.Context) {
	go m.listen(ctx)
	go m.reconcile(ctx)
	go m.heartbeat(ctx)
	go m.runMigrations(ctx)
}
func (m *Manager) listen(ctx context.Context) {
	for ctx.Err() == nil {
		conn, err := m.store.db.Acquire(ctx)
		if err != nil {
			m.wait(ctx, err)
			continue
		}
		_, err = conn.Exec(ctx, `LISTEN nyauth_media_runtime_changed`)
		if err == nil {
			for ctx.Err() == nil {
				if _, err = conn.Conn().WaitForNotification(ctx); err != nil {
					break
				}
				if e := m.Load(ctx); e != nil {
					m.options.OnError(e)
				}
			}
		}
		conn.Release()
		if ctx.Err() == nil {
			m.wait(ctx, err)
		}
	}
}
func (m *Manager) reconcile(ctx context.Context) {
	ticker := time.NewTicker(m.options.ReconciliationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := m.Load(ctx); err != nil {
				m.options.OnError(err)
			}
		}
	}
}
func (m *Manager) heartbeat(ctx context.Context) {
	started := time.Now().UTC()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	run := func() {
		snap := m.snapshot.Load()
		if snap == nil {
			return
		}
		var prepared *uuid.UUID
		if snap.state.CandidateProfileID != nil {
			v := *snap.state.CandidateProfileID
			prepared = &v
		}
		_, err := m.store.db.Exec(ctx, `INSERT INTO media_storage_instances(instance_id,version,started_at,heartbeat_at,loaded_revision,prepared_profile_id) VALUES($1,$2,$3,NOW(),$4,$5) ON CONFLICT(instance_id) DO UPDATE SET heartbeat_at=NOW(),loaded_revision=EXCLUDED.loaded_revision,prepared_profile_id=EXCLUDED.prepared_profile_id`, m.options.InstanceID, m.options.Version, started, snap.state.Revision, prepared)
		if err != nil && !errors.Is(err, context.Canceled) {
			m.options.OnError(err)
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			_, _ = m.store.db.Exec(context.Background(), `DELETE FROM media_storage_instances WHERE instance_id=$1`, m.options.InstanceID)
			return
		case <-ticker.C:
			run()
		}
	}
}
func (m *Manager) wait(ctx context.Context, err error) {
	if err != nil && !errors.Is(err, context.Canceled) {
		m.options.OnError(err)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func (m *Manager) runMigrations(ctx context.Context) {
	worker := m.options.InstanceID.String()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.migrateOnce(ctx, worker)
		}
	}
}
func (m *Manager) migrateOnce(ctx context.Context, worker string) {
	item, err := m.store.ClaimMigrationItem(ctx, worker, time.Now().UTC())
	if err != nil {
		m.options.OnError(err)
		return
	}
	if item == nil {
		migration, loadErr := m.store.LoadActiveMigration(ctx)
		if loadErr != nil {
			m.options.OnError(loadErr)
			return
		}
		if migration != nil {
			finishedMigration, state, finished, finishErr := m.store.FinalizeMigration(ctx, migration.ID, time.Now().UTC())
			if finishErr != nil {
				m.options.OnError(finishErr)
				return
			}
			if state.Revision > 0 {
				_ = m.Load(ctx)
			}
			if finished {
				m.notifyMigrationCompleted(ctx, finishedMigration)
			}
		}
		return
	}
	source, err := m.Resolve(ctx, item.SourceProfileID, item.SourceBackend)
	if err != nil {
		_ = m.store.FailItem(ctx, *item, worker, err, time.Now().UTC())
		return
	}
	target, err := m.Resolve(ctx, &item.TargetProfileID, avatar.StorageS3)
	if err != nil {
		_ = m.store.FailItem(ctx, *item, worker, err, time.Now().UTC())
		return
	}
	if item.Status != "switched" {
		err = copyAndVerifyVariants(ctx, source, target, item.Variants)
		if err == nil {
			err = m.store.MarkItemSwitched(ctx, *item, worker, time.Now().UTC())
			item.Status = "switched"
		}
	}
	if err == nil {
		for _, variant := range item.Variants {
			if deleteErr := source.Delete(ctx, variant.ObjectKey); deleteErr != nil {
				err = deleteErr
				break
			}
		}
	}
	if err == nil {
		err = m.store.CompleteItem(ctx, *item, time.Now().UTC())
	}
	if err != nil {
		if item.Status == "switched" {
			m.options.OnError(err)
		} else {
			_ = m.store.FailItem(ctx, *item, worker, err, time.Now().UTC())
		}
		return
	}
	migration, state, finished, finishErr := m.store.FinalizeMigration(ctx, item.MigrationID, time.Now().UTC())
	if finishErr != nil {
		m.options.OnError(finishErr)
		return
	}
	if state.Revision > 0 {
		if err := m.Load(ctx); err != nil {
			m.options.OnError(err)
		}
	}
	if finished {
		m.notifyMigrationCompleted(ctx, migration)
	}
}

func copyAndVerifyVariants(ctx context.Context, source, target avatar.BlobStore, variants []models.AvatarVariant) error {
	for _, variant := range variants {
		object, err := source.Get(ctx, variant.ObjectKey)
		if err != nil {
			return err
		}
		body, readErr := io.ReadAll(io.LimitReader(object.Body, variant.Bytes+1))
		closeErr := object.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(body)) != variant.Bytes {
			return fmt.Errorf("source object size mismatch")
		}
		expected := sha256.Sum256(body)
		if err := target.Put(ctx, variant.ObjectKey, body, avatar.ContentType); err != nil {
			return err
		}
		check, err := target.Get(ctx, variant.ObjectKey)
		if err != nil {
			return err
		}
		copied, readErr := io.ReadAll(io.LimitReader(check.Body, variant.Bytes+1))
		closeErr = check.Body.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		actual := sha256.Sum256(copied)
		if len(copied) != len(body) || actual != expected {
			return fmt.Errorf("target object verification failed")
		}
	}
	return nil
}

func (m *Manager) notifyMigrationCompleted(ctx context.Context, migration Migration) {
	m.callbackMu.RLock()
	callback := m.onMigrationCompleted
	m.callbackMu.RUnlock()
	if callback != nil {
		if err := callback(ctx, migration); err != nil {
			m.options.OnError(err)
		}
	}
}
func storageErrorCategory(err error) string {
	value := strings.ToLower(err.Error())
	switch {
	case strings.Contains(value, "credential"), strings.Contains(value, "accessdenied"), strings.Contains(value, "signature"):
		return "authentication"
	case strings.Contains(value, "tls"), strings.Contains(value, "certificate"):
		return "tls"
	case strings.Contains(value, "bucket"), strings.Contains(value, "endpoint"), strings.Contains(value, "region"):
		return "configuration"
	default:
		return "transport"
	}
}
