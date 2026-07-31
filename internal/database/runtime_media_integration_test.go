package database_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/avatar"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mediaruntime"
	"github.com/nyasharp/nyauth/pkg/models"
)

var runtimeMediaTestKey = []byte("abcdef0123456789abcdef0123456789")

func runtimeMediaAudit(event string, actorID uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{
		Event: event, ActorID: actorID, ActorName: "media-admin", Result: "success", RiskLevel: "critical",
		IPAddress: "192.0.2.20", UserAgent: "runtime-media-integration-test",
	}
}

func TestRuntimeMediaCandidateEncryptionAndMigrationStateMachine(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("migrate runtime media schema: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	actorID, userID := uuid.New(), uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source) VALUES
		($1,$2,'active','admin','legacy'),($3,$4,'active','user','legacy')
	`, actorID, "media-admin-"+strings.ReplaceAll(actorID.String(), "-", ""), userID, "media-user-"+strings.ReplaceAll(userID.String(), "-", "")); err != nil {
		t.Fatalf("insert media users: %v", err)
	}

	store, err := mediaruntime.NewStore(schema.pool, "primary", map[string][]byte{"primary": runtimeMediaTestKey})
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	initial, err := store.LoadState(ctx)
	if err != nil || initial.Revision != 1 || initial.ActiveProfileID != nil {
		t.Fatalf("initial media state=%#v error=%v", initial, err)
	}
	candidate, candidateState, err := store.CreateCandidate(ctx, mediaruntime.CreateCandidateInput{
		ExpectedRevision: initial.Revision,
		Settings:         mediaruntime.ProfileSettings{Endpoint: "https://s3.example.test", Region: "auto", Bucket: "private-media", Prefix: "nyauth", PathStyle: true},
		Credentials:      mediaruntime.Credentials{AccessKeyID: "test-access-id", SecretAccessKey: "test-secret-key", SessionToken: "test-session-token"},
		Audit:            runtimeMediaAudit(models.AuditMediaSettingsSaved, actorID),
	}, true)
	if err != nil {
		t.Fatalf("CreateCandidate() error = %v", err)
	}
	if candidateState.Revision != 2 || !candidate.CredentialsConfigured || !candidate.SessionTokenConfigured {
		t.Fatalf("candidate=%#v state=%#v", candidate, candidateState)
	}
	encoded, _ := json.Marshal(candidate)
	if bytes.Contains(encoded, []byte("test-access-id")) || bytes.Contains(encoded, []byte("test-secret-key")) || bytes.Contains(encoded, []byte("test-session-token")) {
		t.Fatalf("candidate JSON exposed credentials: %s", encoded)
	}
	var encryptedAccess, encryptedSecret, encryptedToken string
	if err := schema.pool.QueryRow(ctx, `SELECT encrypted_access_key_id,encrypted_secret_access_key,encrypted_session_token FROM media_storage_profiles WHERE id=$1`, candidate.ID).Scan(&encryptedAccess, &encryptedSecret, &encryptedToken); err != nil {
		t.Fatalf("read encrypted credentials: %v", err)
	}
	for name, ciphertext := range map[string]string{"access": encryptedAccess, "secret": encryptedSecret, "token": encryptedToken} {
		if ciphertext == "" || strings.Contains(ciphertext, "test-") {
			t.Fatalf("%s credential was not encrypted: %q", name, ciphertext)
		}
	}
	if _, _, err := store.CreateCandidate(ctx, mediaruntime.CreateCandidateInput{ExpectedRevision: 1, Settings: candidate.Settings, Credentials: mediaruntime.Credentials{AccessKeyID: "other", SecretAccessKey: "other"}, Audit: runtimeMediaAudit(models.AuditMediaSettingsSaved, actorID)}, true); !errors.Is(err, mediaruntime.ErrStateConflict) {
		t.Fatalf("stale candidate error=%v", err)
	}

	tested, testedState, err := store.RecordTest(ctx, mediaruntime.TestCandidateInput{ExpectedRevision: candidateState.Revision, ProfileID: candidate.ID, Audit: runtimeMediaAudit(models.AuditMediaSettingsTested, actorID)}, "success", "", "")
	if err != nil || tested.TestResult == nil || *tested.TestResult != "success" {
		t.Fatalf("RecordTest() profile=%#v state=%#v err=%v", tested, testedState, err)
	}

	localStore, err := avatar.NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	avatarService, err := avatar.NewService(avatar.NewRepository(schema.pool), localStore, avatar.NewProcessor())
	if err != nil {
		t.Fatal(err)
	}
	uploaded, err := avatarService.UploadUserAvatar(ctx, userID, bytes.NewReader(squarePNG(t, 64)), time.Now().UTC())
	if err != nil {
		t.Fatalf("upload source avatar: %v", err)
	}

	if _, err := schema.pool.Exec(ctx, `INSERT INTO service_control_pauses(singleton,capability) VALUES(TRUE,'media_writes'); UPDATE service_control_state SET revision=revision+1,internal_reason='runtime media integration test' WHERE singleton=TRUE`); err != nil {
		t.Fatalf("pause media writes: %v", err)
	}
	var controlRevision int64
	if err := schema.pool.QueryRow(ctx, `SELECT revision FROM service_control_state WHERE singleton=TRUE`).Scan(&controlRevision); err != nil {
		t.Fatal(err)
	}
	instanceID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO media_storage_instances(instance_id,version,started_at,heartbeat_at,loaded_revision,prepared_profile_id)
		VALUES($1,'0.4.0-rc.1',NOW(),NOW(),$2,NULL)
	`, instanceID, testedState.Revision); err != nil {
		t.Fatalf("insert unprepared media instance: %v", err)
	}
	if _, _, err := store.StartMigration(ctx, mediaruntime.StartMigrationInput{ExpectedRevision: testedState.Revision, TargetProfileID: &candidate.ID, TargetBackend: "s3", SourceBackend: "local", InstanceID: instanceID, ServiceControlRevision: controlRevision, ServiceControlPrevious: map[string]any{"auto_added_media_writes": true}, Audit: runtimeMediaAudit(models.AuditMediaMigrationStarted, actorID)}); !errors.Is(err, mediaruntime.ErrInstancesNotReady) {
		t.Fatalf("StartMigration() with unprepared instance error=%v", err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE media_storage_instances SET prepared_profile_id=$2 WHERE instance_id=$1`, instanceID, candidate.ID); err != nil {
		t.Fatalf("prepare media instance: %v", err)
	}
	migration, _, err := store.StartMigration(ctx, mediaruntime.StartMigrationInput{ExpectedRevision: testedState.Revision, TargetProfileID: &candidate.ID, TargetBackend: "s3", SourceBackend: "local", InstanceID: instanceID, ServiceControlRevision: controlRevision, ServiceControlPrevious: map[string]any{"auto_added_media_writes": true}, Audit: runtimeMediaAudit(models.AuditMediaMigrationStarted, actorID)})
	if err != nil {
		t.Fatalf("StartMigration() error=%v", err)
	}
	if migration.TotalCount != 1 {
		t.Fatalf("migration total=%d want 1", migration.TotalCount)
	}
	item, err := store.ClaimMigrationItem(ctx, "worker-a", time.Now().UTC())
	if err != nil || item == nil {
		t.Fatalf("ClaimMigrationItem() item=%#v err=%v", item, err)
	}
	if item.AvatarID != uploaded.ID || item.SourceProfileID != nil || item.TargetProfileID == nil || *item.TargetProfileID != candidate.ID || item.TargetBackend != "s3" {
		t.Fatalf("claimed item=%#v", item)
	}
	if err := store.FailItem(ctx, *item, "worker-a", errors.New("simulated target outage"), time.Now().UTC()); err != nil {
		t.Fatalf("FailItem() error=%v", err)
	}
	if active, err := store.ActiveMigrationExists(ctx); err != nil || !active {
		t.Fatalf("failed migration should continue blocking cleanup: active=%v err=%v", active, err)
	}
	if _, _, err := store.CreateCandidate(ctx, mediaruntime.CreateCandidateInput{
		ExpectedRevision: testedState.Revision,
		Settings:         candidate.Settings,
		Credentials:      mediaruntime.Credentials{AccessKeyID: "replacement-access", SecretAccessKey: "replacement-secret"},
		Audit:            runtimeMediaAudit(models.AuditMediaSettingsSaved, actorID),
	}, true); !errors.Is(err, mediaruntime.ErrMigrationActive) {
		t.Fatalf("CreateCandidate() during failed migration error=%v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM service_control_pauses WHERE singleton=TRUE AND capability='media_writes'; UPDATE service_control_state SET revision=revision+1 WHERE singleton=TRUE`); err != nil {
		t.Fatalf("resume media writes before retry: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT revision FROM service_control_state WHERE singleton=TRUE`).Scan(&controlRevision); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetryMigration(ctx, mediaruntime.RetryMigrationInput{MigrationID: migration.ID, ServiceControlRevision: controlRevision, ServiceControlPrevious: map[string]any{"auto_added_media_writes": false}, Audit: runtimeMediaAudit(models.AuditMediaMigrationRetried, actorID)}); !errors.Is(err, mediaruntime.ErrMigrationNotPaused) {
		t.Fatalf("RetryMigration() without media pause error=%v", err)
	}
	if _, err := schema.pool.Exec(ctx, `INSERT INTO service_control_pauses(singleton,capability) VALUES(TRUE,'media_writes'); UPDATE service_control_state SET revision=revision+1 WHERE singleton=TRUE`); err != nil {
		t.Fatalf("pause media writes for retry: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT revision FROM service_control_state WHERE singleton=TRUE`).Scan(&controlRevision); err != nil {
		t.Fatal(err)
	}
	retried, err := store.RetryMigration(ctx, mediaruntime.RetryMigrationInput{MigrationID: migration.ID, ServiceControlRevision: controlRevision, ServiceControlPrevious: map[string]any{"auto_added_media_writes": false}, Audit: runtimeMediaAudit(models.AuditMediaMigrationRetried, actorID)})
	if err != nil || retried.Status != "pending" || retried.ServiceControlRevision == nil || *retried.ServiceControlRevision != controlRevision {
		t.Fatalf("RetryMigration() migration=%#v err=%v", retried, err)
	}
	item, err = store.ClaimMigrationItem(ctx, "worker-a", time.Now().UTC())
	if err != nil || item == nil {
		t.Fatalf("ClaimMigrationItem() after retry item=%#v err=%v", item, err)
	}
	if err := store.MarkItemSwitched(ctx, *item, "worker-a", time.Now().UTC()); err != nil {
		t.Fatalf("MarkItemSwitched() error=%v", err)
	}
	if err := store.CompleteItem(ctx, *item, time.Now().UTC()); err != nil {
		t.Fatalf("CompleteItem() error=%v", err)
	}
	applying, state, ok, err := store.FinalizeMigration(ctx, migration.ID, time.Now().UTC())
	if err != nil || ok || applying.Status != "applying" {
		t.Fatalf("FinalizeMigration() applying=%#v state=%#v ok=%v err=%v", applying, state, ok, err)
	}
	waiting, state, ok, err := store.FinalizeMigration(ctx, migration.ID, time.Now().UTC())
	if err != nil || ok || waiting.Status != "applying" {
		t.Fatalf("FinalizeMigration() waiting=%#v state=%#v ok=%v err=%v", waiting, state, ok, err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE media_storage_instances SET loaded_revision=$2,prepared_profile_id=NULL,heartbeat_at=NOW() WHERE instance_id=$1`, instanceID, state.Revision); err != nil {
		t.Fatalf("apply media revision on instance: %v", err)
	}
	finished, state, ok, err := store.FinalizeMigration(ctx, migration.ID, time.Now().UTC())
	if err != nil || !ok || finished.Status != "completed" {
		t.Fatalf("FinalizeMigration() completed=%#v state=%#v ok=%v err=%v", finished, state, ok, err)
	}
	if state.ActiveProfileID == nil || *state.ActiveProfileID != candidate.ID || state.CandidateProfileID != nil {
		t.Fatalf("final media state=%#v", state)
	}
	var profileID *uuid.UUID
	var backend string
	if err := schema.pool.QueryRow(ctx, `SELECT storage_profile_id,storage_backend FROM user_avatars WHERE id=$1`, uploaded.ID).Scan(&profileID, &backend); err != nil {
		t.Fatal(err)
	}
	if profileID == nil || *profileID != candidate.ID || backend != "s3" {
		t.Fatalf("avatar profile=%v backend=%q", profileID, backend)
	}

	otherInstanceID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO media_storage_instances(instance_id,version,started_at,heartbeat_at,loaded_revision) VALUES($1,'0.4.0-rc.1',NOW(),NOW(),$2)`, otherInstanceID, state.Revision); err != nil {
		t.Fatalf("insert second media instance: %v", err)
	}
	localInput := mediaruntime.StartMigrationInput{ExpectedRevision: state.Revision, TargetBackend: "local", SourceBackend: "s3", InstanceID: instanceID, ServiceControlRevision: controlRevision, ServiceControlPrevious: map[string]any{"auto_added_media_writes": false}, Audit: runtimeMediaAudit(models.AuditMediaMigrationStarted, actorID)}
	if _, _, err := store.StartMigration(ctx, localInput); !errors.Is(err, mediaruntime.ErrFallbackRequiresSingleInstance) {
		t.Fatalf("StartMigration() to local with second instance error=%v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM media_storage_instances WHERE instance_id=$1`, otherInstanceID); err != nil {
		t.Fatalf("remove second media instance: %v", err)
	}

	returnMigration, _, err := store.StartMigration(ctx, localInput)
	if err != nil {
		t.Fatalf("StartMigration() back to local error=%v", err)
	}
	returnItem, err := store.ClaimMigrationItem(ctx, "worker-local", time.Now().UTC())
	if err != nil || returnItem == nil {
		t.Fatalf("ClaimMigrationItem() back to local item=%#v err=%v", returnItem, err)
	}
	if returnItem.SourceProfileID == nil || *returnItem.SourceProfileID != candidate.ID || returnItem.TargetProfileID != nil || returnItem.TargetBackend != "local" {
		t.Fatalf("local migration item=%#v", returnItem)
	}
	if err := store.MarkItemSwitched(ctx, *returnItem, "worker-local", time.Now().UTC()); err != nil {
		t.Fatalf("MarkItemSwitched() back to local error=%v", err)
	}
	if err := store.CompleteItem(ctx, *returnItem, time.Now().UTC()); err != nil {
		t.Fatalf("CompleteItem() back to local error=%v", err)
	}
	_, state, completed, err := store.FinalizeMigration(ctx, returnMigration.ID, time.Now().UTC())
	if err != nil || completed || state.ActiveProfileID != nil {
		t.Fatalf("FinalizeMigration() back to local applying state=%#v completed=%v err=%v", state, completed, err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE media_storage_instances SET loaded_revision=$2,heartbeat_at=NOW() WHERE instance_id=$1`, instanceID, state.Revision); err != nil {
		t.Fatalf("apply local fallback revision: %v", err)
	}
	finishedReturn, state, completed, err := store.FinalizeMigration(ctx, returnMigration.ID, time.Now().UTC())
	if err != nil || !completed || finishedReturn.Status != "completed" || state.ActiveProfileID != nil || state.PreviousProfileID == nil || *state.PreviousProfileID != candidate.ID {
		t.Fatalf("FinalizeMigration() back to local migration=%#v state=%#v completed=%v err=%v", finishedReturn, state, completed, err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT storage_profile_id,storage_backend FROM user_avatars WHERE id=$1`, uploaded.ID).Scan(&profileID, &backend); err != nil {
		t.Fatal(err)
	}
	if profileID != nil || backend != "local" {
		t.Fatalf("avatar after local fallback profile=%v backend=%q", profileID, backend)
	}

	if _, err := schema.pool.Exec(ctx, `UPDATE media_storage_profiles SET bucket='tampered' WHERE id=$1`, candidate.ID); !isPostgresCode(err, "55000") {
		t.Fatalf("immutable profile update error=%v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, actorID); err != nil {
		t.Fatalf("delete profile creator: %v", err)
	}
	var creator *uuid.UUID
	if err := schema.pool.QueryRow(ctx, `SELECT created_by FROM media_storage_profiles WHERE id=$1`, candidate.ID).Scan(&creator); err != nil {
		t.Fatal(err)
	}
	if creator != nil {
		t.Fatalf("profile creator was not detached: %v", creator)
	}
}
