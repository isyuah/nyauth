package database_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/observabilityruntime"
)

var runtimeObservabilityKey = []byte("0123456789abcdef0123456789abcdef")

func observabilityAudit(event string, actor uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{Event: event, ActorID: actor, ActorName: "telemetry-admin", Result: "success", RiskLevel: "high"}
}

func TestRuntimeOTLPConfigurationLifecycleEncryptionAndHistory(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	actor := uuid.New()
	if _, err := schema.pool.Exec(t.Context(), `INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,$2,'active','admin','legacy')`, actor, "telemetry-"+strings.ReplaceAll(actor.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	store, err := observabilityruntime.NewStore(schema.pool, observabilityruntime.StoreOptions{ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": runtimeObservabilityKey}, Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	fallback := &observabilityruntime.Config{Settings: observabilityruntime.Settings{Endpoint: "https://fallback.example.test/v1/metrics", ExportInterval: 30 * time.Second, Timeout: 5 * time.Second}, Authorization: "Bearer fallback-secret"}
	initial, err := store.LoadState(t.Context())
	if err != nil || initial.Mode != observabilityruntime.ModeFallback || initial.Revision != 0 {
		t.Fatalf("initial=%#v err=%v", initial, err)
	}

	first, err := store.CreateCandidate(t.Context(), observabilityruntime.CreateCandidateInput{ExpectedRevision: 0, Settings: observabilityruntime.Settings{Endpoint: "https://collector-a.example.test/v1/metrics", ExportInterval: 20 * time.Second, Timeout: 4 * time.Second}, Fallback: fallback, Audit: observabilityAudit(observabilityruntime.AuditSettingsSaved, actor)})
	if err != nil {
		t.Fatal(err)
	}
	var ciphertext *string
	if err := schema.pool.QueryRow(t.Context(), `SELECT authorization_ciphertext FROM otlp_config_versions WHERE id=$1`, first.Version.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if ciphertext == nil || strings.Contains(*ciphertext, "fallback-secret") {
		t.Fatalf("authorization was not encrypted: %v", ciphertext)
	}
	_, firstConfig, err := store.LoadVersionConfig(t.Context(), first.Version.ID)
	if err != nil || firstConfig.Authorization != fallback.Authorization {
		t.Fatalf("decrypted config=%#v err=%v", firstConfig, err)
	}
	if _, err := store.Activate(t.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: first.State.Revision, VersionID: first.Version.ID, Audit: observabilityAudit(observabilityruntime.AuditSettingsActivated, actor)}); !errors.Is(err, observabilityruntime.ErrCandidateTestRequired) {
		t.Fatalf("activation without test error=%v", err)
	}

	tested, err := store.RecordTest(t.Context(), observabilityruntime.RecordTestInput{ExpectedRevision: first.State.Revision, VersionID: first.Version.ID, Result: observabilityruntime.TestSuccess, Audit: observabilityAudit(observabilityruntime.AuditSettingsTested, actor)})
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.LoadLatestTest(t.Context(), first.Version.ID)
	if err != nil || latest == nil || latest.Result != observabilityruntime.TestSuccess || latest.Revision == 0 {
		t.Fatalf("latest successful test=%#v err=%v", latest, err)
	}
	failureCode := observabilityruntime.TestErrorConnectionOrCollectorRejected
	failed, err := store.RecordTest(t.Context(), observabilityruntime.RecordTestInput{ExpectedRevision: tested.State.Revision, VersionID: first.Version.ID, Result: observabilityruntime.TestFailure, ErrorCode: &failureCode, Audit: observabilityAudit(observabilityruntime.AuditSettingsTested, actor)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Activate(t.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: failed.State.Revision, VersionID: first.Version.ID, Audit: observabilityAudit(observabilityruntime.AuditSettingsActivated, actor)}); !errors.Is(err, observabilityruntime.ErrCandidateTestRequired) {
		t.Fatalf("activation after latest failed test error=%v", err)
	}
	retested, err := store.RecordTest(t.Context(), observabilityruntime.RecordTestInput{ExpectedRevision: failed.State.Revision, VersionID: first.Version.ID, Result: observabilityruntime.TestSuccess, Audit: observabilityAudit(observabilityruntime.AuditSettingsTested, actor)})
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.Activate(t.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: retested.State.Revision, VersionID: first.Version.ID, Audit: observabilityAudit(observabilityruntime.AuditSettingsActivated, actor)})
	if err != nil || active.Mode != observabilityruntime.ModeActive {
		t.Fatalf("active=%#v err=%v", active, err)
	}

	secondAuth := "Bearer second-secret"
	second, err := store.CreateCandidate(t.Context(), observabilityruntime.CreateCandidateInput{ExpectedRevision: active.Revision, Settings: observabilityruntime.Settings{Endpoint: "https://collector-b.example.test/v1/metrics", ExportInterval: time.Minute, Timeout: 10 * time.Second}, Authorization: &secondAuth, Audit: observabilityAudit(observabilityruntime.AuditSettingsSaved, actor)})
	if err != nil {
		t.Fatal(err)
	}
	secondTest, err := store.RecordTest(t.Context(), observabilityruntime.RecordTestInput{ExpectedRevision: second.State.Revision, VersionID: second.Version.ID, Result: observabilityruntime.TestSuccess, Audit: observabilityAudit(observabilityruntime.AuditSettingsTested, actor)})
	if err != nil {
		t.Fatal(err)
	}
	secondActive, err := store.Activate(t.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: secondTest.State.Revision, VersionID: second.Version.ID, Audit: observabilityAudit(observabilityruntime.AuditSettingsActivated, actor)})
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := store.Rollback(t.Context(), observabilityruntime.StateMutationInput{ExpectedRevision: secondActive.Revision, Audit: observabilityAudit(observabilityruntime.AuditSettingsRolledBack, actor)})
	if err != nil || rolledBack.ActiveVersionID == nil || *rolledBack.ActiveVersionID != first.Version.ID {
		t.Fatalf("rollback=%#v err=%v", rolledBack, err)
	}
	disabled, err := store.Disable(t.Context(), observabilityruntime.StateMutationInput{ExpectedRevision: rolledBack.Revision, Audit: observabilityAudit(observabilityruntime.AuditSettingsDisabled, actor)})
	if err != nil || disabled.Mode != observabilityruntime.ModeDisabled {
		t.Fatalf("disabled=%#v err=%v", disabled, err)
	}

	if _, err := schema.pool.Exec(t.Context(), `UPDATE otlp_config_versions SET endpoint='https://attacker.example.test' WHERE id=$1`, first.Version.ID); err == nil {
		t.Fatal("append-only version was modified")
	}
	if _, err := schema.pool.Exec(t.Context(), `DELETE FROM users WHERE id=$1`, actor); err != nil {
		t.Fatalf("delete creator: %v", err)
	}
	var createdBy *uuid.UUID
	if err := schema.pool.QueryRow(t.Context(), `SELECT created_by FROM otlp_config_versions WHERE id=$1`, first.Version.ID).Scan(&createdBy); err != nil || createdBy != nil {
		t.Fatalf("created_by=%v err=%v", createdBy, err)
	}
	var auditCount int
	if err := schema.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_event_outbox WHERE event LIKE 'telemetry.%'`).Scan(&auditCount); err != nil || auditCount != 10 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
}

func TestRuntimeOTLPManagerReconcilesEffectiveExporter(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	if _, err := schema.pool.Exec(t.Context(), `INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,$2,'active','admin','legacy')`, actor, "telemetry-sync-"+strings.ReplaceAll(actor.String(), "-", "")); err != nil {
		t.Fatal(err)
	}
	store, err := observabilityruntime.NewStore(schema.pool, observabilityruntime.StoreOptions{ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": runtimeObservabilityKey}})
	if err != nil {
		t.Fatal(err)
	}
	fallback := &observabilityruntime.Config{Settings: observabilityruntime.Settings{Endpoint: "https://fallback.example.test/v1/metrics", ExportInterval: 30 * time.Second, Timeout: 5 * time.Second}}
	applied := make(chan string, 8)
	manager, err := observabilityruntime.NewManager(store, observabilityruntime.ManagerOptions{
		Fallback: fallback, ReconciliationInterval: 25 * time.Millisecond,
		Apply: func(_ context.Context, config *observabilityruntime.Config) error {
			if config == nil {
				applied <- "disabled"
			} else {
				applied <- config.Endpoint
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := <-applied; got != fallback.Endpoint {
		t.Fatalf("initial apply=%q", got)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	manager.StartSynchronization(ctx)
	authorization := "Bearer active"
	candidate, err := manager.CreateCandidate(t.Context(), observabilityruntime.CreateCandidateInput{ExpectedRevision: 0, Settings: observabilityruntime.Settings{Endpoint: "https://active.example.test/v1/metrics", ExportInterval: 20 * time.Second, Timeout: 3 * time.Second}, Authorization: &authorization, Audit: observabilityAudit(observabilityruntime.AuditSettingsSaved, actor)})
	if err != nil {
		t.Fatal(err)
	}
	tested, err := manager.RecordTest(t.Context(), observabilityruntime.RecordTestInput{ExpectedRevision: candidate.State.Revision, VersionID: candidate.Version.ID, Result: observabilityruntime.TestSuccess, Audit: observabilityAudit(observabilityruntime.AuditSettingsTested, actor)})
	if err != nil {
		t.Fatal(err)
	}
	active, err := manager.Activate(t.Context(), observabilityruntime.VersionMutationInput{ExpectedRevision: tested.State.Revision, VersionID: candidate.Version.ID, Audit: observabilityAudit(observabilityruntime.AuditSettingsActivated, actor)})
	if err != nil {
		t.Fatal(err)
	}
	waitApplied := func(want string) {
		t.Helper()
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for {
			select {
			case got := <-applied:
				if got == want {
					return
				}
			case <-timer.C:
				t.Fatalf("timed out waiting for apply %q", want)
			}
		}
	}
	waitApplied(candidate.Version.Endpoint)
	if _, err := manager.Disable(t.Context(), observabilityruntime.StateMutationInput{ExpectedRevision: active.Revision, Audit: observabilityAudit(observabilityruntime.AuditSettingsDisabled, actor)}); err != nil {
		t.Fatal(err)
	}
	waitApplied("disabled")
}
