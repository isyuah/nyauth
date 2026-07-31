package database_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/humanverification"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

var humanVerificationTestKey = []byte("0123456789abcdef0123456789abcdef")

func TestHumanVerificationMigrationUpgradesSchemaNine(t *testing.T) {
	schema := newPostgresTestSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create migration runner: %v", err)
	}
	defer func() {
		if sourceErr, databaseErr := runner.Close(); sourceErr != nil || databaseErr != nil {
			t.Errorf("close migration runner: source=%v database=%v", sourceErr, databaseErr)
		}
	}()
	if err := runner.Migrate(9); err != nil {
		t.Fatalf("migrate isolated schema to version 9: %v", err)
	}

	ctx := context.Background()
	var version int
	if err := schema.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatalf("read schema version 9: %v", err)
	}
	if version != 9 {
		t.Fatalf("schema version before upgrade = %d, want 9", version)
	}
	if _, err := schema.pool.Exec(ctx, `SELECT 1 FROM human_verification_runtime_state`); err == nil {
		t.Fatal("human verification state exists before migration 10")
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade isolated schema from 9 to 10: %v", err)
	}
	if err := database.ValidateSchemaVersion(ctx, schema.pool); err != nil {
		t.Fatalf("validate upgraded schema: %v", err)
	}
	var mode string
	var revision int64
	var loginMode string
	var loginTriggerAfter int
	var registration, passwordReset, emailVerificationResend, providerLogin bool
	if err := schema.pool.QueryRow(ctx, `
		SELECT mode,revision,
			policy->>'login_mode',
			(policy->>'login_trigger_after')::integer,
			(policy->>'registration')::boolean,
			(policy->>'password_reset')::boolean,
			(policy->>'email_verification_resend')::boolean,
			(policy->>'provider_login')::boolean
		FROM human_verification_runtime_state WHERE singleton=TRUE
	`).Scan(&mode, &revision, &loginMode, &loginTriggerAfter, &registration, &passwordReset, &emailVerificationResend, &providerLogin); err != nil {
		t.Fatalf("read migrated human verification state: %v", err)
	}
	if mode != humanverification.ModeDisabled || revision != 1 {
		t.Fatalf("migrated human verification state = mode %q revision %d", mode, revision)
	}
	if !registration || loginMode != humanverification.LoginAdaptive || loginTriggerAfter != 3 ||
		!passwordReset || !emailVerificationResend || !providerLogin {
		t.Fatalf("migrated human verification policy = registration=%t login_mode=%q trigger=%d password_reset=%t email_resend=%t provider_login=%t",
			registration, loginMode, loginTriggerAfter, passwordReset, emailVerificationResend, providerLogin)
	}
}

func newHumanVerificationStore(t *testing.T) (*postgresTestSchema, *humanverification.Store, uuid.UUID, *time.Time) {
	t.Helper()
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("migrate human verification schema: %v", err)
	}
	actorID := uuid.New()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,email,email_verified_at,status,role,creation_source)
		VALUES ($1,$2,$3,NOW(),'active','admin','legacy')
	`, actorID, "human-admin-"+strings.ReplaceAll(actorID.String(), "-", ""), "human-admin@example.test"); err != nil {
		t.Fatalf("insert human verification actor: %v", err)
	}
	now := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	store, err := humanverification.NewStore(schema.pool, humanverification.StoreOptions{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": humanVerificationTestKey},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create human verification store: %v", err)
	}
	return schema, store, actorID, &now
}

func humanVerificationAudit(event string, actorID uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{
		Event: event, ActorID: actorID, ActorName: "human-admin", Result: "success", RiskLevel: "high",
		IPAddress: "192.0.2.40", UserAgent: "human-verification-integration-test",
	}
}

func createHumanVerificationCandidate(
	t *testing.T, store *humanverification.Store, actorID uuid.UUID, revision int64, siteKey string, secret *string,
) humanverification.CandidateResult {
	t.Helper()
	result, err := store.CreateCandidate(context.Background(), humanverification.CreateCandidateInput{
		ExpectedRevision: revision,
		Settings: humanverification.Settings{
			Provider: humanverification.ProviderTurnstile, SiteKey: siteKey, WidgetMode: humanverification.WidgetManaged,
		},
		Secret: secret, Audit: humanVerificationAudit(humanverification.AuditSettingsSaved, actorID),
	})
	if err != nil {
		t.Fatalf("create human verification candidate: %v", err)
	}
	return result
}

func recordHumanVerificationTest(
	t *testing.T, store *humanverification.Store, actorID uuid.UUID, revision int64, versionID uuid.UUID, result string,
) humanverification.TestResult {
	t.Helper()
	var errorCode *string
	if result == humanverification.TestFailure {
		value := "invalid-input-response"
		errorCode = &value
	}
	recorded, err := store.RecordTest(context.Background(), humanverification.RecordTestInput{
		ExpectedRevision: revision, VersionID: versionID, Result: result, ErrorCode: errorCode,
		Audit: humanVerificationAudit(humanverification.AuditSettingsTested, actorID),
	})
	if err != nil {
		t.Fatalf("record human verification test: %v", err)
	}
	return recorded
}

func TestHumanVerificationRuntimeLifecycleAndEncryptedSecret(t *testing.T) {
	schema, store, actorID, now := newHumanVerificationStore(t)
	ctx := context.Background()
	state, err := store.LoadState(ctx)
	if err != nil || state.Mode != humanverification.ModeDisabled || state.Revision != 1 {
		t.Fatalf("initial state = %#v, %v", state, err)
	}
	_, err = store.Enable(ctx, humanverification.StateMutationInput{
		ExpectedRevision: state.Revision, Audit: humanVerificationAudit(humanverification.AuditSettingsEnabled, actorID),
	})
	if !errors.Is(err, humanverification.ErrNoActiveVersion) {
		t.Fatalf("enable without retained configuration error = %v", err)
	}

	secret := "turnstile-secret-one"
	first := createHumanVerificationCandidate(t, store, actorID, state.Revision, "site-key-one", &secret)
	var ciphertext string
	if err := schema.pool.QueryRow(ctx, `SELECT secret_ciphertext FROM human_verification_config_versions WHERE id=$1`, first.Version.ID).Scan(&ciphertext); err != nil {
		t.Fatalf("read encrypted secret: %v", err)
	}
	if strings.Contains(ciphertext, secret) {
		t.Fatal("human verification secret was stored in plaintext")
	}
	_, config, err := store.LoadVersionConfig(ctx, first.Version.ID)
	if err != nil || config.Secret != secret {
		t.Fatalf("decrypted config = %#v, %v", config, err)
	}

	policy := humanverification.Policy{Registration: true, LoginMode: humanverification.LoginAdaptive, LoginTriggerAfter: 3}
	_, err = store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: first.State.Revision, VersionID: first.Version.ID, Policy: policy,
		Audit: humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if !errors.Is(err, humanverification.ErrCandidateTestRequired) {
		t.Fatalf("activation without test error = %v", err)
	}
	failed := recordHumanVerificationTest(t, store, actorID, first.State.Revision, first.Version.ID, humanverification.TestFailure)
	_, err = store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: failed.State.Revision, VersionID: first.Version.ID, Policy: policy,
		Audit: humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if !errors.Is(err, humanverification.ErrCandidateTestRequired) {
		t.Fatalf("activation after failed test error = %v", err)
	}
	succeeded := recordHumanVerificationTest(t, store, actorID, failed.State.Revision, first.Version.ID, humanverification.TestSuccess)
	active, err := store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: succeeded.State.Revision, VersionID: first.Version.ID, Policy: policy,
		Audit: humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if err != nil || active.Mode != humanverification.ModeActive || active.ActiveVersionID == nil || *active.ActiveVersionID != first.Version.ID {
		t.Fatalf("activated state = %#v, %v", active, err)
	}

	second := createHumanVerificationCandidate(t, store, actorID, active.Revision, "site-key-two", nil)
	_, inherited, err := store.LoadVersionConfig(ctx, second.Version.ID)
	if err != nil || inherited.Secret != secret {
		t.Fatalf("inherited secret = %q, %v", inherited.Secret, err)
	}
	secondTest := recordHumanVerificationTest(t, store, actorID, second.State.Revision, second.Version.ID, humanverification.TestSuccess)
	secondActive, err := store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: secondTest.State.Revision, VersionID: second.Version.ID, Policy: policy,
		Audit: humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if err != nil || secondActive.PreviousVersionID == nil || *secondActive.PreviousVersionID != first.Version.ID {
		t.Fatalf("second activation = %#v, %v", secondActive, err)
	}
	rolledBack, err := store.Rollback(ctx, humanverification.StateMutationInput{
		ExpectedRevision: secondActive.Revision, Audit: humanVerificationAudit(humanverification.AuditSettingsRolledBack, actorID),
	})
	if err != nil || rolledBack.ActiveVersionID == nil || *rolledBack.ActiveVersionID != first.Version.ID {
		t.Fatalf("rollback state = %#v, %v", rolledBack, err)
	}
	disabled, err := store.Disable(ctx, humanverification.StateMutationInput{
		ExpectedRevision: rolledBack.Revision, Audit: humanVerificationAudit(humanverification.AuditSettingsDisabled, actorID),
	})
	if err != nil || disabled.Mode != humanverification.ModeDisabled || disabled.ActiveVersionID == nil || *disabled.ActiveVersionID != first.Version.ID || disabled.PreviousVersionID == nil {
		t.Fatalf("disabled state = %#v, %v", disabled, err)
	}
	effective, err := store.LoadEffectiveConfig(ctx)
	if err != nil || !effective.Configured || !effective.Available || effective.Version == nil || effective.Version.ID != first.Version.ID {
		t.Fatalf("disabled effective config = %#v, %v", effective, err)
	}
	enabled, err := store.Enable(ctx, humanverification.StateMutationInput{
		ExpectedRevision: disabled.Revision, Audit: humanVerificationAudit(humanverification.AuditSettingsEnabled, actorID),
	})
	if err != nil || enabled.Mode != humanverification.ModeActive || enabled.ActiveVersionID == nil || *enabled.ActiveVersionID != first.Version.ID {
		t.Fatalf("re-enabled state = %#v, %v", enabled, err)
	}
	_, err = store.Enable(ctx, humanverification.StateMutationInput{
		ExpectedRevision: enabled.Revision, Audit: humanVerificationAudit(humanverification.AuditSettingsEnabled, actorID),
	})
	if !errors.Is(err, humanverification.ErrAlreadyEnabled) {
		t.Fatalf("repeated enable error = %v", err)
	}

	*now = now.Add(11 * time.Minute)
	third := createHumanVerificationCandidate(t, store, actorID, enabled.Revision, "site-key-three", nil)
	thirdTest := recordHumanVerificationTest(t, store, actorID, third.State.Revision, third.Version.ID, humanverification.TestSuccess)
	*now = now.Add(humanverification.CandidateTestValidity + time.Second)
	_, err = store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: thirdTest.State.Revision, VersionID: third.Version.ID, Policy: policy,
		Audit: humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if !errors.Is(err, humanverification.ErrCandidateTestExpired) {
		t.Fatalf("expired candidate test error = %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE human_verification_config_versions SET site_key='tampered' WHERE id=$1`, first.Version.ID); err == nil {
		t.Fatal("append-only human verification version accepted an update")
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM human_verification_config_versions WHERE id=$1`, first.Version.ID); err == nil {
		t.Fatal("append-only human verification version accepted a delete")
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, actorID); err != nil {
		t.Fatalf("delete human verification configuration creator: %v", err)
	}
	var retainedVersions, retainedTests int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM human_verification_config_versions WHERE created_by IS NULL`).Scan(&retainedVersions); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM human_verification_config_tests WHERE tested_by IS NULL`).Scan(&retainedTests); err != nil {
		t.Fatal(err)
	}
	if retainedVersions != 3 || retainedTests != 4 {
		t.Fatalf("retained history: versions=%d tests=%d", retainedVersions, retainedTests)
	}

	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox WHERE event LIKE 'human_verification.%'
	`).Scan(&auditCount); err != nil {
		t.Fatalf("count human verification audit outbox: %v", err)
	}
	if auditCount != 12 {
		t.Fatalf("human verification audit count = %d, want 12", auditCount)
	}
}

func TestHumanVerificationCandidateCASAllowsOneConcurrentWinner(t *testing.T) {
	schema, store, actorID, _ := newHumanVerificationStore(t)
	state, err := store.LoadState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	secret := "turnstile-concurrent-secret"
	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, err := store.CreateCandidate(context.Background(), humanverification.CreateCandidateInput{
				ExpectedRevision: state.Revision,
				Settings: humanverification.Settings{
					Provider: humanverification.ProviderTurnstile,
					SiteKey:  "concurrent-site-" + string(rune('a'+index)), WidgetMode: humanverification.WidgetManaged,
				},
				Secret: &secret, Audit: humanVerificationAudit(humanverification.AuditSettingsSaved, actorID),
			})
			errorsByWriter <- err
		}(index)
	}
	close(start)
	wait.Wait()
	close(errorsByWriter)
	successes, conflicts := 0, 0
	for err := range errorsByWriter {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, humanverification.ErrStateConflict):
			conflicts++
		default:
			t.Fatalf("unexpected concurrent candidate error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent results: successes=%d conflicts=%d", successes, conflicts)
	}
	var versionCount int
	if err := schema.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM human_verification_config_versions`).Scan(&versionCount); err != nil {
		t.Fatal(err)
	}
	if versionCount != 1 {
		t.Fatalf("candidate version count = %d, want 1", versionCount)
	}
}

func TestHumanVerificationRecoveryDisableIsAtomicAndIdempotent(t *testing.T) {
	schema, store, actorID, now := newHumanVerificationStore(t)
	ctx := context.Background()
	initial, err := store.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secret := "turnstile-recovery-secret"
	candidate := createHumanVerificationCandidate(t, store, actorID, initial.Revision, "recovery-site", &secret)
	tested := recordHumanVerificationTest(t, store, actorID, candidate.State.Revision, candidate.Version.ID, humanverification.TestSuccess)
	active, err := store.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: tested.State.Revision, VersionID: candidate.Version.ID,
		Policy: humanverification.Policy{LoginMode: humanverification.LoginAlways, LoginTriggerAfter: 3},
		Audit:  humanVerificationAudit(humanverification.AuditSettingsActivated, actorID),
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := humanverification.DisableForRecovery(ctx, schema.pool, "lost Turnstile access", *now)
	if err != nil || !report.Changed || report.State.Revision != active.Revision+1 || report.State.Mode != humanverification.ModeDisabled || report.State.ActiveVersionID == nil || *report.State.ActiveVersionID != candidate.Version.ID {
		t.Fatalf("recovery disable = %#v, %v", report, err)
	}
	repeated, err := humanverification.DisableForRecovery(ctx, schema.pool, "confirm disabled state", now.Add(time.Second))
	if err != nil || repeated.Changed || repeated.State.Revision != report.State.Revision {
		t.Fatalf("repeated recovery disable = %#v, %v", repeated, err)
	}
}
