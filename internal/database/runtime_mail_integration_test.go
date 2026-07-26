package database_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/mailruntime"
)

var runtimeMailTestKey = []byte("0123456789abcdef0123456789abcdef")

func newRuntimeMailStore(t *testing.T) (*postgresTestSchema, *mailruntime.Store, uuid.UUID, *time.Time) {
	t.Helper()
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("migrate runtime mail schema: %v", err)
	}
	actorID := uuid.New()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role) VALUES ($1,$2,'active','admin')
	`, actorID, "mail-admin-"+strings.ReplaceAll(actorID.String(), "-", "")); err != nil {
		t.Fatalf("insert runtime mail actor: %v", err)
	}
	now := time.Date(2026, time.July, 26, 12, 0, 0, 0, time.UTC)
	store, err := mailruntime.NewStore(schema.pool, mailruntime.StoreOptions{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": runtimeMailTestKey},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create runtime mail store: %v", err)
	}
	return schema, store, actorID, &now
}

func runtimeMailSettings(host string) mailruntime.Settings {
	return mailruntime.Settings{
		Host: host, Port: 587, Username: "mailer@example.test", TLSMode: mailruntime.TLSModeStartTLS,
		FromAddress: "noreply@example.test", FromName: "Nyauth",
		PublicBaseURL: "https://auth.example.test", ConnectTimeout: 5 * time.Second, SendTimeout: 15 * time.Second,
	}
}

func runtimeMailAudit(event string, actorID uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{
		Event: event, ActorID: actorID, ActorName: "mail-admin", Result: "success", RiskLevel: "high",
		IPAddress: "192.0.2.10", UserAgent: "runtime-mail-integration-test",
	}
}

func createRuntimeMailCandidate(
	t *testing.T,
	store *mailruntime.Store,
	actorID uuid.UUID,
	expectedRevision int64,
	host string,
	password *string,
	fallback *mailruntime.SMTPConfig,
) mailruntime.CandidateResult {
	t.Helper()
	result, err := store.CreateCandidate(context.Background(), mailruntime.CreateCandidateInput{
		ExpectedRevision: expectedRevision, Settings: runtimeMailSettings(host), Password: password,
		Fallback: fallback, Audit: runtimeMailAudit(mailruntime.AuditSettingsSaved, actorID),
	})
	if err != nil {
		t.Fatalf("create runtime mail candidate: %v", err)
	}
	return result
}

func recordRuntimeMailTest(
	t *testing.T,
	store *mailruntime.Store,
	actorID uuid.UUID,
	expectedRevision int64,
	versionID uuid.UUID,
	result string,
	category *string,
) mailruntime.TestResult {
	t.Helper()
	digest := sha256.Sum256([]byte("operator@example.test"))
	recorded, err := store.RecordTest(context.Background(), mailruntime.RecordTestInput{
		ExpectedRevision: expectedRevision, VersionID: versionID, RecipientHash: digest[:],
		Result: result, ErrorCategory: category, Audit: runtimeMailAudit(mailruntime.AuditSettingsTested, actorID),
	})
	if err != nil {
		t.Fatalf("record runtime mail test: %v", err)
	}
	return recorded
}

func activateRuntimeMailCandidate(
	t *testing.T,
	store *mailruntime.Store,
	actorID uuid.UUID,
	candidate mailruntime.CandidateResult,
) mailruntime.State {
	t.Helper()
	tested := recordRuntimeMailTest(t, store, actorID, candidate.State.Revision, candidate.Version.ID, mailruntime.TestResultSuccess, nil)
	state, err := store.Activate(context.Background(), mailruntime.VersionMutationInput{
		ExpectedRevision: tested.State.Revision, VersionID: candidate.Version.ID,
		Audit: runtimeMailAudit(mailruntime.AuditSettingsActivated, actorID),
	})
	if err != nil {
		t.Fatalf("activate runtime mail candidate: %v", err)
	}
	return state
}

func TestRuntimeMailConfigurationLifecycleAndHistory(t *testing.T) {
	schema, store, actorID, now := newRuntimeMailStore(t)
	fallback := &mailruntime.SMTPConfig{Settings: runtimeMailSettings("fallback.smtp.example.test"), Password: "fallback-secret"}

	initial, err := store.LoadState(context.Background())
	if err != nil || initial.Mode != mailruntime.ModeFallback || initial.Revision != 0 {
		t.Fatalf("initial state=%#v err=%v", initial, err)
	}
	first := createRuntimeMailCandidate(t, store, actorID, initial.Revision, "first.smtp.example.test", nil, fallback)
	if !first.Version.PasswordConfigured {
		t.Fatal("candidate did not inherit the fallback password")
	}
	var ciphertext string
	if err := schema.pool.QueryRow(context.Background(), `SELECT password_ciphertext FROM mail_config_versions WHERE id=$1`, first.Version.ID).Scan(&ciphertext); err != nil {
		t.Fatalf("load encrypted SMTP password: %v", err)
	}
	if ciphertext == "" || strings.Contains(ciphertext, "fallback-secret") {
		t.Fatalf("SMTP password was not envelope encrypted: %q", ciphertext)
	}
	encodedVersion, err := json.Marshal(first.Version)
	if err != nil {
		t.Fatalf("marshal redacted version: %v", err)
	}
	if strings.Contains(string(encodedVersion), "fallback-secret") || strings.Contains(string(encodedVersion), "ciphertext") {
		t.Fatalf("version JSON exposed secret material: %s", encodedVersion)
	}

	failureCategory := mailruntime.ErrorCategoryAuthentication
	failedTest := recordRuntimeMailTest(t, store, actorID, first.State.Revision, first.Version.ID, mailruntime.TestResultFailure, &failureCategory)
	_, err = store.Activate(context.Background(), mailruntime.VersionMutationInput{
		ExpectedRevision: failedTest.State.Revision, VersionID: first.Version.ID,
		Audit: runtimeMailAudit(mailruntime.AuditSettingsActivated, actorID),
	})
	if !errors.Is(err, mailruntime.ErrCandidateTestRequired) {
		t.Fatalf("activation after failed test error=%v", err)
	}

	success := recordRuntimeMailTest(t, store, actorID, failedTest.State.Revision, first.Version.ID, mailruntime.TestResultSuccess, nil)
	active, err := store.Activate(context.Background(), mailruntime.VersionMutationInput{
		ExpectedRevision: success.State.Revision, VersionID: first.Version.ID,
		Audit: runtimeMailAudit(mailruntime.AuditSettingsActivated, actorID),
	})
	if err != nil {
		t.Fatalf("activate first SMTP version: %v", err)
	}
	effective, err := store.LoadEffectiveConfig(context.Background(), nil)
	if err != nil || !effective.Available || effective.Config == nil || effective.Config.Password != "fallback-secret" {
		t.Fatalf("effective config=%#v err=%v", effective, err)
	}

	second := createRuntimeMailCandidate(t, store, actorID, active.Revision, "second.smtp.example.test", nil, nil)
	secondActive := activateRuntimeMailCandidate(t, store, actorID, second)
	if secondActive.PreviousVersionID == nil || *secondActive.PreviousVersionID != first.Version.ID {
		t.Fatalf("second activation previous=%v", secondActive.PreviousVersionID)
	}
	rolledBack, err := store.Rollback(context.Background(), mailruntime.StateMutationInput{
		ExpectedRevision: secondActive.Revision, Audit: runtimeMailAudit(mailruntime.AuditSettingsRolledBack, actorID),
	})
	if err != nil || rolledBack.ActiveVersionID == nil || *rolledBack.ActiveVersionID != first.Version.ID {
		t.Fatalf("rollback state=%#v err=%v", rolledBack, err)
	}
	disabled, err := store.Disable(context.Background(), mailruntime.StateMutationInput{
		ExpectedRevision: rolledBack.Revision, Audit: runtimeMailAudit(mailruntime.AuditSettingsDisabled, actorID),
	})
	if err != nil || disabled.Mode != mailruntime.ModeDisabled || disabled.ActiveVersionID != nil {
		t.Fatalf("disabled state=%#v err=%v", disabled, err)
	}
	if effective, err = store.LoadEffectiveConfig(context.Background(), fallback); err != nil || effective.Config != nil || effective.Available {
		t.Fatalf("disabled effective config=%#v err=%v", effective, err)
	}

	if _, err := schema.pool.Exec(context.Background(), `UPDATE mail_config_versions SET host='tampered.example.test' WHERE id=$1`, first.Version.ID); !isPostgresCode(err, "55000") {
		t.Fatalf("immutable version update error=%v", err)
	}
	if _, err := schema.pool.Exec(context.Background(), `DELETE FROM mail_config_tests WHERE version_id=$1`, first.Version.ID); !isPostgresCode(err, "55000") {
		t.Fatalf("immutable test delete error=%v", err)
	}

	if _, err := schema.pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, actorID); err != nil {
		t.Fatalf("delete mail configuration creator: %v", err)
	}
	var createdBy, testedBy *uuid.UUID
	if err := schema.pool.QueryRow(context.Background(), `SELECT created_by FROM mail_config_versions WHERE id=$1`, first.Version.ID).Scan(&createdBy); err != nil {
		t.Fatalf("load creator after deletion: %v", err)
	}
	if err := schema.pool.QueryRow(context.Background(), `SELECT tested_by FROM mail_config_tests WHERE version_id=$1 ORDER BY created_at LIMIT 1`, first.Version.ID).Scan(&testedBy); err != nil {
		t.Fatalf("load tester after deletion: %v", err)
	}
	if createdBy != nil || testedBy != nil {
		t.Fatalf("history actors not detached: created_by=%v tested_by=%v", createdBy, testedBy)
	}

	*now = now.Add(24 * time.Hour)
}

func TestRuntimeMailSuccessfulTestExpiresAndCandidateRevisionIsSerialized(t *testing.T) {
	_, store, actorID, now := newRuntimeMailStore(t)
	password := "candidate-secret"
	first := createRuntimeMailCandidate(t, store, actorID, 0, "first.smtp.example.test", &password, nil)
	success := recordRuntimeMailTest(t, store, actorID, first.State.Revision, first.Version.ID, mailruntime.TestResultSuccess, nil)
	*now = now.Add(mailruntime.CandidateTestValidity + time.Second)
	_, err := store.Activate(context.Background(), mailruntime.VersionMutationInput{
		ExpectedRevision: success.State.Revision, VersionID: first.Version.ID,
		Audit: runtimeMailAudit(mailruntime.AuditSettingsActivated, actorID),
	})
	if !errors.Is(err, mailruntime.ErrCandidateTestExpired) {
		t.Fatalf("expired activation error=%v", err)
	}

	state, err := store.LoadState(context.Background())
	if err != nil {
		t.Fatalf("load state for concurrent candidate: %v", err)
	}
	var workers sync.WaitGroup
	errorsByWorker := make(chan error, 2)
	start := make(chan struct{})
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			candidatePassword := "concurrent-secret"
			_, candidateErr := store.CreateCandidate(context.Background(), mailruntime.CreateCandidateInput{
				ExpectedRevision: state.Revision,
				Settings:         runtimeMailSettings("concurrent-" + string(rune('a'+index)) + ".smtp.example.test"),
				Password:         &candidatePassword, Audit: runtimeMailAudit(mailruntime.AuditSettingsSaved, actorID),
			})
			errorsByWorker <- candidateErr
		}(index)
	}
	close(start)
	workers.Wait()
	close(errorsByWorker)
	var succeeded, conflicted int
	for candidateErr := range errorsByWorker {
		switch {
		case candidateErr == nil:
			succeeded++
		case errors.Is(candidateErr, mailruntime.ErrStateConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent candidate error: %v", candidateErr)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent results success=%d conflict=%d", succeeded, conflicted)
	}
}

func TestRuntimeMailCandidateInheritsPasswordlessFallbackAndActiveConfiguration(t *testing.T) {
	_, store, actorID, _ := newRuntimeMailStore(t)
	fallback := &mailruntime.SMTPConfig{Settings: runtimeMailSettings("passwordless-fallback.smtp.example.test")}
	first := createRuntimeMailCandidate(t, store, actorID, 0, "passwordless-active.smtp.example.test", nil, fallback)
	if first.Version.PasswordConfigured {
		t.Fatal("passwordless fallback inheritance unexpectedly configured a password")
	}
	active := activateRuntimeMailCandidate(t, store, actorID, first)
	second := createRuntimeMailCandidate(t, store, actorID, active.Revision, "passwordless-next.smtp.example.test", nil, nil)
	if second.Version.PasswordConfigured {
		t.Fatal("passwordless active inheritance unexpectedly configured a password")
	}
}

func TestRuntimeMailManagerClearsOldSenderWhenActiveSecretCannotBeDecrypted(t *testing.T) {
	schema, store, actorID, _ := newRuntimeMailStore(t)
	wrongKeyStore, err := mailruntime.NewStore(schema.pool, mailruntime.StoreOptions{
		ActiveKeyID: "primary",
		MasterKeys:  map[string][]byte{"primary": []byte("abcdef0123456789abcdef0123456789")},
	})
	if err != nil {
		t.Fatalf("create store with unavailable active secret key: %v", err)
	}
	fallback := &mailruntime.SMTPConfig{
		Settings: runtimeMailSettings("old-fallback.smtp.example.test"),
		Password: "old-fallback-secret",
	}
	manager, err := mailruntime.NewManager(wrongKeyStore, mailruntime.ManagerOptions{Fallback: fallback})
	if err != nil {
		t.Fatalf("create manager with old fallback sender: %v", err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load old fallback sender: %v", err)
	}
	if _, _, ok := manager.CurrentSender(); !ok {
		t.Fatal("old fallback sender was not installed")
	}

	password := "new-active-secret"
	candidate := createRuntimeMailCandidate(t, store, actorID, 0, "new-active.smtp.example.test", &password, nil)
	activateRuntimeMailCandidate(t, store, actorID, candidate)
	if err := manager.Load(context.Background()); !errors.Is(err, mailruntime.ErrInvalidConfig) {
		t.Fatalf("active secret decryption error=%v", err)
	}
	status := manager.Status()
	if status.Mode != mailruntime.ModeActive || !status.Configured || status.Available || status.VersionID == nil || *status.VersionID != candidate.Version.ID {
		t.Fatalf("manager retained an unsafe effective state after decryption failure: %#v", status)
	}
	if _, _, ok := manager.CurrentSender(); ok {
		t.Fatal("manager retained the old sender after active secret decryption failure")
	}
}

func TestRuntimeMailSharedCircuitBreaker(t *testing.T) {
	schema, store, actorID, now := newRuntimeMailStore(t)
	password := "active-secret"
	candidate := createRuntimeMailCandidate(t, store, actorID, 0, "active.smtp.example.test", &password, nil)
	active := activateRuntimeMailCandidate(t, store, actorID, candidate)
	source := mailruntime.EffectiveSource{Mode: mailruntime.ModeActive, VersionID: active.ActiveVersionID}

	recipient, err := store.RecordDeliveryOutcome(context.Background(), mailruntime.DeliveryOutcome{
		Source: source, Category: mailruntime.ErrorCategoryRecipient, Reason: "recipient_rejected",
	})
	if err != nil || recipient.Changed {
		t.Fatalf("recipient outcome=%#v err=%v", recipient, err)
	}
	for attempt := 1; attempt <= mailruntime.TransportFailureLimit; attempt++ {
		transition, outcomeErr := store.RecordDeliveryOutcome(context.Background(), mailruntime.DeliveryOutcome{
			Source: source, Category: mailruntime.ErrorCategoryTransport, Reason: "connection_failed",
		})
		if outcomeErr != nil {
			t.Fatalf("record transport failure %d: %v", attempt, outcomeErr)
		}
		if transition.Opened != (attempt == mailruntime.TransportFailureLimit) {
			t.Fatalf("transport attempt %d transition=%#v", attempt, transition)
		}
	}
	opened, err := store.LoadState(context.Background())
	if err != nil || opened.CircuitState != mailruntime.CircuitOpen || opened.NextProbeAt == nil {
		t.Fatalf("opened state=%#v err=%v", opened, err)
	}
	if _, err := store.ClaimProbe(context.Background(), source); !errors.Is(err, mailruntime.ErrProbeNotDue) {
		t.Fatalf("early probe error=%v", err)
	}
	*now = opened.NextProbeAt.UTC()
	claim, err := store.ClaimProbe(context.Background(), source)
	if err != nil || !claim.Acquired {
		t.Fatalf("probe claim=%#v err=%v", claim, err)
	}
	failedProbe, err := store.RecordProbeOutcome(context.Background(), mailruntime.ProbeOutcome{
		Source: source, ExpectedRevision: claim.ExpectedRevision, Category: mailruntime.ErrorCategoryTransport,
		Reason: "probe_failed",
	})
	if err != nil || failedProbe.State.CircuitState != mailruntime.CircuitOpen {
		t.Fatalf("failed probe=%#v err=%v", failedProbe, err)
	}
	*now = failedProbe.State.NextProbeAt.UTC()
	claim, err = store.ClaimProbe(context.Background(), source)
	if err != nil || !claim.Acquired {
		t.Fatalf("recovery probe claim=%#v err=%v", claim, err)
	}
	recovered, err := store.RecordProbeOutcome(context.Background(), mailruntime.ProbeOutcome{
		Source: source, ExpectedRevision: claim.ExpectedRevision, Success: true,
	})
	if err != nil || !recovered.Recovered || recovered.State.CircuitState != mailruntime.CircuitClosed {
		t.Fatalf("recovered transition=%#v err=%v", recovered, err)
	}

	openedImmediately, err := store.RecordDeliveryOutcome(context.Background(), mailruntime.DeliveryOutcome{
		Source: source, Category: mailruntime.ErrorCategoryAuthentication, Reason: "authentication_failed",
	})
	if err != nil || !openedImmediately.Opened {
		t.Fatalf("permanent failure transition=%#v err=%v", openedImmediately, err)
	}
	var openedAudits, recoveredAudits int
	if err := schema.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, mailruntime.AuditCircuitOpened).Scan(&openedAudits); err != nil {
		t.Fatalf("count circuit-open audits: %v", err)
	}
	if err := schema.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, mailruntime.AuditCircuitRecovered).Scan(&recoveredAudits); err != nil {
		t.Fatalf("count circuit-recovered audits: %v", err)
	}
	if openedAudits != 2 || recoveredAudits != 1 {
		t.Fatalf("circuit audits opened=%d recovered=%d", openedAudits, recoveredAudits)
	}
}

func TestRuntimeMailManagersSynchronizeNotificationsCircuitAndMissedNotificationReconciliation(t *testing.T) {
	schema, store, actorID, _ := newRuntimeMailStore(t)
	fallback := &mailruntime.SMTPConfig{
		Settings: runtimeMailSettings("fallback.smtp.example.test"),
		Password: "fallback-secret",
	}
	newManager := func(reconciliationInterval time.Duration) *mailruntime.Manager {
		t.Helper()
		manager, err := mailruntime.NewManager(store, mailruntime.ManagerOptions{
			Fallback: fallback, ReconciliationInterval: reconciliationInterval,
			OnError: func(err error) {
				if !errors.Is(err, context.Canceled) {
					t.Logf("runtime mail synchronization error: %v", err)
				}
			},
		})
		if err != nil {
			t.Fatalf("create runtime mail manager: %v", err)
		}
		if err := manager.Load(context.Background()); err != nil {
			t.Fatalf("load runtime mail manager: %v", err)
		}
		return manager
	}

	managerA := newManager(time.Hour)
	managerB := newManager(time.Hour)
	syncContext, cancelSynchronization := context.WithCancel(context.Background())
	t.Cleanup(cancelSynchronization)
	managerA.StartSynchronization(syncContext)
	managerB.StartSynchronization(syncContext)

	password := "active-secret"
	candidate := createRuntimeMailCandidate(t, store, actorID, 0, "active.smtp.example.test", &password, nil)
	active := activateRuntimeMailCandidate(t, store, actorID, candidate)
	waitForManagersWithNotifications(t, schema, []*mailruntime.Manager{managerA, managerB}, func(status mailruntime.RuntimeStatus) bool {
		return status.Mode == mailruntime.ModeActive && status.Available && status.VersionID != nil && *status.VersionID == candidate.Version.ID
	})

	source := mailruntime.EffectiveSource{Mode: mailruntime.ModeActive, VersionID: active.ActiveVersionID}
	for attempt := 0; attempt < mailruntime.TransportFailureLimit; attempt++ {
		if _, err := store.RecordDeliveryOutcome(context.Background(), mailruntime.DeliveryOutcome{
			Source: source, Category: mailruntime.ErrorCategoryTransport, Reason: "ha_transport_failure",
		}); err != nil {
			t.Fatalf("record HA transport failure %d: %v", attempt+1, err)
		}
	}
	waitForManagersWithNotifications(t, schema, []*mailruntime.Manager{managerA, managerB}, func(status mailruntime.RuntimeStatus) bool {
		return status.Mode == mailruntime.ModeActive && status.Configured && !status.Available && status.CircuitState == mailruntime.CircuitOpen
	})

	managerC := newManager(50 * time.Millisecond)
	managerC.StartSynchronization(syncContext)
	if _, err := schema.pool.Exec(context.Background(), `
		UPDATE mail_runtime_state
		SET mode='disabled',previous_version_id=active_version_id,active_version_id=NULL,
		    candidate_version_id=NULL,revision=revision+1,circuit_state='closed',
		    circuit_open_reason=NULL,circuit_open_category=NULL,circuit_opened_at=NULL,
		    transport_failure_window_started_at=NULL,transport_failure_count=0,
		    next_probe_at=NULL,updated_at=NOW()
		WHERE singleton=TRUE
	`); err != nil {
		t.Fatalf("simulate missed mail runtime notification: %v", err)
	}
	waitForRuntimeMailStatus(t, managerC, func(status mailruntime.RuntimeStatus) bool {
		return status.Mode == mailruntime.ModeDisabled && !status.Configured && !status.Available && status.CircuitState == mailruntime.CircuitClosed
	})
}

func waitForManagersWithNotifications(
	t *testing.T,
	schema *postgresTestSchema,
	managers []*mailruntime.Manager,
	condition func(mailruntime.RuntimeStatus) bool,
) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := schema.pool.Exec(context.Background(), `SELECT pg_notify($1,$2)`, mailruntime.NotificationChannel, "integration-test"); err != nil {
			t.Fatalf("publish runtime mail synchronization notification: %v", err)
		}
		allMatched := true
		for _, manager := range managers {
			if !condition(manager.Status()) {
				allMatched = false
				break
			}
		}
		if allMatched {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	statuses := make([]mailruntime.RuntimeStatus, 0, len(managers))
	for _, manager := range managers {
		statuses = append(statuses, manager.Status())
	}
	t.Fatalf("runtime mail managers did not synchronize: %#v", statuses)
}

func waitForRuntimeMailStatus(t *testing.T, manager *mailruntime.Manager, condition func(mailruntime.RuntimeStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if status := manager.Status(); condition(status) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("runtime mail manager did not reconcile: %#v", manager.Status())
}

func isPostgresCode(err error, code string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == code
}
