package database_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/mailruntime"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	coordinationTestReachedLock int64 = 0x4e5941545354
	coordinationTestBlockLock   int64 = 0x4e594154424c
)

type coordinationTriggerBlocker struct {
	connection *pgxpool.Conn
	released   bool
}

func installCoordinationTriggerBlocker(
	t *testing.T,
	schema *postgresTestSchema,
	table string,
	event string,
) *coordinationTriggerBlocker {
	t.Helper()
	if (table != "email_outbox" || event != "UPDATE") && (table != "users" || event != "INSERT") {
		t.Fatalf("unsupported coordination trigger target %s %s", event, table)
	}
	connection, err := schema.pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire coordination blocker connection: %v", err)
	}
	blocker := &coordinationTriggerBlocker{connection: connection}
	t.Cleanup(blocker.release)
	if _, err := connection.Exec(context.Background(), `SELECT pg_advisory_lock($1)`, coordinationTestBlockLock); err != nil {
		connection.Release()
		t.Fatalf("lock coordination blocker: %v", err)
	}
	if _, err := schema.pool.Exec(context.Background(), fmt.Sprintf(`
		CREATE FUNCTION coordination_test_block() RETURNS trigger
		LANGUAGE plpgsql AS $function$
		BEGIN
			PERFORM pg_advisory_xact_lock(%d);
			PERFORM pg_advisory_xact_lock(%d);
			RETURN NEW;
		END;
		$function$;
		CREATE TRIGGER coordination_test_block_trigger
		BEFORE %s ON %s
		FOR EACH ROW EXECUTE FUNCTION coordination_test_block();
	`, coordinationTestReachedLock, coordinationTestBlockLock, event, table)); err != nil {
		blocker.release()
		t.Fatalf("install coordination blocker trigger: %v", err)
	}
	return blocker
}

func (b *coordinationTriggerBlocker) waitUntilBlocked(t *testing.T, schema *postgresTestSchema) {
	t.Helper()
	probe, err := schema.pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire coordination probe connection: %v", err)
	}
	defer probe.Release()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var acquired bool
		if err := probe.QueryRow(context.Background(), `SELECT pg_try_advisory_lock($1)`, coordinationTestReachedLock).Scan(&acquired); err != nil {
			t.Fatalf("probe coordination trigger: %v", err)
		}
		if !acquired {
			return
		}
		var unlocked bool
		if err := probe.QueryRow(context.Background(), `SELECT pg_advisory_unlock($1)`, coordinationTestReachedLock).Scan(&unlocked); err != nil || !unlocked {
			t.Fatalf("release coordination probe lock: unlocked=%v err=%v", unlocked, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("database transaction did not reach the coordination trigger")
}

func (b *coordinationTriggerBlocker) release() {
	if b == nil || b.connection == nil || b.released {
		return
	}
	b.released = true
	var unlocked bool
	_ = b.connection.QueryRow(context.Background(), `SELECT pg_advisory_unlock($1)`, coordinationTestBlockLock).Scan(&unlocked)
	b.connection.Release()
}

func assertStillBlocked[T any](t *testing.T, result <-chan T, operation string) {
	t.Helper()
	select {
	case <-result:
		t.Fatalf("%s completed before the coordinating transaction committed", operation)
	case <-time.After(150 * time.Millisecond):
	}
}

func insertCoordinationOutbox(
	t *testing.T,
	schema *postgresTestSchema,
	now time.Time,
	status string,
	workerID *string,
) uuid.UUID {
	t.Helper()
	userID := uuid.New()
	outboxID := uuid.New()
	username := "coord-" + userID.String()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,$2,'active','user','legacy')
	`, userID, username); err != nil {
		t.Fatalf("insert coordination outbox user: %v", err)
	}
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO email_outbox (
			id,user_id,message_type,recipient_hash,encrypted_message,status,available_at,
			locked_at,locked_by,expires_at,created_at,updated_at
		) VALUES ($1,$2,'account.email_verification',$3,'opaque-envelope',$4,$5,$6,$7,$8,$9,$9)
	`, outboxID, userID, make([]byte, 32), status, now.Add(-time.Minute),
		func() *time.Time {
			if workerID == nil {
				return nil
			}
			lockedAt := now.Add(-time.Second)
			return &lockedAt
		}(), workerID, now.Add(time.Hour), now.Add(-2*time.Minute)); err != nil {
		t.Fatalf("insert coordination outbox: %v", err)
	}
	return outboxID
}

func TestStaleRuntimeMailSenderCannotClaimNewMessages(t *testing.T) {
	schema, mailStore, actorID, now := newRuntimeMailStore(t)
	password := "active-secret"
	first := createRuntimeMailCandidate(t, mailStore, actorID, 0, "first.smtp.example.test", &password, nil)
	firstActive := activateRuntimeMailCandidate(t, mailStore, actorID, first)
	manager, err := mailruntime.NewManager(mailStore, mailruntime.ManagerOptions{})
	if err != nil {
		t.Fatalf("create runtime mail manager: %v", err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load first runtime mail sender: %v", err)
	}
	_, staleGate, available := manager.CurrentSender()
	if !available || staleGate.VersionID == nil || *staleGate.VersionID != *firstActive.ActiveVersionID {
		t.Fatalf("first sender gate=%#v available=%v", staleGate, available)
	}

	second := createRuntimeMailCandidate(t, mailStore, actorID, firstActive.Revision, "second.smtp.example.test", &password, nil)
	activateRuntimeMailCandidate(t, mailStore, actorID, second)
	insertCoordinationOutbox(t, schema, *now, "pending", nil)
	accountStore := account.NewStore(schema.pool)
	claimed, err := accountStore.ClaimEmailBatch(
		context.Background(), "stale-worker", 10, *now, time.Minute, &staleGate,
	)
	if !errors.Is(err, runtimecoord.ErrMailDeliveryGateChanged) || len(claimed) != 0 {
		t.Fatalf("stale claim items=%d err=%v", len(claimed), err)
	}
	var status string
	var attempts int
	if err := schema.pool.QueryRow(context.Background(), `SELECT status,attempt_count FROM email_outbox`).Scan(&status, &attempts); err != nil {
		t.Fatalf("load outbox after stale claim: %v", err)
	}
	if status != "pending" || attempts != 0 {
		t.Fatalf("stale sender mutated outbox: status=%s attempts=%d", status, attempts)
	}

	if err := manager.RefreshEmailSender(context.Background()); err != nil {
		t.Fatalf("refresh runtime mail sender: %v", err)
	}
	_, currentGate, available := manager.CurrentSender()
	if !available || currentGate.VersionID == nil || *currentGate.VersionID != second.Version.ID {
		t.Fatalf("current sender gate=%#v available=%v", currentGate, available)
	}
	claimed, err = accountStore.ClaimEmailBatch(
		context.Background(), "current-worker", 10, *now, time.Minute, &currentGate,
	)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("current claim items=%d err=%v", len(claimed), err)
	}
}

func TestClaimedMailBecomesInFlightBeforeRuntimeMailChanges(t *testing.T) {
	schema, mailStore, actorID, now := newRuntimeMailStore(t)
	password := "active-secret"
	first := createRuntimeMailCandidate(t, mailStore, actorID, 0, "inflight-first.smtp.example.test", &password, nil)
	firstActive := activateRuntimeMailCandidate(t, mailStore, actorID, first)
	second := createRuntimeMailCandidate(t, mailStore, actorID, firstActive.Revision, "inflight-second.smtp.example.test", &password, nil)
	tested := recordRuntimeMailTest(t, mailStore, actorID, second.State.Revision, second.Version.ID, mailruntime.TestResultSuccess, nil)
	manager, err := mailruntime.NewManager(mailStore, mailruntime.ManagerOptions{})
	if err != nil {
		t.Fatalf("create runtime mail manager: %v", err)
	}
	if err := manager.Load(context.Background()); err != nil {
		t.Fatalf("load in-flight sender: %v", err)
	}
	_, gate, available := manager.CurrentSender()
	if !available || gate.VersionID == nil || *gate.VersionID != first.Version.ID {
		t.Fatalf("in-flight gate=%#v available=%v", gate, available)
	}
	insertCoordinationOutbox(t, schema, *now, "pending", nil)
	blocker := installCoordinationTriggerBlocker(t, schema, "email_outbox", "UPDATE")

	type claimResult struct {
		items []account.OutboxEmail
		err   error
	}
	claimResults := make(chan claimResult, 1)
	go func() {
		items, claimErr := account.NewStore(schema.pool).ClaimEmailBatch(
			context.Background(), "inflight-worker", 10, *now, time.Minute, &gate,
		)
		claimResults <- claimResult{items: items, err: claimErr}
	}()
	blocker.waitUntilBlocked(t, schema)

	activationResults := make(chan error, 1)
	go func() {
		_, activateErr := mailStore.Activate(context.Background(), mailruntime.VersionMutationInput{
			ExpectedRevision: tested.State.Revision, VersionID: second.Version.ID,
			Audit: runtimeMailAudit(mailruntime.AuditSettingsActivated, actorID),
		})
		activationResults <- activateErr
	}()
	assertStillBlocked(t, activationResults, "runtime mail activation")
	blocker.release()

	claim := <-claimResults
	if claim.err != nil || len(claim.items) != 1 {
		t.Fatalf("in-flight claim items=%d err=%v", len(claim.items), claim.err)
	}
	if err := <-activationResults; err != nil {
		t.Fatalf("activate after in-flight claim: %v", err)
	}
}

func TestRegistrationLinearizesBeforeCloseOrMailDisable(t *testing.T) {
	for _, test := range []struct {
		name            string
		mutate          func(*postgresTestSchema, *settings.Manager, time.Time) error
		wantMutationErr error
	}{
		{
			name: "close registration",
			mutate: func(_ *postgresTestSchema, manager *settings.Manager, _ time.Time) error {
				return manager.SetRegistration(context.Background(), settings.DefaultRegistration(), "coordination-admin", true)
			},
		},
		{
			name: "disable mail",
			mutate: func(schema *postgresTestSchema, _ *settings.Manager, now time.Time) error {
				store, err := mailruntime.NewStore(schema.pool, mailruntime.StoreOptions{
					ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": runtimeMailTestKey},
					Clock: func() time.Time { return now },
				})
				if err != nil {
					return err
				}
				_, err = store.Disable(context.Background(), mailruntime.StateMutationInput{
					ExpectedRevision: 0,
					Audit:            runtimeMailAudit(mailruntime.AuditSettingsDisabled, uuid.New()),
				})
				return err
			},
			wantMutationErr: mailruntime.ErrRegistrationOpen,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			schema := newMigratedRegistrationSchema(t)
			now := time.Now().UTC().Truncate(time.Microsecond)
			policy := settings.DefaultRegistration()
			policy.Mode = settings.RegistrationOpen
			settingsManager := settings.NewManager(schema.pool, settings.Branding{})
			if err := settingsManager.SetRegistration(context.Background(), policy, "coordination-admin", true); err != nil {
				t.Fatalf("open registration: %v", err)
			}
			pending := registrationTestUser("linearized-"+uuid.NewString()[:8], models.UserStatusPending)
			blocker := installCoordinationTriggerBlocker(t, schema, "users", "INSERT")

			registrationResults := make(chan error, 1)
			go func() {
				_, registrationErr := user.NewStore(schema.pool).CreateRegistration(
					context.Background(), pending, user.RegistrationCommitOptions{
						ExpiresAt: now.Add(time.Hour), Now: now, Registration: policy,
						MailGate:     runtimecoord.MailDeliveryGate{Mode: runtimecoord.MailModeFallback},
						Verification: validPreparedVerification(pending, now, now.Add(time.Hour)),
					},
				)
				registrationResults <- registrationErr
			}()
			blocker.waitUntilBlocked(t, schema)

			mutationResults := make(chan error, 1)
			go func() { mutationResults <- test.mutate(schema, settingsManager, now) }()
			assertStillBlocked(t, mutationResults, test.name)
			blocker.release()

			if err := <-registrationResults; err != nil {
				t.Fatalf("registration did not commit first: %v", err)
			}
			mutationErr := <-mutationResults
			if !errors.Is(mutationErr, test.wantMutationErr) {
				t.Fatalf("mutation error=%v want=%v", mutationErr, test.wantMutationErr)
			}
		})
	}
}

func TestOpeningRegistrationAndDisablingMailCannotBothCommit(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	settingsManager := settings.NewManager(schema.pool, settings.Branding{})
	mailStore, err := mailruntime.NewStore(schema.pool, mailruntime.StoreOptions{
		ActiveKeyID: "primary", MasterKeys: map[string][]byte{"primary": runtimeMailTestKey},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("create runtime mail store: %v", err)
	}
	openPolicy := settings.DefaultRegistration()
	openPolicy.Mode = settings.RegistrationOpen
	start := make(chan struct{})
	settingsResult := make(chan error, 1)
	disableResult := make(chan error, 1)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		<-start
		settingsResult <- settingsManager.SetRegistration(context.Background(), openPolicy, "coordination-admin", true)
	}()
	go func() {
		defer workers.Done()
		<-start
		_, disableErr := mailStore.Disable(context.Background(), mailruntime.StateMutationInput{
			ExpectedRevision: 0,
			Audit:            runtimeMailAudit(mailruntime.AuditSettingsDisabled, uuid.New()),
		})
		disableResult <- disableErr
	}()
	close(start)
	workers.Wait()
	settingsErr := <-settingsResult
	disableErr := <-disableResult

	successes := 0
	if settingsErr == nil {
		successes++
	}
	if disableErr == nil {
		successes++
	}
	if successes != 1 {
		t.Fatalf("settings error=%v disable error=%v successes=%d", settingsErr, disableErr, successes)
	}
	if settingsErr == nil && !errors.Is(disableErr, mailruntime.ErrRegistrationOpen) {
		t.Fatalf("registration won but disable error=%v", disableErr)
	}
	if disableErr == nil && !errors.Is(settingsErr, settings.ErrMailConfigurationNeeded) {
		t.Fatalf("disable won but settings error=%v", settingsErr)
	}
}

func TestEmailArtifactExpiryAndPermanentRejectionClearSensitivePayloads(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uuid.New()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,$2,'active','user','legacy')
	`, userID, "artifact-cleanup-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert artifact cleanup user: %v", err)
	}
	createdAt := now.Add(-2 * time.Hour)
	expiresAt := now.Add(-time.Hour)
	expiredOutboxID := uuid.New()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO account_action_tokens (
			id,user_id,action,token_hash,payload_ciphertext,expires_at,created_at
		) VALUES ($1,$2,'email_verification',$3,'sensitive-action',$4,$5)
	`, uuid.New(), userID, make([]byte, 32), expiresAt, createdAt); err != nil {
		t.Fatalf("insert expired account action: %v", err)
	}
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO email_outbox (
			id,user_id,message_type,recipient_hash,encrypted_message,status,available_at,expires_at,created_at,updated_at
		) VALUES ($1,$2,'account.email_verification',$3,'sensitive-email','pending',$4,$5,$4,$4)
	`, expiredOutboxID, userID, make([]byte, 32), createdAt, expiresAt); err != nil {
		t.Fatalf("insert expired email artifacts: %v", err)
	}
	store := account.NewStore(schema.pool)
	expired, err := store.ExpireEmailArtifacts(context.Background(), now, 10)
	if err != nil {
		t.Fatalf("expire email artifacts: %v", err)
	}
	if expired != 2 {
		t.Fatalf("expired artifact count=%d", expired)
	}
	var revokedReason, actionCiphertext string
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT revoked_reason,payload_ciphertext FROM account_action_tokens WHERE user_id=$1
	`, userID).Scan(&revokedReason, &actionCiphertext); err != nil {
		t.Fatalf("load expired action token: %v", err)
	}
	var expiredStatus, expiredCiphertext string
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT status,encrypted_message FROM email_outbox WHERE id=$1
	`, expiredOutboxID).Scan(&expiredStatus, &expiredCiphertext); err != nil {
		t.Fatalf("load expired email outbox: %v", err)
	}
	if revokedReason != "expired" || actionCiphertext != "" || expiredStatus != "expired" || expiredCiphertext != "" {
		t.Fatalf("expired artifacts retained data: reason=%q action=%q status=%q email=%q", revokedReason, actionCiphertext, expiredStatus, expiredCiphertext)
	}

	workerID := "rejection-worker"
	rejectedID := insertCoordinationOutbox(t, schema, now, "sending", &workerID)
	if err := store.MarkEmailRejected(context.Background(), rejectedID, workerID, now); err != nil {
		t.Fatalf("mark email rejected: %v", err)
	}
	var rejectedStatus, rejectedCiphertext, rejectedError string
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT status,encrypted_message,last_error FROM email_outbox WHERE id=$1
	`, rejectedID).Scan(&rejectedStatus, &rejectedCiphertext, &rejectedError); err != nil {
		t.Fatalf("load rejected email: %v", err)
	}
	if rejectedStatus != "rejected" || rejectedCiphertext != "" || rejectedError != "permanent SMTP recipient failure" {
		t.Fatalf("rejected message status=%q ciphertext=%q error=%q", rejectedStatus, rejectedCiphertext, rejectedError)
	}
	claimed, err := store.ClaimEmailBatch(context.Background(), "retry-worker", 10, now, time.Minute, nil)
	if err != nil {
		t.Fatalf("claim after permanent rejection: %v", err)
	}
	for _, item := range claimed {
		if item.ID == rejectedID {
			t.Fatal("permanently rejected message was scheduled for retry")
		}
	}
}

func TestEmailArtifactExpiryUsesBoundedPerTableBatches(t *testing.T) {
	schema := newMigratedRegistrationSchema(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := uuid.New()
	if _, err := schema.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,$2,'active','user','legacy')
	`, userID, "bounded-expiry-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert bounded expiry user: %v", err)
	}
	createdAt := now.Add(-3 * time.Hour)
	for index := 0; index < 3; index++ {
		expiresAt := now.Add(-2*time.Hour + time.Duration(index)*time.Second)
		tokenHash := make([]byte, 32)
		tokenHash[len(tokenHash)-1] = byte(index + 1)
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO account_action_tokens (
				id,user_id,action,token_hash,payload_ciphertext,expires_at,created_at
			) VALUES ($1,$2,'email_verification',$3,$4,$5,$6)
		`, uuid.New(), userID, tokenHash, fmt.Sprintf("sensitive-token-%d", index), expiresAt, createdAt); err != nil {
			t.Fatalf("insert expired token %d: %v", index, err)
		}
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO email_outbox (
				id,user_id,message_type,recipient_hash,encrypted_message,status,available_at,expires_at,created_at,updated_at
			) VALUES ($1,$2,'account.email_verification',$3,$4,'pending',$5,$6,$5,$5)
		`, uuid.New(), userID, make([]byte, 32), fmt.Sprintf("sensitive-email-%d", index), createdAt, expiresAt); err != nil {
			t.Fatalf("insert expired email %d: %v", index, err)
		}
	}

	store := account.NewStore(schema.pool)
	expired, err := store.ExpireEmailArtifacts(context.Background(), now, 2)
	if err != nil {
		t.Fatalf("expire bounded email artifacts: %v", err)
	}
	if expired != 4 {
		t.Fatalf("first bounded expiry count=%d", expired)
	}
	var expiredTokens, remainingTokens, expiredMessages, remainingMessages int64
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FILTER (WHERE revoked_at IS NOT NULL),
		       COUNT(*) FILTER (WHERE revoked_at IS NULL)
		FROM account_action_tokens WHERE user_id=$1
	`, userID).Scan(&expiredTokens, &remainingTokens); err != nil {
		t.Fatalf("count bounded token expiry: %v", err)
	}
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FILTER (WHERE status='expired'),
		       COUNT(*) FILTER (WHERE status<>'expired')
		FROM email_outbox WHERE user_id=$1
	`, userID).Scan(&expiredMessages, &remainingMessages); err != nil {
		t.Fatalf("count bounded email expiry: %v", err)
	}
	if expiredTokens != 2 || remainingTokens != 1 || expiredMessages != 2 || remainingMessages != 1 {
		t.Fatalf(
			"first bounded expiry tokens=%d remaining_tokens=%d messages=%d remaining_messages=%d",
			expiredTokens, remainingTokens, expiredMessages, remainingMessages,
		)
	}

	expired, err = store.ExpireEmailArtifacts(context.Background(), now, 2)
	if err != nil {
		t.Fatalf("expire remaining email artifacts: %v", err)
	}
	if expired != 2 {
		t.Fatalf("remaining bounded expiry count=%d", expired)
	}
}
