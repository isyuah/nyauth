package database_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/securityrevocation"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestSecurityRevocationTriggerLeasingAndRevisionHandoff(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,1,'{}'::jsonb,'legacy')
	`, userID, "revoke-trigger-"+userID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET display_name='No security change' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM security_revocation_outbox`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("non-security update enqueued tasks=%d err=%v", count, err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET auth_version=2 WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}

	store := securityrevocation.NewStore(schema.pool)
	now := time.Now().UTC()
	claimed, err := store.Claim(ctx, "worker-a", 10, now, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("first claim=%#v err=%v", claimed, err)
	}
	first := claimed[0]
	if first.Revision != 1 || first.AuthVersion != 2 || first.SessionVersion != 1 || first.UserDeleted {
		t.Fatalf("unexpected first task: %#v", first)
	}

	if _, err := schema.pool.Exec(ctx, `UPDATE users SET session_version=2 WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	completed, err := store.Complete(ctx, first, "worker-a", now.Add(time.Second))
	if err != nil || completed {
		t.Fatalf("old revision completion completed=%v err=%v", completed, err)
	}
	claimed, err = store.Claim(ctx, "worker-b", 10, now.Add(2*time.Second), time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("replacement claim=%#v err=%v", claimed, err)
	}
	replacement := claimed[0]
	if replacement.Revision != 2 || replacement.AuthVersion != 2 || replacement.SessionVersion != 2 || replacement.AttemptCount != 1 {
		t.Fatalf("replacement task did not reset attempt state: %#v", replacement)
	}
	if completed, err = store.Complete(ctx, replacement, "worker-b", now.Add(3*time.Second)); err != nil || !completed {
		t.Fatalf("replacement completion completed=%v err=%v", completed, err)
	}

	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	claimed, err = store.Claim(ctx, "worker-delete", 10, now.Add(4*time.Second), time.Minute)
	if err != nil || len(claimed) != 1 || !claimed[0].UserDeleted || claimed[0].Reason != "user_deleted" {
		t.Fatalf("delete task=%#v err=%v", claimed, err)
	}
}

func TestSecurityRevocationClaimIsHASafe(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,metadata,creation_source)
		VALUES ($1,$2,'active','user','{}'::jsonb,'legacy')
	`, userID, "revoke-ha-"+userID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET auth_version=auth_version+1 WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	start := make(chan struct{})
	results := make(chan []securityrevocation.Task, 2)
	errorsByWorker := make(chan error, 2)
	var workers sync.WaitGroup
	for _, workerID := range []string{"ha-a", "ha-b"} {
		workerID := workerID
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			tasks, err := securityrevocation.NewStore(schema.pool).Claim(ctx, workerID, 1, now, time.Minute)
			results <- tasks
			errorsByWorker <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
	total := 0
	for tasks := range results {
		total += len(tasks)
	}
	if total != 1 {
		t.Fatalf("HA workers claimed task %d times, want exactly once", total)
	}
}

func TestSecurityRevocationRetriesAfterRedisRecoveryWithoutDeletingNewGeneration(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,1,'{}'::jsonb,'legacy')
	`, userID, "revoke-retry-"+userID.String()[:8]); err != nil {
		t.Fatal(err)
	}
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	redisStore := session.NewStore(rdb)
	for id, versions := range map[string][2]int64{"old-session": {1, 1}, "new-session": {2, 2}} {
		if err := redisStore.SaveSession(ctx, id, &session.SessionData{
			UserID: userID.String(), Username: "alice", AuthVersion: versions[0], SessionVersion: versions[1],
		}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	for token, authVersion := range map[string]int64{"old-refresh": 1, "new-refresh": 2} {
		if err := redisStore.SaveRefreshToken(ctx, token, &session.TokenData{
			ClientID: "client", UserID: userID.String(), AuthVersion: authVersion,
		}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET auth_version=2,session_version=2 WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	clock := now
	dispatcher, err := securityrevocation.NewDispatcher(
		securityrevocation.NewStore(schema.pool), redisStore,
		securityrevocation.DispatcherOptions{
			WorkerID: "retry-worker", RefreshTokenTTL: time.Hour, Clock: func() time.Time { return clock },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	mini.Close()
	if processed, err := dispatcher.DispatchOnce(ctx); err == nil || processed != 0 {
		t.Fatalf("Redis outage dispatch processed=%d err=%v", processed, err)
	}
	var attempt int
	var lockedBy *string
	var lastError *string
	if err := schema.pool.QueryRow(ctx, `
		SELECT attempt_count,locked_by,last_error FROM security_revocation_outbox WHERE user_id=$1
	`, userID).Scan(&attempt, &lockedBy, &lastError); err != nil {
		t.Fatal(err)
	}
	if attempt != 1 || lockedBy != nil || lastError == nil || *lastError == "" {
		t.Fatalf("retry state attempt=%d lockedBy=%v lastError=%v", attempt, lockedBy, lastError)
	}
	if err := mini.Restart(); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Second)
	if processed, err := dispatcher.DispatchOnce(ctx); err != nil || processed != 1 {
		t.Fatalf("recovered dispatch processed=%d err=%v", processed, err)
	}
	if _, err := redisStore.GetSession(ctx, "old-session"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("old session survived recovery: %v", err)
	}
	if _, err := redisStore.GetRefreshToken(ctx, "old-refresh"); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("old refresh survived recovery: %v", err)
	}
	if _, err := redisStore.GetSession(ctx, "new-session"); err != nil {
		t.Fatalf("new session was removed: %v", err)
	}
	if _, err := redisStore.GetRefreshToken(ctx, "new-refresh"); err != nil {
		t.Fatalf("new refresh was removed: %v", err)
	}
}

func TestConcurrentIdentityRemovalRetainsOneAuthenticationMethod(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	current := registrationTestUser("identity-race-"+uuid.NewString()[:8], models.UserStatusActive)
	insertRegistrationTestUser(t, schema, current)
	if _, err := schema.pool.Exec(ctx, `UPDATE users SET password_hash=NULL,password_changed_at=NULL WHERE id=$1`, current.ID); err != nil {
		t.Fatal(err)
	}
	identityIDs := []uuid.UUID{uuid.New(), uuid.New()}
	providers := []string{"provider-a", "provider-b"}
	for index, identityID := range identityIDs {
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO identities (id,user_id,provider,external_id,metadata)
			VALUES ($1,$2,$3,$4,'{}'::jsonb)
		`, identityID, current.ID, providers[index], "external-"+uuid.NewString()); err != nil {
			t.Fatal(err)
		}
	}
	store := identity.NewStore(schema.pool)
	start := make(chan struct{})
	errorsByWorker := make(chan error, 2)
	var workers sync.WaitGroup
	for index, identityID := range identityIDs {
		index, identityID := index, identityID
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			errorsByWorker <- store.DeleteOwned(ctx, current.ID, identityID, audit.MutationAudit{
				Event: models.AuditIdentityUnbound, ActorID: current.ID, ActorName: current.Username,
				Result: "success", RiskLevel: "high", IPAddress: []string{"192.0.2.1", "192.0.2.2"}[index],
			})
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByWorker)
	succeeded, retained := 0, 0
	for err := range errorsByWorker {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, identity.ErrLastAuthenticationMethod):
			retained++
		default:
			t.Fatalf("unexpected concurrent deletion error: %v", err)
		}
	}
	if succeeded != 1 || retained != 1 {
		t.Fatalf("concurrent outcomes success=%d retained=%d", succeeded, retained)
	}
	var identities, authVersion, auditEvents int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM identities WHERE user_id=$1`, current.ID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT auth_version FROM users WHERE id=$1`, current.ID).Scan(&authVersion); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_type='identity'`, models.AuditIdentityUnbound).Scan(&auditEvents); err != nil {
		t.Fatal(err)
	}
	if identities != 1 || authVersion != 2 || auditEvents != 1 {
		t.Fatalf("final state identities=%d authVersion=%d auditEvents=%d", identities, authVersion, auditEvents)
	}
}
