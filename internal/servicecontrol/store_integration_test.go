package servicecontrol

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/runtimecoord"
)

type serviceControlTestSchema struct {
	migrationDSN string
	pool         *pgxpool.Pool
}

func newServiceControlTestSchema(t *testing.T) *serviceControlTestSchema {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv("NYAUTH_TEST_DATABASE_DSN"))
	if baseDSN == "" {
		t.Skip("NYAUTH_TEST_DATABASE_DSN is not set; skipping service control PostgreSQL integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	basePool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect test PostgreSQL: %v", err)
	}
	if err := basePool.Ping(ctx); err != nil {
		basePool.Close()
		t.Fatalf("ping test PostgreSQL: %v", err)
	}

	schemaName := "nyauth_service_control_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		basePool.Close()
		t.Fatalf("create isolated schema: %v", err)
	}
	poolConfig, err := pgxpool.ParseConfig(baseDSN)
	if err != nil {
		_, _ = basePool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		basePool.Close()
		t.Fatalf("parse PostgreSQL DSN: %v", err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schemaName
	scopedPool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		_, _ = basePool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		basePool.Close()
		t.Fatalf("connect isolated schema: %v", err)
	}
	t.Cleanup(func() {
		scopedPool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := basePool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema %s: %v", schemaName, err)
		}
		basePool.Close()
	})
	return &serviceControlTestSchema{
		migrationDSN: serviceControlDSNWithSearchPath(t, baseDSN, schemaName),
		pool:         scopedPool,
	}
}

func serviceControlDSNWithSearchPath(t *testing.T, dsn, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schemaName)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return strings.TrimSpace(dsn) + " search_path=" + schemaName
}

func newServiceControlStore(t *testing.T) (*serviceControlTestSchema, *Store, uuid.UUID) {
	t.Helper()
	schema := newServiceControlTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run service control migrations: %v", err)
	}
	store, err := NewStore(schema.pool)
	if err != nil {
		t.Fatalf("create service control store: %v", err)
	}
	actorID := uuid.New()
	if _, err := schema.pool.Exec(t.Context(), `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,$2,'active','admin','legacy')
	`, actorID, "service-control-admin-"+strings.ReplaceAll(actorID.String(), "-", "")); err != nil {
		t.Fatalf("insert service control administrator: %v", err)
	}
	return schema, store, actorID
}

func serviceControlAudit(actorID uuid.UUID, actorName string) audit.MutationAudit {
	return audit.MutationAudit{
		Event: AuditUpdated, ActorID: actorID, ActorName: actorName,
		Result: "success", RiskLevel: "critical", IPAddress: "192.0.2.44",
		UserAgent: "service-control-integration-test",
	}
}

func TestServiceControlStoreLifecycleConcurrencyAndCoordination(t *testing.T) {
	schema, store, actorID := newServiceControlStore(t)
	ctx := t.Context()
	initial, err := store.LoadSnapshot(ctx)
	if err != nil {
		t.Fatalf("load initial state: %v", err)
	}
	if initial.Revision != 1 || len(initial.PausedCapabilities) != 0 ||
		initial.DatabaseNow.IsZero() || initial.ObservedAt.IsZero() {
		t.Fatalf("initial state = %#v", initial)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO service_control_pauses (capability) VALUES ('future_capability')
	`); err == nil {
		t.Fatal("migration accepted an unknown capability")
	}

	updated, err := store.Update(ctx, UpdateInput{
		ExpectedRevision: 1,
		PausedCapabilities: []Capability{
			CapabilityAuthIssuance, CapabilitySelfRegistration, CapabilityAuthIssuance,
		},
		PublicMessage:  "  authentication maintenance  ",
		InternalReason: "  rotating signing infrastructure  ",
		UpdatedBy:      actorID, UpdatedByName: "  operations-admin  ",
		Audit: serviceControlAudit(actorID, "operations-admin"),
	})
	if err != nil {
		t.Fatalf("update service control: %v", err)
	}
	if updated.Revision != 2 || updated.PublicMessage != "authentication maintenance" ||
		updated.InternalReason != "rotating signing infrastructure" ||
		updated.UpdatedByName == nil || *updated.UpdatedByName != "operations-admin" {
		t.Fatalf("trimmed updated state = %#v", updated)
	}
	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='settings' AND aggregate_id='operations'
	`, AuditUpdated).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("transactional update audit count = %d, err=%v", auditCount, err)
	}
	if _, err := store.Update(ctx, UpdateInput{
		ExpectedRevision: 1, PausedCapabilities: []Capability{CapabilityAccountMutations},
		InternalReason: "stale update", UpdatedBy: actorID, UpdatedByName: "admin",
		Audit: serviceControlAudit(actorID, "admin"),
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error = %v, want ErrRevisionConflict", err)
	}

	start := make(chan struct{})
	errorsByWriter := make(chan error, 2)
	var writers sync.WaitGroup
	for _, capability := range []Capability{CapabilityAccountMutations, CapabilityAdminMutations} {
		capability := capability
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			_, updateErr := store.Update(context.Background(), UpdateInput{
				ExpectedRevision: 2, PausedCapabilities: []Capability{capability},
				InternalReason: "concurrent maintenance", UpdatedBy: actorID,
				UpdatedByName: "concurrent-admin", Audit: serviceControlAudit(actorID, "concurrent-admin"),
			})
			errorsByWriter <- updateErr
		}()
	}
	close(start)
	writers.Wait()
	close(errorsByWriter)
	var succeeded, conflicted int
	for updateErr := range errorsByWriter {
		switch {
		case updateErr == nil:
			succeeded++
		case errors.Is(updateErr, ErrRevisionConflict):
			conflicted++
		default:
			t.Fatalf("concurrent update error = %v", updateErr)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent updates succeeded=%d conflicted=%d, want 1/1", succeeded, conflicted)
	}
	current, err := store.LoadSnapshot(ctx)
	if err != nil || current.Revision != 3 {
		t.Fatalf("state after concurrent updates = %#v, err=%v", current, err)
	}

	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO runtime_settings (key,value,updated_by,updated_at)
		VALUES ('registration','{"mode":"open"}'::jsonb,'test',now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
	`); err != nil {
		t.Fatalf("open registration fixture: %v", err)
	}
	if _, err := store.Update(ctx, UpdateInput{
		ExpectedRevision: 3, PausedCapabilities: []Capability{CapabilityMailDelivery},
		InternalReason: "mail maintenance", UpdatedBy: actorID, UpdatedByName: "admin",
		Audit: serviceControlAudit(actorID, "admin"),
	}); !errors.Is(err, ErrDependencyViolation) {
		t.Fatalf("mail/registration dependency error = %v", err)
	}
	current, err = store.Update(ctx, UpdateInput{
		ExpectedRevision:   3,
		PausedCapabilities: []Capability{CapabilityMailDelivery, CapabilitySelfRegistration},
		InternalReason:     "mail maintenance", UpdatedBy: actorID, UpdatedByName: "admin",
		Audit: serviceControlAudit(actorID, "admin"),
	})
	if err != nil || current.Revision != 4 {
		t.Fatalf("valid mail pause state = %#v, err=%v", current, err)
	}

	reset, err := store.Reset(ctx, ResetInput{Reason: " emergency recovery ", ActorName: " operator "})
	if err != nil || reset.Revision != 5 || len(reset.PausedCapabilities) != 0 {
		t.Fatalf("CLI reset state = %#v, err=%v", reset, err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, AuditCLIReset).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("CLI reset audit count = %d, err=%v", auditCount, err)
	}

	instanceID := uuid.New()
	if _, err := store.RegisterInstance(ctx, RegisterInstanceInput{
		ID: instanceID, Version: "0.5.0-rc.1", StartedAt: time.Now().UTC(),
		LoadedRevision: 5, AppliedRevision: 4,
	}); err != nil {
		t.Fatalf("register instance: %v", err)
	}
	status, err := store.ApplicationStatus(ctx, 5, time.Minute)
	if err != nil || status.Applied || status.ActiveInstances != 1 || status.AppliedInstances != 0 {
		t.Fatalf("pending application status = %#v, err=%v", status, err)
	}
	if _, err := store.Heartbeat(ctx, HeartbeatInput{
		ID: instanceID, LoadedRevision: 5, AppliedRevision: 4,
	}); err != nil {
		t.Fatalf("heartbeat pending instance: %v", err)
	}
	if _, err := store.ConfirmApplied(ctx, instanceID, 5); err != nil {
		t.Fatalf("confirm instance revision: %v", err)
	}
	status, err = store.WaitForApplied(ctx, 5, time.Minute)
	if err != nil || !status.Applied || status.AppliedInstances != 1 {
		t.Fatalf("applied status = %#v, err=%v", status, err)
	}

	expires := time.Now().UTC().Add(2 * time.Minute)
	current, err = store.Update(ctx, UpdateInput{
		ExpectedRevision: 5, PausedCapabilities: []Capability{CapabilityMediaWrites},
		InternalReason: "temporary media maintenance", ExpiresAt: &expires,
		UpdatedBy: actorID, UpdatedByName: "admin", Audit: serviceControlAudit(actorID, "admin"),
	})
	if err != nil || current.Revision != 6 {
		t.Fatalf("create expiring state = %#v, err=%v", current, err)
	}
	if _, err := schema.pool.Exec(ctx, `
		UPDATE service_control_state SET expires_at=clock_timestamp()-interval '1 second'
		WHERE singleton=TRUE
	`); err != nil {
		t.Fatalf("expire state fixture: %v", err)
	}
	expired, err := store.TryExpire(ctx)
	if err != nil || !expired.Leader || !expired.Expired || expired.State.Revision != 7 {
		t.Fatalf("expiration result = %#v, err=%v", expired, err)
	}
	again, err := store.TryExpire(ctx)
	if err != nil || !again.Leader || again.Expired {
		t.Fatalf("second expiration result = %#v, err=%v", again, err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1`, AuditExpired).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("expiration audit count = %d, err=%v", auditCount, err)
	}
}

func TestServiceControlAuditFailureRollsBackState(t *testing.T) {
	schema, store, actorID := newServiceControlStore(t)
	ctx := t.Context()
	if _, err := schema.pool.Exec(ctx, `DROP TABLE audit_event_outbox`); err != nil {
		t.Fatalf("remove audit outbox failure fixture: %v", err)
	}
	_, err := store.Update(ctx, UpdateInput{
		ExpectedRevision: 1, PausedCapabilities: []Capability{CapabilityAccountMutations},
		InternalReason: "transaction rollback test", UpdatedBy: actorID, UpdatedByName: "admin",
		Audit: serviceControlAudit(actorID, "admin"),
	})
	if err == nil || !strings.Contains(err.Error(), "auditing service control update") {
		t.Fatalf("audit failure error = %v", err)
	}
	var revision int64
	var pauses int
	if err := schema.pool.QueryRow(ctx, `
		SELECT state.revision,(SELECT COUNT(*) FROM service_control_pauses)
		FROM service_control_state AS state WHERE singleton=TRUE
	`).Scan(&revision, &pauses); err != nil {
		t.Fatalf("load rolled-back service control state: %v", err)
	}
	if revision != 1 || pauses != 0 {
		t.Fatalf("state after audit failure = revision %d pauses %d, want 1/0", revision, pauses)
	}
}

func TestServiceControlUpdateSerializesWithRegistrationPolicy(t *testing.T) {
	schema, store, actorID := newServiceControlStore(t)
	ctx := t.Context()
	registrationTx, err := schema.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin registration policy transaction: %v", err)
	}
	defer registrationTx.Rollback(context.Background())
	if err := runtimecoord.LockRegistrationExclusive(ctx, registrationTx); err != nil {
		t.Fatalf("lock registration policy: %v", err)
	}
	if _, err := registrationTx.Exec(ctx, `
		INSERT INTO runtime_settings (key,value,updated_by,updated_at)
		VALUES ('registration','{"mode":"open"}'::jsonb,'test',now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()
	`); err != nil {
		t.Fatalf("stage open registration policy: %v", err)
	}

	updateDone := make(chan error, 1)
	go func() {
		_, updateErr := store.Update(context.Background(), UpdateInput{
			ExpectedRevision: 1, PausedCapabilities: []Capability{CapabilityMailDelivery},
			InternalReason: "mail maintenance", UpdatedBy: actorID, UpdatedByName: "admin",
			Audit: serviceControlAudit(actorID, "admin"),
		})
		updateDone <- updateErr
	}()
	select {
	case updateErr := <-updateDone:
		t.Fatalf("service control update bypassed registration lock: %v", updateErr)
	case <-time.After(100 * time.Millisecond):
	}
	if err := registrationTx.Commit(ctx); err != nil {
		t.Fatalf("commit registration policy: %v", err)
	}
	select {
	case updateErr := <-updateDone:
		if !errors.Is(updateErr, ErrDependencyViolation) {
			t.Fatalf("post-commit dependency error = %v", updateErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service control update remained blocked after registration commit")
	}
	snapshot, err := store.LoadSnapshot(ctx)
	if err != nil || snapshot.Revision != 1 || len(snapshot.PausedCapabilities) != 0 {
		t.Fatalf("rejected concurrent update changed state = %#v, err=%v", snapshot, err)
	}
}

func TestServiceControlManagersSynchronizeAcrossInstances(t *testing.T) {
	_, store, actorID := newServiceControlStore(t)
	options := func() ManagerOptions {
		return ManagerOptions{
			InstanceID: uuid.New(), Version: "0.5.0-rc.1", StartedAt: time.Now().UTC(),
			HeartbeatInterval: 50 * time.Millisecond, ReconciliationInterval: 50 * time.Millisecond,
			ApplyTimeout: 2 * time.Second, StaleAfter: 3 * time.Second,
			CleanupInterval: time.Second, InstanceRetention: 4 * time.Second,
			OnError: func(err error) {
				if !errors.Is(err, context.Canceled) {
					t.Logf("manager synchronization error: %v", err)
				}
			},
		}
	}
	firstOptions, secondOptions := options(), options()
	firstController := NewController(ControllerOptions{StaleAfter: firstOptions.StaleAfter})
	secondController := NewController(ControllerOptions{StaleAfter: secondOptions.StaleAfter})
	first, err := NewManager(store, firstController, firstOptions)
	if err != nil {
		t.Fatalf("create first manager: %v", err)
	}
	second, err := NewManager(store, secondController, secondOptions)
	if err != nil {
		t.Fatalf("create second manager: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := first.Start(ctx); err != nil {
		t.Fatalf("start first manager: %v", err)
	}
	if err := second.Start(ctx); err != nil {
		t.Fatalf("start second manager: %v", err)
	}
	state, err := first.Update(ctx, 1, UpdateRequest{
		PausedCapabilities: []Capability{CapabilityAccountMutations},
		InternalReason:     "HA synchronization test",
	}, serviceControlAudit(actorID, "ha-admin"))
	if err != nil || state.Snapshot.Revision != 2 || !state.Applied || state.AppliedInstances != 2 {
		t.Fatalf("update through first manager = %#v, err=%v", state, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for second.Snapshot().Revision != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if second.Snapshot().Revision != 2 {
		t.Fatalf("second manager did not load revision 2: %#v", second.Snapshot())
	}
	if _, err := second.Acquire(CapabilityAccountMutations); !errors.Is(err, ErrCapabilityPaused) {
		t.Fatalf("second manager did not enforce synchronized pause: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(ctx, 2*time.Second)
	defer waitCancel()
	status, err := first.WaitApplied(waitCtx, 2)
	if err != nil || !status.Applied || status.AppliedInstances != 2 {
		t.Fatalf("HA application status = %#v, err=%v", status, err)
	}
	cancel()
	shutdownDeadline := time.Now().Add(time.Second)
	for time.Now().Before(shutdownDeadline) {
		shutdownStatus, statusErr := store.ApplicationStatus(context.Background(), 2, time.Minute)
		if statusErr == nil && shutdownStatus.ActiveInstances == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}
