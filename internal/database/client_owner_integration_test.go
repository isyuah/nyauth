package database_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestClientOwnerAssignmentValidationAndAuditAreAtomic(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	activeOwnerID := uuid.New()
	inactiveOwnerID := uuid.New()
	insertClientOwnerUser(t, ctx, schema.pool, activeOwnerID, "active")
	insertClientOwnerUser(t, ctx, schema.pool, inactiveOwnerID, "suspended")
	service := client.NewService(client.NewStore(schema.pool))
	adminCreated, err := service.CreateAdmin(ctx, clientOwnerCreateRequest("Admin owned", stringPointer(activeOwnerID.String())), clientCreatedMutation(activeOwnerID))
	if err != nil {
		t.Fatalf("admin create owned client: %v", err)
	}
	if adminCreated.OwnerID == nil || *adminCreated.OwnerID != activeOwnerID.String() {
		t.Fatalf("admin-created client owner = %v", adminCreated.OwnerID)
	}
	var createAuditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='client' AND aggregate_id=$2
	`, models.AuditClientCreated, adminCreated.ID).Scan(&createAuditCount); err != nil {
		t.Fatalf("count admin client creation audit: %v", err)
	}
	if createAuditCount != 1 {
		t.Fatalf("admin client creation audit rows = %d, want 1", createAuditCount)
	}
	badCreateMutation := clientCreatedMutation(activeOwnerID)
	badCreateMutation.Details = map[string]any{"client_secret": "must-not-be-audited"}
	if _, err := service.CreateAdmin(ctx, clientOwnerCreateRequest("Rolled back admin create", nil), badCreateMutation); err == nil {
		t.Fatal("admin client creation succeeded after audit payload rejection")
	}
	var rolledBackCreates int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE name='Rolled back admin create'`).Scan(&rolledBackCreates); err != nil {
		t.Fatalf("count rolled back admin clients: %v", err)
	}
	if rolledBackCreates != 0 {
		t.Fatalf("failed creation audit left %d client rows", rolledBackCreates)
	}
	created, err := service.Create(ctx, clientOwnerCreateRequest("Owner lifecycle", nil))
	if err != nil {
		t.Fatalf("create ownerless client: %v", err)
	}
	mutation := clientOwnerMutation(activeOwnerID)

	missingOwnerID := uuid.NewString()
	if _, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: &missingOwnerID}, mutation); !errors.Is(err, client.ErrClientOwnerUnavailable) {
		t.Fatalf("missing owner error = %v", err)
	}
	inactive := inactiveOwnerID.String()
	if _, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: &inactive}, mutation); !errors.Is(err, client.ErrClientOwnerUnavailable) {
		t.Fatalf("inactive owner error = %v", err)
	}
	if _, err := service.CreateAdmin(ctx, clientOwnerCreateRequest("Inactive owner", &inactive), clientCreatedMutation(activeOwnerID)); !errors.Is(err, client.ErrClientOwnerUnavailable) {
		t.Fatalf("admin create for inactive owner error = %v", err)
	}

	racingOwnerID := uuid.New()
	insertClientOwnerUser(t, ctx, schema.pool, racingOwnerID, "active")
	raceCandidate, err := service.Create(ctx, clientOwnerCreateRequest("Concurrent suspension", nil))
	if err != nil {
		t.Fatalf("create concurrent suspension candidate: %v", err)
	}
	statusTx, err := schema.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin owner suspension: %v", err)
	}
	defer statusTx.Rollback(ctx)
	if _, err := statusTx.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, racingOwnerID); err != nil {
		t.Fatalf("stage owner suspension: %v", err)
	}
	racingOwner := racingOwnerID.String()
	raceResult := make(chan error, 1)
	go func() {
		_, updateErr := service.UpdateOwner(ctx, raceCandidate.ID, models.UpdateClientOwnerRequest{OwnerID: &racingOwner}, mutation)
		raceResult <- updateErr
	}()
	select {
	case updateErr := <-raceResult:
		t.Fatalf("owner assignment did not wait for concurrent status update: %v", updateErr)
	case <-time.After(150 * time.Millisecond):
	}
	if err := statusTx.Commit(ctx); err != nil {
		t.Fatalf("commit owner suspension: %v", err)
	}
	select {
	case updateErr := <-raceResult:
		if !errors.Is(updateErr, client.ErrClientOwnerUnavailable) {
			t.Fatalf("concurrent suspension owner assignment error = %v", updateErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner assignment remained blocked after status update committed")
	}
	afterSuspension, err := service.GetByID(ctx, raceCandidate.ID)
	if err != nil {
		t.Fatalf("get concurrent suspension candidate: %v", err)
	}
	if afterSuspension.OwnerID != nil {
		t.Fatalf("concurrent suspension left owner assigned: %v", afterSuspension.OwnerID)
	}

	active := activeOwnerID.String()
	badMutation := mutation
	badMutation.Details = map[string]any{"client_secret": "must-not-be-audited"}
	if _, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: &active}, badMutation); err == nil {
		t.Fatal("owner assignment succeeded after audit payload rejection")
	}
	afterRollback, err := service.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get client after rolled back assignment: %v", err)
	}
	if afterRollback.OwnerID != nil {
		t.Fatalf("failed audit left owner assigned: %v", afterRollback.OwnerID)
	}

	assigned, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: &active}, mutation)
	if err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if assigned.ID != created.ID || assigned.Name != created.Name || assigned.OwnerID == nil || *assigned.OwnerID != active {
		t.Fatalf("assignment did not return complete updated client: %#v", assigned)
	}

	var payloadBytes []byte
	if err := schema.pool.QueryRow(ctx, `
		SELECT payload FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='client' AND aggregate_id=$2
		ORDER BY created_at LIMIT 1
	`, models.AuditClientOwnerChanged, created.ID).Scan(&payloadBytes); err != nil {
		t.Fatalf("read owner assignment audit: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode owner assignment audit: %v", err)
	}
	details, ok := payload["details"].(map[string]any)
	if !ok || details["old_owner_id"] != nil || details["new_owner_id"] != active {
		t.Fatalf("unexpected owner assignment audit details: %#v", payload["details"])
	}

	unassigned, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: nil}, mutation)
	if err != nil {
		t.Fatalf("remove owner: %v", err)
	}
	if unassigned.OwnerID != nil {
		t.Fatalf("owner was not removed: %#v", unassigned.OwnerID)
	}
	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2
	`, models.AuditClientOwnerChanged, created.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count owner audit rows: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("owner audit rows = %d, want 2", auditCount)
	}
	if _, err := service.UpdateOwner(ctx, created.ID, models.UpdateClientOwnerRequest{OwnerID: &active}, mutation); err != nil {
		t.Fatalf("reassign owner before deletion: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, activeOwnerID); err != nil {
		t.Fatalf("delete client owner: %v", err)
	}
	for _, clientID := range []string{created.ID, adminCreated.ID} {
		preserved, err := service.GetByID(ctx, clientID)
		if err != nil {
			t.Fatalf("get client %s after owner deletion: %v", clientID, err)
		}
		if preserved.OwnerID != nil {
			t.Fatalf("client %s owner after user deletion = %v, want nil", clientID, preserved.OwnerID)
		}
	}
}

func TestConcurrentClientOwnerCreatesAndTransfersRespectQuota(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ownerID := uuid.New()
	insertClientOwnerUser(t, ctx, schema.pool, ownerID, "active")
	service := client.NewService(client.NewStore(schema.pool))
	owner := ownerID.String()
	for index := range 9 {
		if _, err := service.CreateForOwner(ctx, owner, 10, clientOwnerCreateRequest(fmt.Sprintf("Owned %d", index), nil)); err != nil {
			t.Fatalf("seed owned client %d: %v", index, err)
		}
	}

	const transferCandidates = 4
	const createCandidates = 4
	const candidates = transferCandidates + createCandidates
	clientIDs := make([]string, 0, transferCandidates)
	for index := range transferCandidates {
		created, err := service.Create(ctx, clientOwnerCreateRequest(fmt.Sprintf("Candidate %d", index), nil))
		if err != nil {
			t.Fatalf("seed candidate client %d: %v", index, err)
		}
		clientIDs = append(clientIDs, created.ID)
	}

	start := make(chan struct{})
	results := make(chan error, candidates)
	var workers sync.WaitGroup
	for _, clientID := range clientIDs {
		clientID := clientID
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := service.UpdateOwner(ctx, clientID, models.UpdateClientOwnerRequest{OwnerID: &owner}, clientOwnerMutation(ownerID))
			results <- err
		}()
	}
	for index := range createCandidates {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := service.CreateAdmin(ctx, clientOwnerCreateRequest(fmt.Sprintf("Concurrent admin create %d", index), &owner), clientCreatedMutation(ownerID))
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	succeeded, quotaRejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, client.ErrClientQuotaExceeded):
			quotaRejected++
		default:
			t.Fatalf("unexpected concurrent transfer error: %v", err)
		}
	}
	if succeeded != 1 || quotaRejected != candidates-1 {
		t.Fatalf("concurrent results: succeeded=%d quota_rejected=%d, want 1/%d", succeeded, quotaRejected, candidates-1)
	}
	var ownedCount, auditCount int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&ownedCount); err != nil {
		t.Fatalf("count owned clients: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox WHERE event IN ($1,$2)
	`, models.AuditClientOwnerChanged, models.AuditClientCreated).Scan(&auditCount); err != nil {
		t.Fatalf("count owner transfer audit rows: %v", err)
	}
	if ownedCount != 10 || auditCount != 1 {
		t.Fatalf("owned clients=%d audit rows=%d, want 10/1", ownedCount, auditCount)
	}
}

func TestClientConfigurationUpdateAndAuditAreAtomic(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	service := client.NewService(client.NewStore(schema.pool))
	created, err := service.Create(ctx, clientOwnerCreateRequest("Before update", nil))
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	updatedName := "After update"
	request := models.UpdateClientRequest{Name: &updatedName}
	mutation := audit.MutationAudit{
		Event: models.AuditClientUpdated, ActorID: uuid.New(), ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", IPAddress: "203.0.113.24", UserAgent: "nyauth-integration-test",
	}
	badMutation := mutation
	badMutation.Details = map[string]any{"client_secret": "must-not-be-audited"}
	if _, err := service.Update(ctx, created.ID, request, badMutation); err == nil {
		t.Fatal("client update succeeded after audit payload rejection")
	}
	rolledBack, err := service.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("get client after rolled back update: %v", err)
	}
	if rolledBack.Name != "Before update" {
		t.Fatalf("failed audit left client name %q", rolledBack.Name)
	}

	updated, err := service.Update(ctx, created.ID, request, mutation)
	if err != nil {
		t.Fatalf("update client: %v", err)
	}
	if updated.Name != updatedName {
		t.Fatalf("updated client name = %q", updated.Name)
	}
	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='client' AND aggregate_id=$2
	`, models.AuditClientUpdated, created.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count client update audit rows: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("client update audit rows = %d, want 1", auditCount)
	}
}

func insertClientOwnerUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID, status string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata)
		VALUES ($1,$2,$3,'user',1,FALSE,'{}'::jsonb)
	`, id, "client-owner-"+id.String(), status); err != nil {
		t.Fatalf("insert %s owner: %v", status, err)
	}
}

func clientOwnerCreateRequest(name string, ownerID *string) models.CreateClientRequest {
	return models.CreateClientRequest{
		Name: name, RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"}, OwnerID: ownerID,
	}
}

func clientOwnerMutation(actorID uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{
		Event: models.AuditClientOwnerChanged, ActorID: actorID, ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", IPAddress: "203.0.113.24", UserAgent: "nyauth-integration-test",
	}
}

func clientCreatedMutation(actorID uuid.UUID) audit.MutationAudit {
	return audit.MutationAudit{
		Event: models.AuditClientCreated, ActorID: actorID, ActorName: "integration-admin",
		Result: "success", RiskLevel: "low", IPAddress: "203.0.113.24", UserAgent: "nyauth-integration-test",
	}
}

func stringPointer(value string) *string { return &value }
