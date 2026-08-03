package database_test

import (
	"context"
	"sync"
	"testing"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/oauthops"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestOAuthOperationsAggregateDiagnosticsAndManagementFilters(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx := context.Background()
	ownerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (id,username,status,role,creation_source) VALUES ($1,'oauth-owner','active','user','admin')`, ownerID); err != nil {
		t.Fatalf("insert owner: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id,name,redirect_uris,grants,scopes,allowed_claims,is_public,owner_id,publisher_type,publisher_verification_status)
		VALUES ('ops-client','Operations App',ARRAY['https://app.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],ARRAY['sub'],TRUE,$1,'user_registered','unverified')
	`, ownerID); err != nil {
		t.Fatalf("insert client: %v", err)
	}
	authorizationStore := authorization.NewStore(schema.pool)
	if err := authorizationStore.Upsert(ctx, ownerID, "ops-client", []string{"openid"}, []string{"sub"}, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("insert authorization: %v", err)
	}
	operations := oauthops.NewStore(schema.pool)
	const successes = 12
	errorsChannel := make(chan error, successes)
	var wait sync.WaitGroup
	for index := 0; index < successes; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- operations.Record(ctx, oauthops.Event{
				ClientID: "ops-client", Flow: oauthops.FlowAuthorizationCode, Stage: oauthops.StageToken, Outcome: oauthops.OutcomeSuccess,
			})
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("record concurrent success: %v", err)
		}
	}
	if err := operations.Record(ctx, oauthops.Event{
		ClientID: "ops-client", Flow: oauthops.FlowAuthorizationCode, Stage: oauthops.StageAuthorization,
		Outcome: oauthops.OutcomeFailure, Reason: oauthops.ReasonRedirectURIMismatch,
		RequestID: "request-1", RedirectURI: "https://app.example/callback?secret=value#fragment", Scopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("record failure: %v", err)
	}
	insights, err := operations.GetInsights(ctx, "ops-client", 7)
	if err != nil {
		t.Fatalf("GetInsights: %v", err)
	}
	if insights.Totals.Success != successes || insights.Totals.Failure != 1 || insights.ActiveAuthorizations != 1 {
		t.Fatalf("insights totals = %#v active=%d", insights.Totals, insights.ActiveAuthorizations)
	}
	diagnostics, err := operations.ListDiagnostics(ctx, oauthops.DiagnosticFilter{ClientID: "ops-client", Reason: string(oauthops.ReasonRedirectURIMismatch)})
	if err != nil {
		t.Fatalf("ListDiagnostics: %v", err)
	}
	if diagnostics.Total != 1 || diagnostics.Items[0].RedirectURI == nil || *diagnostics.Items[0].RedirectURI != "https://app.example/callback" {
		t.Fatalf("diagnostics = %#v", diagnostics)
	}
	clients, err := client.NewStore(schema.pool).ListFiltered(ctx, client.ListFilter{
		Pagination: models.NewPagination(1, 20), Query: "oauth-owner", ClientType: "public", PublisherVerification: "unverified", Ownership: "owned", Sort: "activity_desc",
	})
	if err != nil {
		t.Fatalf("ListFiltered clients: %v", err)
	}
	if clients.Total != 1 || clients.Items[0].SuccessCount7d != successes || clients.Items[0].FailureCount7d != 1 || clients.Items[0].OwnerUsername == nil || *clients.Items[0].OwnerUsername != "oauth-owner" {
		t.Fatalf("filtered clients = %#v", clients)
	}
	filteredAuthorizations, err := authorizationStore.ListByUserFiltered(ctx, authorization.ListFilter{
		UserID: ownerID, Query: "Operations", Status: "valid", Pagination: models.NewPagination(1, 20),
	})
	if err != nil || filteredAuthorizations.Total != 1 {
		t.Fatalf("valid authorization filter = %#v err=%v", filteredAuthorizations, err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE oauth_clients SET identity_revision=identity_revision+1 WHERE id='ops-client'`); err != nil {
		t.Fatalf("change client identity revision: %v", err)
	}
	changed, err := authorizationStore.ListByUserFiltered(ctx, authorization.ListFilter{UserID: ownerID, Status: "changed", Pagination: models.NewPagination(1, 20)})
	if err != nil || changed.Total != 1 || !changed.Items[0].ApplicationChanged || changed.Items[0].ReauthorizationRequired {
		t.Fatalf("changed authorization filter = %#v err=%v", changed, err)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE oauth_clients SET authorization_revision=authorization_revision+1 WHERE id='ops-client'`); err != nil {
		t.Fatalf("change client authorization revision: %v", err)
	}
	reauthorize, err := authorizationStore.ListByUserFiltered(ctx, authorization.ListFilter{UserID: ownerID, Status: "reauthorization_required", Pagination: models.NewPagination(1, 20)})
	if err != nil || reauthorize.Total != 1 || !reauthorize.Items[0].ReauthorizationRequired {
		t.Fatalf("reauthorization filter = %#v err=%v", reauthorize, err)
	}
}

func TestOAuthOperationsUpgradeSchema17To18(t *testing.T) {
	schema := newPostgresTestSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open migrations: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		t.Fatalf("create migration runner: %v", err)
	}
	t.Cleanup(func() { _, _ = runner.Close() })
	if err := runner.Migrate(17); err != nil {
		t.Fatalf("migrate to schema 17: %v", err)
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade schema 17 to 18: %v", err)
	}
	if err := database.ValidateSchemaVersion(context.Background(), schema.pool); err != nil {
		t.Fatalf("ValidateSchemaVersion: %v", err)
	}
	for _, table := range []string{"oauth_client_stats_daily", "oauth_client_diagnostics", "provider_diagnostic_runs"} {
		var resolved *string
		if err := schema.pool.QueryRow(context.Background(), `SELECT to_regclass($1)::text`, table).Scan(&resolved); err != nil || resolved == nil {
			t.Fatalf("table %s missing: resolved=%v err=%v", table, resolved, err)
		}
	}
}
