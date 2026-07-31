package database_test

import (
	"context"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestOAuthPublisherTrustMigrationAndTransactionalReview(t *testing.T) {
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
	if err := runner.Migrate(12); err != nil {
		t.Fatalf("migrate isolated schema to version 12: %v", err)
	}

	ctx := context.Background()
	ownerID := uuid.New()
	reviewerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,'publisher-owner','active','user','admin'),
		       ($2,'publisher-reviewer','active','admin','admin')
	`, ownerID, reviewerID); err != nil {
		t.Fatalf("insert schema-12 users: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,name,redirect_uris,post_logout_redirect_uris,grants,scopes,optional_scopes,
			allowed_claims,is_public,access_policy
		) VALUES ('legacy-system-client','Legacy System Client',ARRAY['https://client.example/callback'],
			ARRAY[]::text[],ARRAY['authorization_code'],ARRAY['openid'],ARRAY[]::text[],ARRAY['sub'],TRUE,'open')
	`); err != nil {
		t.Fatalf("insert schema-12 client: %v", err)
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade isolated schema from 12 to 13: %v", err)
	}
	if err := database.ValidateSchemaVersion(ctx, schema.pool); err != nil {
		t.Fatalf("validate upgraded schema: %v", err)
	}

	service := client.NewService(client.NewStore(schema.pool))
	legacy, err := service.GetByID(ctx, "legacy-system-client")
	if err != nil {
		t.Fatalf("load migrated client: %v", err)
	}
	if legacy.PublisherType != models.PublisherTypeSystemManaged || legacy.PublisherVerification != models.PublisherVerificationNotApplicable {
		t.Fatalf("legacy publisher state = %q/%q", legacy.PublisherType, legacy.PublisherVerification)
	}

	created, err := service.CreateForOwner(ctx, ownerID.String(), models.CreateClientRequest{
		Name: "User Registered Client", RedirectURIs: []string{"https://user-client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
		AllowedClaims: []string{"sub"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create user-registered client: %v", err)
	}
	if created.PublisherType != models.PublisherTypeUserRegistered || created.PublisherVerification != models.PublisherVerificationUnverified {
		t.Fatalf("created publisher state = %q/%q", created.PublisherType, created.PublisherVerification)
	}

	invalidAudit := audit.MutationAudit{
		Event: models.AuditClientPublisherVerified, ActorName: "missing-reviewer",
		Result: "success", RiskLevel: "high",
	}
	if _, err := service.VerifyPublisher(ctx, created.ID, invalidAudit); err == nil {
		t.Fatal("verification with invalid audit actor unexpectedly succeeded")
	}
	rolledBack, err := service.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("reload rolled-back client: %v", err)
	}
	if rolledBack.PublisherVerification != models.PublisherVerificationUnverified {
		t.Fatalf("publisher status after audit failure = %q", rolledBack.PublisherVerification)
	}

	mutation := audit.MutationAudit{
		Event: models.AuditClientPublisherVerified, ActorID: reviewerID, ActorName: "publisher-reviewer",
		Result: "success", RiskLevel: "high",
	}
	verified, err := service.VerifyPublisher(ctx, created.ID, mutation)
	if err != nil {
		t.Fatalf("verify publisher: %v", err)
	}
	if verified.PublisherVerification != models.PublisherVerificationVerified || verified.PublisherVerifiedAt == nil || verified.PublisherVerifiedBy == nil || *verified.PublisherVerifiedBy != reviewerID.String() {
		t.Fatalf("verified publisher state = %#v", verified)
	}
	var verifiedAudits int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2`, models.AuditClientPublisherVerified, created.ID).Scan(&verifiedAudits); err != nil {
		t.Fatalf("count verification audits: %v", err)
	}
	if verifiedAudits != 1 {
		t.Fatalf("verification audit count = %d, want 1", verifiedAudits)
	}

	if _, err := schema.pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, reviewerID); err != nil {
		t.Fatalf("delete reviewer: %v", err)
	}
	verified, err = service.GetByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("reload verified client after reviewer deletion: %v", err)
	}
	if verified.PublisherVerification != models.PublisherVerificationVerified || verified.PublisherVerifiedBy != nil {
		t.Fatalf("reviewer deletion changed trust state: %#v", verified)
	}

	mutation.Event = models.AuditClientPublisherRevoked
	revoked, err := service.RevokePublisherVerification(ctx, created.ID, mutation)
	if err != nil {
		t.Fatalf("revoke publisher verification: %v", err)
	}
	if revoked.PublisherVerification != models.PublisherVerificationUnverified || revoked.PublisherVerifiedAt != nil || revoked.PublisherVerifiedBy != nil {
		t.Fatalf("revoked publisher state = %#v", revoked)
	}

	for _, testCase := range []struct {
		name, query, clientID string
	}{
		{name: "system cannot be verified", query: `UPDATE oauth_clients SET publisher_verification_status='verified',publisher_verified_at=NOW() WHERE id=$1`, clientID: "legacy-system-client"},
		{name: "user cannot use not applicable", query: `UPDATE oauth_clients SET publisher_verification_status='not_applicable' WHERE id=$1`, clientID: created.ID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := schema.pool.Exec(ctx, testCase.query, testCase.clientID); !isPostgresCode(err, "23514") {
				t.Fatalf("constraint error = %v, want PostgreSQL check violation", err)
			}
		})
	}
}
