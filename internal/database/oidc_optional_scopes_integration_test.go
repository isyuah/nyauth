package database_test

import (
	"context"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

func TestOIDCOptionalScopesMigrationPreservesClientsAndEnforcesInvariants(t *testing.T) {
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
	if err := runner.Migrate(10); err != nil {
		t.Fatalf("migrate isolated schema to version 10: %v", err)
	}

	ctx := context.Background()
	const clientID = "optional-scope-migration-client"
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,name,redirect_uris,post_logout_redirect_uris,grants,scopes,is_public,access_policy
		) VALUES ($1,'Optional Scope Migration',ARRAY['https://client.example/callback'],ARRAY[]::text[],
			ARRAY['authorization_code','refresh_token'],ARRAY['openid','profile','email','offline_access'],TRUE,'open')
	`, clientID); err != nil {
		t.Fatalf("insert schema-10 client: %v", err)
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade isolated schema from 10 to 11: %v", err)
	}
	if err := database.ValidateSchemaVersion(ctx, schema.pool); err != nil {
		t.Fatalf("validate upgraded schema: %v", err)
	}

	stored, err := client.NewStore(schema.pool).GetByID(ctx, clientID)
	if err != nil {
		t.Fatalf("load migrated client: %v", err)
	}
	if stored.OptionalScopes == nil || len(stored.OptionalScopes) != 0 {
		t.Fatalf("legacy client optional scopes = %#v, want non-nil empty array", stored.OptionalScopes)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE oauth_clients SET optional_scopes=ARRAY['profile','offline_access'] WHERE id=$1`, clientID); err != nil {
		t.Fatalf("store valid optional scopes: %v", err)
	}

	invalidUpdates := []struct {
		name  string
		query string
	}{
		{name: "openid remains required", query: `UPDATE oauth_clients SET optional_scopes=ARRAY['openid'] WHERE id=$1`},
		{name: "optional scopes are a subset", query: `UPDATE oauth_clients SET optional_scopes=ARRAY['groups'] WHERE id=$1`},
		{name: "a required scope remains", query: `UPDATE oauth_clients SET scopes=ARRAY['profile'],optional_scopes=ARRAY['profile'] WHERE id=$1`},
		{name: "authorization code is required", query: `UPDATE oauth_clients SET grants=ARRAY['client_credentials'],scopes=ARRAY['service.read','profile'],optional_scopes=ARRAY['profile'] WHERE id=$1`},
	}
	for _, testCase := range invalidUpdates {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := schema.pool.Exec(ctx, testCase.query, clientID); !isPostgresCode(err, "23514") {
				t.Fatalf("constraint error = %v, want PostgreSQL check violation", err)
			}
		})
	}
}
