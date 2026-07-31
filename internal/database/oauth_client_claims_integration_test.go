package database_test

import (
	"context"
	"slices"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/database"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

func TestOAuthClientClaimsMigrationBackfillsExistingClientsAndEnforcesInvariants(t *testing.T) {
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
	if err := runner.Migrate(11); err != nil {
		t.Fatalf("migrate isolated schema to version 11: %v", err)
	}

	ctx := context.Background()
	const clientID = "claim-migration-client"
	userID := "11111111-1111-1111-1111-111111111112"
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,'claim-migration-user','active','user','legacy')
	`, userID); err != nil {
		t.Fatalf("insert schema-11 user: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			id,name,redirect_uris,post_logout_redirect_uris,grants,scopes,optional_scopes,is_public,access_policy
		) VALUES ($1,'Claim Migration',ARRAY['https://client.example/callback'],ARRAY[]::text[],
			ARRAY['authorization_code'],ARRAY['openid','profile','email','tenant.read'],ARRAY['email'],TRUE,'open')
	`, clientID); err != nil {
		t.Fatalf("insert schema-11 client: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_authorizations (id,user_id,client_id,scopes,granted_at,last_used_at)
		VALUES ('22222222-2222-2222-2222-222222222223',$1,$2,ARRAY['openid','profile','email'],NOW(),NOW())
	`, userID, clientID); err != nil {
		t.Fatalf("insert schema-11 authorization: %v", err)
	}
	if err := runner.Up(); err != nil {
		t.Fatalf("upgrade isolated schema from 11 to 12: %v", err)
	}
	if err := database.ValidateSchemaVersion(ctx, schema.pool); err != nil {
		t.Fatalf("validate upgraded schema: %v", err)
	}

	stored, err := client.NewStore(schema.pool).GetByID(ctx, clientID)
	if err != nil {
		t.Fatalf("load migrated client: %v", err)
	}
	wantClaims := []string{"sub", "preferred_username", "name", "picture", "email"}
	if !slices.Equal(stored.AllowedClaims, wantClaims) {
		t.Fatalf("migrated claims = %#v, want %#v", stored.AllowedClaims, wantClaims)
	}
	var authorizationClaims []string
	if err := schema.pool.QueryRow(ctx, `SELECT allowed_claims FROM oauth_authorizations WHERE user_id=$1 AND client_id=$2`, userID, clientID).Scan(&authorizationClaims); err != nil {
		t.Fatalf("load migrated authorization claims: %v", err)
	}
	if !slices.Equal(authorizationClaims, wantClaims) {
		t.Fatalf("migrated authorization claims = %#v, want %#v", authorizationClaims, wantClaims)
	}
	if _, err := schema.pool.Exec(ctx, `UPDATE oauth_clients SET allowed_claims=ARRAY['sub','name','email','role'] WHERE id=$1`, clientID); err != nil {
		t.Fatalf("store claims supplied by custom scope mappings: %v", err)
	}

	invalidUpdates := []struct {
		name  string
		query string
	}{
		{name: "unsupported claim", query: `UPDATE oauth_clients SET allowed_claims=ARRAY['sub','phone_number'] WHERE id=$1`},
		{name: "sub requires openid", query: `UPDATE oauth_clients SET scopes=ARRAY['profile'],allowed_claims=ARRAY['sub'] WHERE id=$1`},
		{name: "openid requires sub", query: `UPDATE oauth_clients SET scopes=ARRAY['openid'],allowed_claims=ARRAY[]::text[] WHERE id=$1`},
	}
	for _, testCase := range invalidUpdates {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := schema.pool.Exec(ctx, testCase.query, clientID); !isPostgresCode(err, "23514") {
				t.Fatalf("constraint error = %v, want PostgreSQL check violation", err)
			}
		})
	}
	for _, testCase := range []struct {
		name  string
		query string
	}{
		{name: "authorization unsupported claim", query: `UPDATE oauth_authorizations SET allowed_claims=ARRAY['phone_number'] WHERE user_id=$1`},
		{name: "authorization sub requires openid", query: `UPDATE oauth_authorizations SET scopes=ARRAY['profile'],allowed_claims=ARRAY['sub'] WHERE user_id=$1`},
		{name: "authorization openid requires sub", query: `UPDATE oauth_authorizations SET scopes=ARRAY['openid'],allowed_claims=ARRAY[]::text[] WHERE user_id=$1`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := schema.pool.Exec(ctx, testCase.query, userID); !isPostgresCode(err, "23514") {
				t.Fatalf("constraint error = %v, want PostgreSQL check violation", err)
			}
		})
	}
}
