package database_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

const postgresTestDSNEnv = "NYAUTH_TEST_DATABASE_DSN"

type postgresTestSchema struct {
	name         string
	migrationDSN string
	pool         *pgxpool.Pool
}

func newPostgresTestSchema(t *testing.T) *postgresTestSchema {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv(postgresTestDSNEnv))
	if baseDSN == "" {
		t.Skipf("%s is not set", postgresTestDSNEnv)
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

	schemaName := "nyauth_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

	return &postgresTestSchema{
		name:         schemaName,
		migrationDSN: postgresDSNWithSearchPath(t, baseDSN, schemaName),
		pool:         scopedPool,
	}
}

func postgresDSNWithSearchPath(t *testing.T, dsn, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schemaName)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	// lib/pq keyword/value DSNs accept search_path as a connection parameter.
	// schemaName is generated from a UUID and therefore needs no value quoting.
	return strings.TrimSpace(dsn) + " search_path=" + schemaName
}

func TestConcurrentBaselineMigrationInIsolatedSchema(t *testing.T) {
	schema := newPostgresTestSchema(t)
	start := make(chan struct{})
	errorsByWorker := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			errorsByWorker <- database.RunMigrations(schema.migrationDSN)
		}()
	}
	close(start)
	workers.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatalf("concurrent RunMigrations error: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var migrationRows int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationRows); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if migrationRows != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", migrationRows)
	}

	assertColumn(t, schema, "users", "auth_version", "NO")
	assertColumn(t, schema, "users", "must_change_password", "NO")
	assertColumn(t, schema, "users", "password_hash", "YES")
	assertColumn(t, schema, "oauth_clients", "post_logout_redirect_uris", "NO")
	assertMissingColumns(t, schema, "identities", "access_token", "refresh_token", "token_expires_at")
	assertColumn(t, schema, "jwk_keys", "encrypted_private_key", "YES")
	assertColumn(t, schema, "jwk_keys", "status", "NO")
	assertColumn(t, schema, "jwk_keys", "signing_started_at", "NO")
	assertColumn(t, schema, "jwk_keys", "verify_until", "NO")
	assertMissingColumns(t, schema, "jwk_keys", "private_key", "is_active", "expires_at")
	for _, constraintName := range []string{
		"users_auth_version_positive",
		"oauth_clients_secret_kind_consistent",
		"oauth_providers_generic_discovery_required",
		"identities_external_unique",
		"jwk_keys_status_valid",
		"jwk_keys_private_key_lifecycle",
		"jwk_keys_verify_window_valid",
	} {
		assertConstraint(t, schema, constraintName)
	}
}

func TestClientQuotaIsAtomicAcrossConcurrentCreates(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ownerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb)
	`, ownerID, "quota-owner-"+ownerID.String()); err != nil {
		t.Fatalf("insert owner: %v", err)
	}

	store := client.NewStore(schema.pool)
	start := make(chan struct{})
	results := make(chan error, 20)
	var workers sync.WaitGroup
	for i := range 20 {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			secret := crypto.HashClientSecret(fmt.Sprintf("integration-secret-%d", index))
			registered := &models.OAuthClient{
				ID: fmt.Sprintf("quota-client-%02d-%s", index, uuid.NewString()), SecretHash: &secret,
				Name: fmt.Sprintf("Quota client %d", index), RedirectURIs: []string{"https://client.example/callback"},
				PostLogoutRedirectURIs: []string{}, Grants: []string{models.GrantAuthorizationCode},
				Scopes: []string{"openid"}, IsPublic: false, Metadata: map[string]string{},
			}
			results <- store.CreateForOwner(ctx, registered, ownerID.String(), 10)
		}(i)
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
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if succeeded != 10 || quotaRejected != 10 {
		t.Fatalf("concurrent results: succeeded=%d quota_rejected=%d, want 10/10", succeeded, quotaRejected)
	}
	var stored int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients WHERE owner_id=$1`, ownerID).Scan(&stored); err != nil {
		t.Fatalf("count stored clients: %v", err)
	}
	if stored != 10 {
		t.Fatalf("stored clients = %d, want 10", stored)
	}
}

func assertColumn(t *testing.T, schema *postgresTestSchema, tableName, columnName, nullable string) {
	t.Helper()
	var actualNullable string
	err := schema.pool.QueryRow(context.Background(), `
		SELECT is_nullable FROM information_schema.columns
		WHERE table_schema=$1 AND table_name=$2 AND column_name=$3
	`, schema.name, tableName, columnName).Scan(&actualNullable)
	if err != nil {
		t.Fatalf("column %s.%s missing: %v", tableName, columnName, err)
	}
	if actualNullable != nullable {
		t.Fatalf("column %s.%s is_nullable=%s, want %s", tableName, columnName, actualNullable, nullable)
	}
}

func assertMissingColumns(t *testing.T, schema *postgresTestSchema, tableName string, columnNames ...string) {
	t.Helper()
	var count int
	err := schema.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=$1 AND table_name=$2 AND column_name = ANY($3)
	`, schema.name, tableName, columnNames).Scan(&count)
	if err != nil {
		t.Fatalf("check removed columns on %s: %v", tableName, err)
	}
	if count != 0 {
		t.Fatalf("table %s retained %d removed token/lifecycle columns from %v", tableName, count, columnNames)
	}
}

func assertConstraint(t *testing.T, schema *postgresTestSchema, constraintName string) {
	t.Helper()
	var exists bool
	err := schema.pool.QueryRow(context.Background(), `
		SELECT EXISTS (
			SELECT 1 FROM pg_constraint c
			JOIN pg_namespace n ON n.oid=c.connamespace
			WHERE n.nspname=$1 AND c.conname=$2
		)
	`, schema.name, constraintName).Scan(&exists)
	if err != nil {
		t.Fatalf("check constraint %s: %v", constraintName, err)
	}
	if !exists {
		t.Fatalf("constraint %s is missing", constraintName)
	}
}
