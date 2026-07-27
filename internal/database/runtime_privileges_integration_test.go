package database_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/database"
)

func TestEnsureRuntimePrivilegesRestrictsRuntimeRole(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run baseline migration: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	role, password := createRuntimeRole(t, schema, ctx)
	var runtimePool *pgxpool.Pool
	t.Cleanup(func() {
		if runtimePool != nil {
			runtimePool.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		roleIdentifier := pgx.Identifier{role}.Sanitize()
		_, _ = schema.pool.Exec(cleanupCtx, "DROP OWNED BY "+roleIdentifier)
		_, _ = schema.pool.Exec(cleanupCtx, "DROP ROLE "+roleIdentifier)
	})
	if _, err := schema.pool.Exec(ctx, `
		CREATE TYPE runtime_existing_state AS ENUM ('ready');
		REVOKE ALL PRIVILEGES ON TYPE runtime_existing_state FROM PUBLIC;
		CREATE TABLE runtime_existing_privilege_probe (
			id BIGSERIAL PRIMARY KEY,
			state runtime_existing_state NOT NULL
		);
		CREATE FUNCTION runtime_existing_probe_value() RETURNS integer
		LANGUAGE SQL IMMUTABLE AS 'SELECT 21';
		REVOKE ALL PRIVILEGES ON FUNCTION runtime_existing_probe_value() FROM PUBLIC;
	`); err != nil {
		t.Fatalf("create existing privilege probe objects: %v", err)
	}
	if err := database.EnsureRuntimePrivileges(ctx, schema.pool, role); err != nil {
		t.Fatalf("ensure runtime privileges: %v", err)
	}

	runtimePool = newRuntimePool(t, schema.migrationDSN, role, password)

	if err := database.ValidateRuntimeRole(ctx, runtimePool, role); err != nil {
		t.Fatalf("validate runtime role: %v", err)
	}
	if err := database.ValidateRuntimeRole(ctx, runtimePool, "different_runtime_role"); err == nil {
		t.Fatal("runtime role validation accepted a mismatched current_user")
	}
	var existingProbeID int64
	if err := runtimePool.QueryRow(ctx, `INSERT INTO runtime_existing_privilege_probe (state) VALUES ('ready') RETURNING id`).Scan(&existingProbeID); err != nil {
		t.Fatalf("runtime role lacks existing sequence/type/table privileges: %v", err)
	}
	var existingProbeValue int
	if err := runtimePool.QueryRow(ctx, `SELECT runtime_existing_probe_value()`).Scan(&existingProbeValue); err != nil {
		t.Fatalf("runtime role lacks existing function privilege: %v", err)
	}
	if existingProbeValue != 21 || existingProbeID < 1 {
		t.Fatalf("existing privilege probe result = id %d, value %d", existingProbeID, existingProbeValue)
	}

	userID := uuid.New()
	if err := runtimePool.QueryRow(ctx, `
		INSERT INTO users (id, username, email, status, role, creation_source)
		VALUES ($1, $2, $3, 'active', 'user', 'legacy')
		RETURNING id
	`, userID, "runtime-user-"+uuid.NewString(), "runtime-"+uuid.NewString()+"@example.test").Scan(&userID); err != nil {
		t.Fatalf("runtime role cannot insert business row: %v", err)
	}
	var username string
	if err := runtimePool.QueryRow(ctx, `SELECT username FROM users WHERE id = $1`, userID).Scan(&username); err != nil {
		t.Fatalf("runtime role cannot read business row: %v", err)
	}
	if _, err := runtimePool.Exec(ctx, `UPDATE users SET display_name = 'updated-by-runtime' WHERE id = $1`, userID); err != nil {
		t.Fatalf("runtime role cannot update business row: %v", err)
	}
	if _, err := runtimePool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
		t.Fatalf("runtime role cannot delete business row: %v", err)
	}

	var migrationRows int
	if err := runtimePool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationRows); err != nil {
		t.Fatalf("runtime role cannot read schema_migrations: %v", err)
	}
	if migrationRows != 1 {
		t.Fatalf("schema_migrations rows = %d, want 1", migrationRows)
	}
	if _, err := runtimePool.Exec(ctx, `UPDATE schema_migrations SET dirty = NOT dirty`); err == nil {
		t.Fatal("runtime role modified schema_migrations")
	}
	if _, err := runtimePool.Exec(ctx, `CREATE TABLE runtime_forbidden_table (id integer)`); err == nil {
		t.Fatal("runtime role created a table")
	}

	// Verify default privileges for objects created by the migration role after
	// the initial grant, including sequences, types, and functions.
	if _, err := schema.pool.Exec(ctx, `
		CREATE TYPE runtime_probe_state AS ENUM ('ready');
		CREATE TABLE runtime_privilege_probe (
			id BIGSERIAL PRIMARY KEY,
			state runtime_probe_state NOT NULL
		);
		CREATE FUNCTION runtime_probe_value() RETURNS integer
		LANGUAGE SQL IMMUTABLE AS 'SELECT 42';
		REVOKE ALL PRIVILEGES ON TYPE runtime_probe_state FROM PUBLIC;
		REVOKE ALL PRIVILEGES ON FUNCTION runtime_probe_value() FROM PUBLIC;
	`); err != nil {
		t.Fatalf("create default privilege probe objects: %v", err)
	}
	var probeID int64
	if err := runtimePool.QueryRow(ctx, `INSERT INTO runtime_privilege_probe (state) VALUES ('ready') RETURNING id`).Scan(&probeID); err != nil {
		t.Fatalf("runtime role lacks default sequence/type/table privileges: %v", err)
	}
	var probeValue int
	if err := runtimePool.QueryRow(ctx, `SELECT runtime_probe_value()`).Scan(&probeValue); err != nil {
		t.Fatalf("runtime role lacks default function privilege: %v", err)
	}
	if probeValue != 42 || probeID < 1 {
		t.Fatalf("default privilege probe result = id %d, value %d", probeID, probeValue)
	}

	roleIdentifier := pgx.Identifier{role}.Sanitize()
	schemaIdentifier := pgx.Identifier{schema.name}.Sanitize()
	if _, err := schema.pool.Exec(ctx, "GRANT CREATE ON SCHEMA "+schemaIdentifier+" TO "+roleIdentifier); err != nil {
		t.Fatalf("grant runtime CREATE privilege for validation probe: %v", err)
	}
	if err := database.ValidateRuntimeRole(ctx, runtimePool, role); err == nil {
		t.Fatal("runtime role validation accepted schema CREATE privilege")
	}
	if _, err := schema.pool.Exec(ctx, "REVOKE CREATE ON SCHEMA "+schemaIdentifier+" FROM "+roleIdentifier); err != nil {
		t.Fatalf("revoke runtime CREATE privilege: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, "GRANT UPDATE ON TABLE "+schemaIdentifier+".schema_migrations TO PUBLIC"); err != nil {
		t.Fatalf("grant migration table probe privilege: %v", err)
	}
	if err := database.ValidateRuntimeRole(ctx, runtimePool, role); err == nil {
		t.Fatal("runtime role validation accepted PUBLIC schema_migrations write privilege")
	}
	if _, err := schema.pool.Exec(ctx, "REVOKE UPDATE ON TABLE "+schemaIdentifier+".schema_migrations FROM PUBLIC"); err != nil {
		t.Fatalf("revoke migration table probe privilege: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, "ALTER ROLE "+roleIdentifier+" CREATEDB"); err != nil {
		t.Fatalf("grant elevated role probe attribute: %v", err)
	}
	if err := database.ValidateRuntimeRole(ctx, runtimePool, role); err == nil {
		t.Fatal("runtime role validation accepted elevated PostgreSQL role attributes")
	}
	if _, err := schema.pool.Exec(ctx, "ALTER ROLE "+roleIdentifier+" NOCREATEDB"); err != nil {
		t.Fatalf("revoke elevated role probe attribute: %v", err)
	}

	membershipRole := "nyauth_runtime_membership_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	membershipIdentifier := pgx.Identifier{membershipRole}.Sanitize()
	if _, err := schema.pool.Exec(ctx, "CREATE ROLE "+membershipIdentifier+" NOLOGIN"); err != nil {
		t.Fatalf("create membership probe role: %v", err)
	}
	membershipRoleDropped := false
	t.Cleanup(func() {
		if membershipRoleDropped {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		_, _ = schema.pool.Exec(cleanupCtx, "REVOKE "+membershipIdentifier+" FROM "+roleIdentifier)
		_, _ = schema.pool.Exec(cleanupCtx, "DROP ROLE "+membershipIdentifier)
	})
	if _, err := schema.pool.Exec(ctx, "GRANT "+membershipIdentifier+" TO "+roleIdentifier); err != nil {
		t.Fatalf("grant runtime membership probe role: %v", err)
	}
	if err := database.EnsureRuntimePrivileges(ctx, schema.pool, role); err == nil {
		t.Fatal("runtime privilege setup accepted a runtime role membership")
	}
	if err := database.ValidateRuntimeRole(ctx, runtimePool, role); err == nil {
		t.Fatal("runtime role validation accepted a PostgreSQL role membership")
	}
	if _, err := schema.pool.Exec(ctx, "REVOKE "+membershipIdentifier+" FROM "+roleIdentifier); err != nil {
		t.Fatalf("revoke runtime membership probe role: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, "DROP ROLE "+membershipIdentifier); err != nil {
		t.Fatalf("drop runtime membership probe role: %v", err)
	}
	membershipRoleDropped = true
}

func createRuntimeRole(t *testing.T, schema *postgresTestSchema, ctx context.Context) (string, string) {
	t.Helper()
	role := "nyauth_runtime_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := strings.ReplaceAll(uuid.NewString()+uuid.NewString(), "-", "")
	roleIdentifier := pgx.Identifier{role}.Sanitize()
	statement := fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT", roleIdentifier, password)
	if _, err := schema.pool.Exec(ctx, statement); err != nil {
		t.Fatalf("create runtime role: %v", err)
	}
	return role, password
}

func newRuntimePool(t *testing.T, dsn, role, password string) *pgxpool.Pool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse runtime DSN: %v", err)
	}
	poolConfig.ConnConfig.User = role
	poolConfig.ConnConfig.Password = password
	poolConfig.MaxConns = 3
	poolConfig.MinConns = 0
	runtimePool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect runtime role: %v", err)
	}
	if err := runtimePool.Ping(ctx); err != nil {
		runtimePool.Close()
		t.Fatalf("ping runtime role: %v", err)
	}
	return runtimePool
}
