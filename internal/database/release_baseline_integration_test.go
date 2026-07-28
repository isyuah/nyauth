package database_test

import (
	"context"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/nyasharp/nyauth/internal/database"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

func TestReleaseBaselineMigratesFreshDatabaseDownAndUp(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run release baseline: %v", err)
	}
	assertReleaseBaseline(t, schema)

	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open embedded release baseline: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create release baseline runner: %v", err)
	}
	t.Cleanup(func() { _, _ = runner.Close() })

	if err := runner.Down(); err != nil {
		t.Fatalf("migrate release baseline down: %v", err)
	}
	var usersTable *string
	if err := schema.pool.QueryRow(context.Background(), `SELECT to_regclass('users')::text`).Scan(&usersTable); err != nil {
		t.Fatalf("inspect users table after baseline down: %v", err)
	}
	if usersTable != nil {
		t.Fatalf("users table remains after baseline down: %q", *usersTable)
	}

	if err := runner.Up(); err != nil {
		t.Fatalf("migrate release baseline up again: %v", err)
	}
	assertReleaseBaseline(t, schema)
}

func assertReleaseBaseline(t *testing.T, schema *postgresTestSchema) {
	t.Helper()
	ctx := context.Background()
	var version int64
	var dirty bool
	if err := schema.pool.QueryRow(ctx, `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read release baseline version: %v", err)
	}
	if version != database.SchemaVersion || dirty {
		t.Fatalf("release baseline version=%d dirty=%v, want version=%d clean", version, dirty, database.SchemaVersion)
	}

	for _, object := range []string{
		"runtime_settings", "client_access_users", "self_registrations", "mail_config_versions",
		"registration_stats_daily", "user_totp_credentials", "user_passkey_credentials",
		"user_avatars", "provider_avatar_import_jobs", "idx_audit_logs_target_created",
	} {
		var resolved *string
		if err := schema.pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, object).Scan(&resolved); err != nil {
			t.Fatalf("inspect baseline object %s: %v", object, err)
		}
		if resolved == nil {
			t.Fatalf("release baseline object %s is missing", object)
		}
	}

	for _, column := range []struct{ table, name string }{
		{"users", "current_avatar_id"}, {"users", "creation_source"}, {"users", "created_by"},
		{"oauth_clients", "access_policy"}, {"oauth_providers", "import_avatar"},
		{"oauth_providers", "avatar_allowed_hosts"},
	} {
		var count int
		if err := schema.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM information_schema.columns
			WHERE table_schema=$1 AND table_name=$2 AND column_name=$3
		`, schema.name, column.table, column.name).Scan(&count); err != nil {
			t.Fatalf("inspect baseline column %s.%s: %v", column.table, column.name, err)
		}
		if count != 1 {
			t.Fatalf("release baseline column %s.%s is missing", column.table, column.name)
		}
	}
}
