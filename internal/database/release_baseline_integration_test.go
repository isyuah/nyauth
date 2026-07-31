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

func TestReleaseBaselineUpgradesSchema3ToCurrent(t *testing.T) {
	schema := newPostgresTestSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create schema 3 migration runner: %v", err)
	}
	if err := runner.Migrate(3); err != nil {
		_, _ = runner.Close()
		t.Fatalf("migrate to schema 3: %v", err)
	}

	var version int64
	var dirty bool
	if err := schema.pool.QueryRow(t.Context(), `SELECT version,dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		_, _ = runner.Close()
		t.Fatalf("read schema 3 migration state: %v", err)
	}
	if version != 3 || dirty {
		_, _ = runner.Close()
		t.Fatalf("migration state=%d dirty=%v, want schema 3 clean", version, dirty)
	}
	var serviceControlTable *string
	if err := schema.pool.QueryRow(t.Context(), `SELECT to_regclass('service_control_state')::text`).Scan(&serviceControlTable); err != nil {
		_, _ = runner.Close()
		t.Fatalf("inspect service control table before upgrade: %v", err)
	}
	if serviceControlTable != nil {
		_, _ = runner.Close()
		t.Fatalf("service control table exists before schema 4: %q", *serviceControlTable)
	}
	if sourceErr, databaseErr := runner.Close(); sourceErr != nil || databaseErr != nil {
		t.Fatalf("close schema 3 migration runner: source=%v database=%v", sourceErr, databaseErr)
	}

	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("upgrade schema 3 to current schema: %v", err)
	}
	assertReleaseBaseline(t, schema)

	var revision int64
	var pauses int
	if err := schema.pool.QueryRow(t.Context(), `
		SELECT state.revision,COUNT(pauses.capability)
		FROM service_control_state AS state
		LEFT JOIN service_control_pauses AS pauses ON pauses.singleton=state.singleton
		WHERE state.singleton=TRUE
		GROUP BY state.revision
	`).Scan(&revision, &pauses); err != nil {
		t.Fatalf("read initial service control state: %v", err)
	}
	if revision != 1 || pauses != 0 {
		t.Fatalf("initial service control revision=%d pauses=%d, want revision 1 with no pauses", revision, pauses)
	}
}

func TestRuntimeObservabilityUpgradesSchema8To9(t *testing.T) {
	schema := newPostgresTestSchema(t)
	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	if err := runner.Migrate(8); err != nil {
		_, _ = runner.Close()
		t.Fatalf("migrate to schema 8: %v", err)
	}
	var before *string
	if err := schema.pool.QueryRow(t.Context(), `SELECT to_regclass('otlp_runtime_state')::text`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if before != nil {
		t.Fatalf("OTLP runtime table exists at schema 8: %q", *before)
	}
	if sourceErr, databaseErr := runner.Close(); sourceErr != nil || databaseErr != nil {
		t.Fatalf("close schema 8 runner: source=%v database=%v", sourceErr, databaseErr)
	}
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("upgrade schema 8 to 9: %v", err)
	}
	var mode string
	var revision int64
	if err := schema.pool.QueryRow(t.Context(), `SELECT mode,revision FROM otlp_runtime_state WHERE singleton=TRUE`).Scan(&mode, &revision); err != nil {
		t.Fatal(err)
	}
	if mode != "fallback" || revision != 0 {
		t.Fatalf("initial OTLP state mode=%q revision=%d", mode, revision)
	}
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
		"service_control_state", "service_control_pauses", "service_control_instances",
		"media_storage_profiles", "media_storage_state", "media_storage_migrations",
		"media_storage_migration_items", "media_storage_instances",
		"otlp_config_versions", "otlp_config_tests", "otlp_runtime_state",
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
		{"oauth_clients", "access_policy"}, {"oauth_clients", "optional_scopes"}, {"oauth_clients", "allowed_claims"}, {"oauth_authorizations", "allowed_claims"}, {"oauth_providers", "import_avatar"},
		{"oauth_providers", "avatar_allowed_hosts"},
		{"user_avatars", "storage_profile_id"},
		{"media_storage_migrations", "target_backend"},
		{"media_storage_migration_items", "target_backend"},
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
