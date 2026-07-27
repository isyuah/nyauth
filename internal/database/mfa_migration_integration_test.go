package database_test

import (
	"context"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/settings"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

func TestTOTPMFADownMigrationRemovesSecurityPolicyAndReupgradeUsesDefaults(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run migrations through MFA schema: %v", err)
	}

	ctx := context.Background()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO runtime_settings (key,value,updated_by)
		VALUES ('security','{"totp_enabled":true,"require_mfa_for_admins":true}'::jsonb,'migration-test')
		ON CONFLICT (key) DO UPDATE
		SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()
	`); err != nil {
		t.Fatalf("seed non-default security policy: %v", err)
	}

	source, err := iofs.New(migrationfiles.Files, ".")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	runner, err := migrate.NewWithSourceInstance("iofs", source, schema.migrationDSN)
	if err != nil {
		_ = source.Close()
		t.Fatalf("create migration runner: %v", err)
	}
	t.Cleanup(func() {
		_, _ = runner.Close()
	})

	if err := runner.Migrate(6); err != nil {
		t.Fatalf("migrate MFA schema down to version 6: %v", err)
	}
	assertMigrationVersion(t, schema, 6)

	var securityRows int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM runtime_settings WHERE key='security'
	`).Scan(&securityRows); err != nil {
		t.Fatalf("count security settings after down migration: %v", err)
	}
	if securityRows != 0 {
		t.Fatalf("security settings rows after down migration = %d, want 0", securityRows)
	}

	if err := runner.Migrate(7); err != nil {
		t.Fatalf("migrate MFA schema back to version 7: %v", err)
	}
	assertMigrationVersion(t, schema, 7)
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM runtime_settings WHERE key='security'
	`).Scan(&securityRows); err != nil {
		t.Fatalf("count security settings after reupgrade: %v", err)
	}
	if securityRows != 0 {
		t.Fatalf("security settings rows after reupgrade = %d, want 0 so defaults apply", securityRows)
	}

	manager := settings.NewManager(schema.pool, settings.Branding{Title: "Migration Test"})
	if err := manager.Load(ctx); err != nil {
		t.Fatalf("load settings after MFA reupgrade: %v", err)
	}
	got := manager.Security()
	want := settings.DefaultSecurity()
	if got != want {
		t.Fatalf("security settings after reupgrade = %#v, want defaults %#v", got, want)
	}
}

func assertMigrationVersion(t *testing.T, schema *postgresTestSchema, want int) {
	t.Helper()
	var version int
	var dirty bool
	if err := schema.pool.QueryRow(context.Background(), `
		SELECT version,dirty FROM schema_migrations
	`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read schema migration state: %v", err)
	}
	if version != want || dirty {
		t.Fatalf("schema migration state = version %d dirty %v, want version %d clean", version, dirty, want)
	}
}
