package database_test

import (
	"bytes"
	"context"
	"testing"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/settings"
	migrationfiles "github.com/nyasharp/nyauth/migrations"
)

func TestPasskeyMigrationPreservesOlderSecuritySettingsAndScopesIdentifiersByRP(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run migrations through Passkey schema: %v", err)
	}
	ctx := context.Background()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO runtime_settings (key,value,updated_by)
		VALUES (
			'security',
			'{"totp_enabled":false,"passkeys_enabled":false,"require_mfa_for_admins":false}'::jsonb,
			'migration-test'
		)
		ON CONFLICT (key) DO UPDATE
		SET value=EXCLUDED.value,updated_by=EXCLUDED.updated_by,updated_at=now()
	`); err != nil {
		t.Fatalf("seed security settings: %v", err)
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
	t.Cleanup(func() { _, _ = runner.Close() })
	if err := runner.Migrate(7); err != nil {
		t.Fatalf("migrate Passkey schema down to version 7: %v", err)
	}
	assertMigrationVersion(t, schema, 7)

	var hasPasskeyKey bool
	var totpEnabled, requireAdminMFA bool
	if err := schema.pool.QueryRow(ctx, `
		SELECT value ? 'passkeys_enabled',
		       COALESCE((value->>'totp_enabled')::boolean,true),
		       COALESCE((value->>'require_mfa_for_admins')::boolean,false)
		FROM runtime_settings WHERE key='security'
	`).Scan(&hasPasskeyKey, &totpEnabled, &requireAdminMFA); err != nil {
		t.Fatalf("read downgraded security settings: %v", err)
	}
	if hasPasskeyKey || totpEnabled || requireAdminMFA {
		t.Fatalf("downgraded security = passkey key %v, totp %v, require admin %v", hasPasskeyKey, totpEnabled, requireAdminMFA)
	}

	if err := runner.Migrate(8); err != nil {
		t.Fatalf("migrate Passkey schema back to version 8: %v", err)
	}
	assertMigrationVersion(t, schema, 8)
	manager := settings.NewManager(schema.pool, settings.Branding{Title: "Migration Test"})
	if err := manager.Load(ctx); err != nil {
		t.Fatalf("load security settings after reupgrade: %v", err)
	}
	security := manager.Security()
	if security.TOTPEnabled || !security.PasskeysEnabled || security.RequireMFAForAdmins {
		t.Fatalf("security after reupgrade = %#v", security)
	}

	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role) VALUES ($1,$2,'active','user')
	`, userID, "passkey-migration-"+uuid.NewString()[:8]); err != nil {
		t.Fatalf("insert Passkey user: %v", err)
	}
	handle := bytes.Repeat([]byte{0x41}, 32)
	credentialID := []byte("same-credential-id")
	for _, rpID := range []string{"auth.example.test", "login.example.test"} {
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO user_passkey_handles (rp_id,user_id,user_handle)
			VALUES ($1,$2,$3)
		`, rpID, userID, handle); err != nil {
			t.Fatalf("insert handle for %s: %v", rpID, err)
		}
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO user_passkey_credentials (
				rp_id,user_id,credential_id,credential_ciphertext,name
			) VALUES ($1,$2,$3,'encrypted','test')
		`, rpID, userID, credentialID); err != nil {
			t.Fatalf("insert credential for %s: %v", rpID, err)
		}
	}
}
