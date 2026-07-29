package settings

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

type securitySettingsTestSchema struct {
	migrationDSN string
	pool         *pgxpool.Pool
}

func TestSetSecurityAuditFailureRollsBackSetting(t *testing.T) {
	schema := newSecuritySettingsTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run settings migrations: %v", err)
	}

	ctx := t.Context()
	manager := NewManager(schema.pool, Branding{Title: "Nyauth Test"})
	actorID := uuid.New()
	mutation := audit.MutationAudit{
		Event: models.AuditSettingsUpdated, ActorID: actorID, ActorName: "security-admin",
		Result: "success", RiskLevel: "high", IPAddress: "192.0.2.80",
		UserAgent: "settings-integration-test",
		Details:   map[string]any{"method": "PUT", "path": "/api/admin/settings/security"},
	}

	stored := Security{TOTPEnabled: false, RequireMFAForAdmins: false}
	if _, err := manager.SetSecurity(ctx, stored, 0, mutation.ActorName, mutation); err != nil {
		t.Fatalf("store audited security settings: %v", err)
	}
	var auditCount int
	if err := schema.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='settings' AND aggregate_id=$2
	`, models.AuditSettingsUpdated, securityKey).Scan(&auditCount); err != nil {
		t.Fatalf("count security audit events: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("security audit event count = %d, want 1", auditCount)
	}

	if _, err := schema.pool.Exec(ctx, `DROP TABLE audit_event_outbox`); err != nil {
		t.Fatalf("remove audit outbox failure fixture: %v", err)
	}
	desired := DefaultSecurity()
	_, err := manager.SetSecurity(ctx, desired, 1, mutation.ActorName, mutation)
	if err == nil || !strings.Contains(err.Error(), "auditing security settings") {
		t.Fatalf("SetSecurity audit failure error = %v", err)
	}

	var encoded []byte
	if err := schema.pool.QueryRow(ctx, `SELECT value FROM runtime_settings WHERE key=$1`, securityKey).Scan(&encoded); err != nil {
		t.Fatalf("load security settings after audit failure: %v", err)
	}
	var persisted Security
	if err := json.Unmarshal(encoded, &persisted); err != nil {
		t.Fatalf("decode security settings after audit failure: %v", err)
	}
	if persisted != stored {
		t.Fatalf("persisted security settings after audit failure = %#v, want %#v", persisted, stored)
	}
	if snapshot := manager.Security(); snapshot != stored {
		t.Fatalf("published security settings after audit failure = %#v, want %#v", snapshot, stored)
	}
}

func newSecuritySettingsTestSchema(t *testing.T) *securitySettingsTestSchema {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv("NYAUTH_TEST_DATABASE_DSN"))
	if baseDSN == "" {
		t.Skip("NYAUTH_TEST_DATABASE_DSN is not set; skipping security settings integration test")
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

	schemaName := "nyauth_settings_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		basePool.Close()
		t.Fatalf("create isolated settings schema: %v", err)
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
		t.Fatalf("connect isolated settings schema: %v", err)
	}

	t.Cleanup(func() {
		scopedPool.Close()
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := basePool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated settings schema %s: %v", schemaName, err)
		}
		basePool.Close()
	})

	return &securitySettingsTestSchema{
		migrationDSN: securitySettingsDSNWithSearchPath(t, baseDSN, schemaName),
		pool:         scopedPool,
	}
}

func securitySettingsDSNWithSearchPath(t *testing.T, dsn, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schemaName)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return strings.TrimSpace(dsn) + " search_path=" + schemaName
}
