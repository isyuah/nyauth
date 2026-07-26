package database_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestAuditPartitionsRetentionAndFutureMaintenance(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var partitioned bool
	if err := schema.pool.QueryRow(ctx, `
		SELECT relkind='p' FROM pg_class
		JOIN pg_namespace ON pg_namespace.oid=pg_class.relnamespace
		WHERE pg_namespace.nspname=$1 AND pg_class.relname='audit_logs'
	`, schema.name).Scan(&partitioned); err != nil {
		t.Fatalf("inspect audit_logs: %v", err)
	}
	if !partitioned {
		t.Fatal("audit_logs is not a partitioned table")
	}

	store := audit.NewStore(schema.pool)
	future := time.Date(2032, time.April, 15, 12, 0, 0, 0, time.UTC)
	if err := store.EnsureMonthlyPartitions(ctx, future, 2); err != nil {
		t.Fatalf("EnsureMonthlyPartitions: %v", err)
	}
	oldID := uuid.New()
	recentID := uuid.New()
	for _, entry := range []*models.AuditLog{
		{ID: oldID, Event: "integration.old", Result: "success", RiskLevel: "low", Details: map[string]any{}, CreatedAt: future.AddDate(0, -1, 0)},
		{ID: recentID, Event: "integration.recent", Result: "success", RiskLevel: "low", Details: map[string]any{}, CreatedAt: future},
	} {
		if err := store.Record(ctx, entry); err != nil {
			t.Fatalf("Record(%s): %v", entry.Event, err)
		}
	}

	retention, err := store.ApplyRetention(ctx, time.Date(2032, time.April, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("ApplyRetention: %v", err)
	}
	if retention.DroppedPartitions == 0 {
		t.Fatal("retention did not drop any complete expired partition")
	}
	var oldCount, recentCount int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE id=$1`, oldID).Scan(&oldCount); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE id=$1`, recentID).Scan(&recentCount); err != nil {
		t.Fatal(err)
	}
	if oldCount != 0 || recentCount != 1 {
		t.Fatalf("retained audit rows old=%d recent=%d, want 0/1", oldCount, recentCount)
	}
}
