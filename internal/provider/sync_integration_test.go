package provider

import (
	"context"
	"net/url"
	"os"
	"slices"
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

const providerPostgresTestDSNEnv = "NYAUTH_TEST_DATABASE_DSN"

func TestSynchronizationPropagatesProviderMutationsAcrossInstances(t *testing.T) {
	firstPool, secondPool := newProviderSyncTestPools(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	first := NewManager(firstPool, masterKey)
	second := NewManager(secondPool, masterKey)
	if err := first.LoadDynamic(ctx); err != nil {
		t.Fatalf("load first provider snapshot: %v", err)
	}
	if err := second.LoadDynamic(ctx); err != nil {
		t.Fatalf("load second provider snapshot: %v", err)
	}

	listenerReady := make(chan struct{}, 1)
	go second.listenForChangesWithReady(ctx, listenerReady)
	select {
	case <-listenerReady:
	case <-ctx.Done():
		t.Fatalf("provider notification listener did not become ready: %v", ctx.Err())
	}

	actorID := uuid.New()
	mutation := func(event string) audit.MutationAudit {
		return audit.MutationAudit{
			Event: event, ActorID: actorID, ActorName: "provider-sync-test",
			Result: "success", RiskLevel: "high",
		}
	}

	const providerName = "shared-github"
	enabledOnCreate := true
	if _, err := first.CreateProvider(ctx, models.CreateProviderRequest{
		Name: providerName, Type: "github", ClientID: "client-v1", ClientSecret: "provider-secret",
		Enabled: &enabledOnCreate, Scopes: []string{"read:user", "user:email"},
	}, mutation(models.AuditProviderCreated)); err != nil {
		t.Fatalf("create provider on first instance: %v", err)
	}
	waitForProviderState(t, ctx, second, providerName, "client-v1")

	disabled := false
	if _, err := first.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{Enabled: &disabled}, mutation(models.AuditProviderUpdated)); err != nil {
		t.Fatalf("disable provider on first instance: %v", err)
	}
	waitForProviderState(t, ctx, second, providerName, "")

	enabled := true
	clientV2 := "client-v2"
	if _, err := first.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{
		ClientID: &clientV2,
		Enabled:  &enabled,
	}, mutation(models.AuditProviderUpdated)); err != nil {
		t.Fatalf("re-enable provider on first instance: %v", err)
	}
	waitForProviderState(t, ctx, second, providerName, clientV2)

	if err := first.DeleteProvider(ctx, providerName, mutation(models.AuditProviderDeleted)); err != nil {
		t.Fatalf("delete provider on first instance: %v", err)
	}
	waitForProviderState(t, ctx, second, providerName, "")
}

func TestProviderReconciliationRepairsMissedNotifications(t *testing.T) {
	if providerReconciliationInterval != 60*time.Second {
		t.Fatalf("production reconciliation interval = %s, want 60s", providerReconciliationInterval)
	}
	firstPool, secondPool := newProviderSyncTestPools(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	masterKey := []byte("0123456789abcdef0123456789abcdef")
	writer := NewManager(firstPool, masterKey)
	reader := NewManager(secondPool, masterKey)
	if err := reader.LoadDynamic(ctx); err != nil {
		t.Fatalf("load initial provider snapshot: %v", err)
	}

	const providerName = "reconciled-github"
	encryptedSecret, err := writer.EncryptSecret(providerName, "provider-secret")
	if err != nil {
		t.Fatalf("encrypt provider secret: %v", err)
	}
	if _, err := firstPool.Exec(ctx, `
		INSERT INTO oauth_providers (name,type,client_id,client_secret,scopes,enabled)
		VALUES ($1,'github',$2,$3,$4,TRUE)
	`, providerName, "reconciled-client", encryptedSecret, []string{"user:email"}); err != nil {
		t.Fatalf("insert provider without notification: %v", err)
	}
	if _, ok := reader.Get(providerName); ok {
		t.Fatal("provider appeared before reconciliation ran")
	}

	go reader.reconcileProvidersAtInterval(ctx, 25*time.Millisecond)
	waitForProviderState(t, ctx, reader, providerName, "reconciled-client")

	if _, err := firstPool.Exec(ctx, `UPDATE oauth_providers SET enabled=FALSE,revision=revision+1 WHERE name=$1`, providerName); err != nil {
		t.Fatalf("disable provider without notification: %v", err)
	}
	waitForProviderState(t, ctx, reader, providerName, "")
}

func TestProviderLoadIsolatesCorruptRowsAndReportsDegraded(t *testing.T) {
	pool, _ := newProviderSyncTestPools(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	masterKey := []byte("0123456789abcdef0123456789abcdef")
	manager := NewManager(pool, masterKey)
	validSecret, err := manager.EncryptSecret("healthy-github", "provider-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO oauth_providers (name,type,client_id,client_secret,scopes,enabled)
		VALUES ('healthy-github','github','healthy-client',$1,ARRAY['user:email'],TRUE),
		       ('broken-github','github','broken-client','not-an-envelope',ARRAY['user:email'],TRUE)
	`, validSecret); err != nil {
		t.Fatal(err)
	}
	var results []string
	manager.SetTelemetrySink(func(_ context.Context, operation, _ string, result, reason string, _ time.Duration) {
		if operation == "synchronization" {
			results = append(results, result+":"+reason)
		}
	})
	if err := manager.LoadDynamic(ctx); err != nil {
		t.Fatalf("LoadDynamic: %v", err)
	}
	if _, ok := manager.Get("healthy-github"); !ok {
		t.Fatal("healthy provider was omitted with corrupt neighbor")
	}
	if _, ok := manager.Get("broken-github"); ok {
		t.Fatal("corrupt provider entered runtime snapshot")
	}
	if !manager.Ready() || !manager.Degraded() {
		t.Fatalf("provider state ready=%v degraded=%v", manager.Ready(), manager.Degraded())
	}
	if !slices.Contains(results, "degraded:secret_decrypt_failed") || !slices.Contains(results, "degraded:provider_rows_skipped") {
		t.Fatalf("provider degradation telemetry = %v", results)
	}
}

func waitForProviderState(t *testing.T, ctx context.Context, manager *Manager, name, expectedClientID string) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		configured, exists := manager.Get(name)
		if expectedClientID == "" {
			if !exists {
				return
			}
		} else if github, ok := configured.(*GitHub); exists && ok && github.clientID == expectedClientID {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("provider %q did not reach expected client ID %q: exists=%v type=%T", name, expectedClientID, exists, configured)
		case <-ticker.C:
		}
	}
}

func newProviderSyncTestPools(t *testing.T) (*pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv(providerPostgresTestDSNEnv))
	if baseDSN == "" {
		t.Skipf("%s is not set", providerPostgresTestDSNEnv)
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

	schemaName := "nyauth_provider_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		basePool.Close()
		t.Fatalf("create isolated provider schema: %v", err)
	}

	var pools []*pgxpool.Pool
	t.Cleanup(func() {
		for _, pool := range pools {
			pool.Close()
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if _, err := basePool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop isolated provider schema %s: %v", schemaName, err)
		}
		basePool.Close()
	})

	scopedDSN := providerDSNWithSearchPath(baseDSN, schemaName)
	if err := database.RunMigrations(scopedDSN); err != nil {
		t.Fatalf("run provider integration migrations: %v", err)
	}
	for range 2 {
		poolConfig, err := pgxpool.ParseConfig(baseDSN)
		if err != nil {
			t.Fatalf("parse PostgreSQL DSN: %v", err)
		}
		if poolConfig.ConnConfig.RuntimeParams == nil {
			poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
		}
		poolConfig.ConnConfig.RuntimeParams["search_path"] = schemaName
		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			t.Fatalf("connect isolated provider schema: %v", err)
		}
		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			t.Fatalf("ping isolated provider schema: %v", err)
		}
		pools = append(pools, pool)
	}
	return pools[0], pools[1]
}

func providerDSNWithSearchPath(dsn, schemaName string) string {
	parsed, err := url.Parse(dsn)
	if err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") {
		query := parsed.Query()
		query.Set("search_path", schemaName)
		parsed.RawQuery = query.Encode()
		return parsed.String()
	}
	return strings.TrimSpace(dsn) + " search_path=" + schemaName
}
