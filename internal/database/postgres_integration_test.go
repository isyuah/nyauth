package database_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/internal/session"
	dashboardstats "github.com/nyasharp/nyauth/internal/stats"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

const postgresTestDSNEnv = "NYAUTH_TEST_DATABASE_DSN"

type postgresTestSchema struct {
	name         string
	migrationDSN string
	pool         *pgxpool.Pool
}

type invalidEmailNotificationBuilder struct{}

func (invalidEmailNotificationBuilder) BuildSecurityNotification(user *models.User, notice account.SecurityNotice) (*account.OutboxEmail, error) {
	now := time.Now().UTC()
	userID := user.ID
	return &account.OutboxEmail{
		ID: uuid.New(), UserID: &userID, MessageType: notice.MessageType,
		RecipientHash: []byte{1}, EncryptedMessage: "invalid-test-envelope",
		AvailableAt: now, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}, nil
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
	assertColumn(t, schema, "users", "email_verified_at", "YES")
	assertColumn(t, schema, "users", "password_changed_at", "YES")
	assertColumn(t, schema, "users", "last_authenticated_at", "YES")
	assertColumn(t, schema, "oauth_clients", "post_logout_redirect_uris", "NO")
	assertColumn(t, schema, "oauth_clients", "secret_version", "NO")
	assertColumn(t, schema, "oauth_clients", "secret_rotated_at", "YES")
	assertColumn(t, schema, "oauth_clients", "secret_last_used_at", "YES")
	assertColumn(t, schema, "oauth_providers", "revision", "NO")
	assertColumn(t, schema, "oauth_providers", "display_name", "NO")
	assertColumn(t, schema, "oauth_providers", "icon_key", "NO")
	assertColumn(t, schema, "account_action_tokens", "token_hash", "NO")
	assertColumn(t, schema, "email_outbox", "encrypted_message", "NO")
	assertColumn(t, schema, "oauth_authorizations", "revoked_at", "YES")
	assertColumn(t, schema, "audit_logs", "details", "NO")
	assertColumn(t, schema, "audit_event_outbox", "payload", "NO")
	assertMissingColumns(t, schema, "identities", "access_token", "refresh_token", "token_expires_at")
	assertColumn(t, schema, "jwk_keys", "encrypted_private_key", "YES")
	assertColumn(t, schema, "jwk_keys", "status", "NO")
	assertColumn(t, schema, "jwk_keys", "signing_started_at", "NO")
	assertColumn(t, schema, "jwk_keys", "verify_until", "NO")
	assertMissingColumns(t, schema, "jwk_keys", "private_key", "is_active", "expires_at")
	for _, constraintName := range []string{
		"users_auth_version_positive",
		"users_verified_email_present",
		"oauth_clients_secret_kind_consistent",
		"oauth_clients_secret_version_nonnegative",
		"oauth_providers_generic_discovery_required",
		"oauth_providers_revision_positive",
		"identities_external_unique",
		"jwk_keys_status_valid",
		"jwk_keys_private_key_lifecycle",
		"jwk_keys_verify_window_valid",
		"account_action_tokens_hash_length",
		"email_outbox_recipient_hash_length",
		"audit_logs_details_object",
	} {
		assertConstraint(t, schema, constraintName)
	}
	var displayName, iconKey string
	if err := schema.pool.QueryRow(ctx, `
		INSERT INTO oauth_providers (name,type,client_id,client_secret,enabled)
		VALUES ('migration-default-provider','github','client','test-envelope',FALSE)
		RETURNING display_name,icon_key
	`).Scan(&displayName, &iconKey); err != nil {
		t.Fatalf("insert provider with presentation defaults: %v", err)
	}
	if displayName != "migration-default-provider" || iconKey != "auto" {
		t.Fatalf("provider presentation defaults = %q/%q", displayName, iconKey)
	}
}

func TestDashboardStatisticsAreServedFromRefreshedAggregates(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("run baseline migration: %v", err)
	}

	redisServer := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: redisServer.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id, username, status, role, creation_source)
		VALUES ($1, $2, 'active', 'user', 'legacy')
	`, userID, "stats-user-"+uuid.NewString()); err != nil {
		t.Fatalf("insert aggregate test user: %v", err)
	}
	clientID := "stats-client-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO oauth_clients (id, name, redirect_uris, grants, is_public, owner_id)
		VALUES ($1, 'Statistics client', ARRAY['https://client.example/callback'], ARRAY['authorization_code'], TRUE, $2)
	`, clientID, userID); err != nil {
		t.Fatalf("insert aggregate test client: %v", err)
	}
	now := time.Now().UTC()
	auditStore := audit.NewStore(schema.pool)
	actorName := "stats-user"
	for _, entry := range []*models.AuditLog{
		{ID: uuid.New(), Event: models.AuditUserLogin, ActorID: &userID, ActorName: &actorName, Result: "success", RiskLevel: "low", Details: map[string]any{}, CreatedAt: now.Add(-time.Hour)},
		{ID: uuid.New(), Event: models.AuditUserLoginFailed, ActorID: &userID, ActorName: &actorName, Result: "failure", RiskLevel: "medium", Details: map[string]any{}, CreatedAt: now.Add(-25 * time.Hour)},
	} {
		if err := audit.EnqueueLog(ctx, auditStore, entry); err != nil {
			t.Fatalf("enqueue aggregate audit row: %v", err)
		}
	}
	dispatcher, err := audit.NewDispatcher(auditStore, audit.DispatcherOptions{WorkerID: "stats-integration", Clock: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("create aggregate audit dispatcher: %v", err)
	}
	if processed, err := dispatcher.DispatchOnce(ctx); err != nil || processed != 2 {
		t.Fatalf("dispatch aggregate audit rows: processed=%d err=%v", processed, err)
	}
	if err := session.NewStore(rdb).SaveSession(ctx, "stats-session-secret", &session.SessionData{
		UserID: userID.String(), Username: "stats-user", AuthVersion: 1,
	}, time.Hour); err != nil {
		t.Fatalf("save aggregate test session: %v", err)
	}

	handler := dashboardstats.NewHandler(schema.pool, rdb)
	if err := handler.Refresh(ctx); err != nil {
		t.Fatalf("refresh dashboard statistics: %v", err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil)
	recorder := httptest.NewRecorder()
	handler.GetStats(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("stats status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var snapshot models.DashboardStats
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode statistics snapshot: %v", err)
	}
	if snapshot.UserCount != 1 || snapshot.AppCount != 1 || snapshot.ActiveSessions != 1 || snapshot.LoginCount7d != 1 || snapshot.FailedLogins7d != 1 {
		t.Fatalf("unexpected statistics snapshot: %#v", snapshot)
	}

	if _, err := schema.pool.Exec(ctx, `INSERT INTO users (username, status, role, creation_source) VALUES ($1, 'active', 'user', 'legacy')`, "unrefreshed-user-"+uuid.NewString()); err != nil {
		t.Fatalf("insert unrefreshed user: %v", err)
	}
	recorder = httptest.NewRecorder()
	handler.GetStats(recorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil))
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode unchanged statistics snapshot: %v", err)
	}
	if snapshot.UserCount != 1 {
		t.Fatalf("request path recalculated user count: got %d, want cached 1", snapshot.UserCount)
	}
	if err := handler.Refresh(ctx); err != nil {
		t.Fatalf("refresh changed dashboard statistics: %v", err)
	}
	recorder = httptest.NewRecorder()
	handler.GetStats(recorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats", nil))
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("decode refreshed statistics snapshot: %v", err)
	}
	if snapshot.UserCount != 2 {
		t.Fatalf("refreshed user count = %d, want 2", snapshot.UserCount)
	}

	trendRecorder := httptest.NewRecorder()
	handler.GetLoginTrend(trendRecorder, httptest.NewRequest(http.MethodGet, "/api/admin/stats/login-trend?days=7", nil))
	if trendRecorder.Code != http.StatusOK {
		t.Fatalf("trend status = %d, body = %s", trendRecorder.Code, trendRecorder.Body.String())
	}
	var trend models.LoginTrend
	if err := json.Unmarshal(trendRecorder.Body.Bytes(), &trend); err != nil {
		t.Fatalf("decode login trend: %v", err)
	}
	var successfulLogins int64
	for _, count := range trend.Values {
		successfulLogins += count
	}
	if successfulLogins != 1 {
		t.Fatalf("successful login trend total = %d, want 1", successfulLogins)
	}
}

func TestPasswordResetTokenIsConsumedOnceAcrossConcurrentRequests(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	userID := uuid.New()
	email := "recovery-" + userID.String() + "@example.test"
	initialHash, err := crypto.HashPassword("initial-secure-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (
			id,username,email,email_verified_at,password_hash,password_changed_at,status,role,
			auth_version,must_change_password,metadata,creation_source
		) VALUES ($1,$2,$3,NOW(),$4,NOW(),'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, userID, "recovery-"+userID.String(), email, initialHash); err != nil {
		t.Fatalf("insert recovery user: %v", err)
	}

	accountStore := account.NewStore(schema.pool)
	const rawToken = "integration-account-action-token-with-32-bytes"
	service, err := account.NewService(accountStore, account.ServiceOptions{
		PublicBaseURL: "https://auth.example.test",
		ActiveKeyID:   "primary",
		MasterKeys:    map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
		GenerateToken: func() (string, error) { return rawToken, nil },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if err := service.RequestPasswordReset(ctx, email, account.RequestMetadata{IPAddress: "203.0.113.10"}); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := service.ConfirmPasswordReset(ctx, rawToken, "replacement-secure-password")
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	succeeded, rejected := 0, 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, account.ErrInvalidActionToken):
			rejected++
		default:
			t.Fatalf("unexpected password reset result: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("password reset results: succeeded=%d rejected=%d, want 1/1", succeeded, rejected)
	}

	var passwordHash string
	var authVersion int64
	if err := schema.pool.QueryRow(ctx, `SELECT password_hash,auth_version FROM users WHERE id=$1`, userID).Scan(&passwordHash, &authVersion); err != nil {
		t.Fatalf("read reset user: %v", err)
	}
	valid, err := crypto.VerifyPassword("replacement-secure-password", passwordHash)
	if err != nil || !valid {
		t.Fatalf("replacement password validation: valid=%v err=%v", valid, err)
	}
	if authVersion != 2 {
		t.Fatalf("auth_version=%d, want 2", authVersion)
	}
	var consumed, emailMessages, auditEvents int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM account_action_tokens WHERE user_id=$1 AND consumed_at IS NOT NULL`, userID).Scan(&consumed); err != nil {
		t.Fatalf("count consumed tokens: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_outbox WHERE user_id=$1`, userID).Scan(&emailMessages); err != nil {
		t.Fatalf("count email outbox: %v", err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE aggregate_id=$1`, userID.String()).Scan(&auditEvents); err != nil {
		t.Fatalf("count audit outbox: %v", err)
	}
	if consumed != 1 || emailMessages != 2 || auditEvents != 2 {
		t.Fatalf("persisted reset state: consumed=%d email=%d audit=%d, want 1/2/2", consumed, emailMessages, auditEvents)
	}
}

func TestUserListFiltersStatusBeforePagination(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for index := 0; index < 6; index++ {
		status := models.UserStatusSuspended
		if index >= 3 {
			status = models.UserStatusActive
		}
		id := uuid.New()
		if _, err := schema.pool.Exec(ctx, `
			INSERT INTO users (id,username,status,role,auth_version,session_version,must_change_password,metadata,creation_source)
			VALUES ($1,$2,$3,'user',1,1,FALSE,'{}'::jsonb,'legacy')
		`, id, fmt.Sprintf("status-filter-%d-%s", index, id.String()), status); err != nil {
			t.Fatal(err)
		}
	}

	result, err := user.NewStore(schema.pool).List(ctx, models.NewPagination(1, 2), "", models.UserStatusActive)
	if err != nil {
		t.Fatalf("List(active): %v", err)
	}
	if result.Total != 3 || result.TotalPages != 2 || len(result.Items) != 2 {
		t.Fatalf("active pagination = total:%d pages:%d items:%d", result.Total, result.TotalPages, len(result.Items))
	}
	for _, item := range result.Items {
		if item.Status != models.UserStatusActive {
			t.Fatalf("non-active user returned in active page: %#v", item)
		}
	}
}

func TestRoleChangeIncrementsAuthVersion(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, userID, "role-change-"+userID.String()); err != nil {
		t.Fatal(err)
	}
	store := user.NewStore(schema.pool)
	role := "admin"
	actorID := uuid.New()
	updated, err := store.UpdateAdmin(ctx, userID, models.AdminUpdateUserRequest{Role: &role}, audit.MutationAudit{
		Event: models.AuditUserRoleChanged, ActorID: actorID, ActorName: "integration-admin",
		TargetType: "user", TargetID: userID.String(), Result: "success", RiskLevel: "high",
		IPAddress: "203.0.113.20", UserAgent: "nyauth-integration-test",
	})
	if err != nil {
		t.Fatalf("UpdateAdmin: %v", err)
	}
	if updated.Role != role || updated.AuthVersion != 2 {
		t.Fatalf("updated user role=%q auth_version=%d", updated.Role, updated.AuthVersion)
	}
	var payloadBytes []byte
	if err := schema.pool.QueryRow(ctx, `
		SELECT payload FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='user' AND aggregate_id=$2
	`, models.AuditUserRoleChanged, userID.String()).Scan(&payloadBytes); err != nil {
		t.Fatalf("read role-change audit outbox: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("decode role-change audit payload: %v", err)
	}
	for key, expected := range map[string]string{
		"actor_id": actorID.String(), "actor_name": "integration-admin", "target_type": "user", "target_id": userID.String(),
		"result": "success", "risk_level": "high", "ip_address": "203.0.113.20",
		"user_agent": "nyauth-integration-test",
	} {
		if actual, _ := payload[key].(string); actual != expected {
			t.Fatalf("role-change audit %s=%q, want %q (payload=%v)", key, actual, expected, payload)
		}
	}
}

func TestManagementMutationRollsBackWhenAuditEnqueueFails(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, userID, "audit-rollback-"+userID.String()); err != nil {
		t.Fatal(err)
	}
	role := "admin"
	_, err := user.NewStore(schema.pool).UpdateAdmin(ctx, userID, models.AdminUpdateUserRequest{Role: &role}, audit.MutationAudit{
		Event: models.AuditUserRoleChanged, ActorID: uuid.New(), ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", Details: map[string]any{"client_secret": "must-not-persist"},
	})
	if err == nil {
		t.Fatal("user update succeeded after audit payload rejection")
	}
	var storedRole string
	var authVersion int64
	if err := schema.pool.QueryRow(ctx, `SELECT role,auth_version FROM users WHERE id=$1`, userID).Scan(&storedRole, &authVersion); err != nil {
		t.Fatal(err)
	}
	if storedRole != "user" || authVersion != 1 {
		t.Fatalf("user mutation was not rolled back: role=%q auth_version=%d", storedRole, authVersion)
	}
	var outboxCount int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE aggregate_id=$1`, userID.String()).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 0 {
		t.Fatalf("audit outbox rows=%d after rejected transaction", outboxCount)
	}
	missingID := uuid.New()
	_, err = user.NewStore(schema.pool).UpdateAdmin(ctx, missingID, models.AdminUpdateUserRequest{Role: &role}, audit.MutationAudit{
		Event: models.AuditUserRoleChanged, ActorID: uuid.New(), ActorName: "integration-admin",
		Result: "success", RiskLevel: "high",
	})
	if err == nil {
		t.Fatal("missing user update unexpectedly succeeded")
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE aggregate_id=$1`, missingID.String()).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 0 {
		t.Fatalf("state-write failure left %d success audit rows", outboxCount)
	}
}

func TestSessionRevocationGenerationAndAuditCommitAtomically(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,session_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',11,7,FALSE,'{}'::jsonb,'legacy')
	`, userID, "session-revoke-"+userID.String()); err != nil {
		t.Fatal(err)
	}
	store := user.NewStore(schema.pool)
	actorID := uuid.New()
	mutation := audit.MutationAudit{
		Event: models.AuditUserSessionsRevoked, ActorID: actorID, ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", IPAddress: "203.0.113.30",
	}
	version, err := store.RevokeSessions(ctx, userID, mutation)
	if err != nil {
		t.Fatalf("RevokeSessions: %v", err)
	}
	if version != 8 {
		t.Fatalf("session_version=%d, want 8", version)
	}
	var authVersion, storedSessionVersion int64
	if err := schema.pool.QueryRow(ctx, `SELECT auth_version,session_version FROM users WHERE id=$1`, userID).Scan(&authVersion, &storedSessionVersion); err != nil {
		t.Fatal(err)
	}
	if authVersion != 11 || storedSessionVersion != 8 {
		t.Fatalf("stored versions = {auth:%d session:%d}, want {11 8}", authVersion, storedSessionVersion)
	}
	var storedEvent string
	var payloadBytes []byte
	if err := schema.pool.QueryRow(ctx, `
		SELECT event,payload FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2
	`, models.AuditUserSessionsRevoked, userID.String()).Scan(&storedEvent, &payloadBytes); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Details map[string]any `json:"details"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatal(err)
	}
	if storedEvent != models.AuditUserSessionsRevoked || payload.Details["session_version"] != float64(8) {
		t.Fatalf("unexpected session revocation audit: event=%q payload=%#v", storedEvent, payload)
	}

	invalidMutation := mutation
	invalidMutation.Details = map[string]any{"client_secret": "must-not-persist"}
	if _, err := store.RevokeSessions(ctx, userID, invalidMutation); err == nil {
		t.Fatal("session generation advanced after audit payload rejection")
	}
	if err := schema.pool.QueryRow(ctx, `SELECT session_version FROM users WHERE id=$1`, userID).Scan(&storedSessionVersion); err != nil {
		t.Fatal(err)
	}
	if storedSessionVersion != 8 {
		t.Fatalf("session generation was not rolled back: %d", storedSessionVersion)
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
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
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

func TestClientSecretRotationImmediatelyReplacesCredential(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ownerID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, ownerID, "secret-owner-"+ownerID.String()); err != nil {
		t.Fatalf("insert owner: %v", err)
	}

	service := client.NewService(client.NewStore(schema.pool))
	created, err := service.CreateForOwner(ctx, ownerID.String(), 10, models.CreateClientRequest{
		Name: "Confidential client", RedirectURIs: []string{"https://client.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
	})
	if err != nil {
		t.Fatalf("create confidential client: %v", err)
	}
	if created.Secret == "" || created.SecretVersion != 1 || created.SecretRotatedAt == nil || created.SecretHint == nil {
		t.Fatalf("missing initial secret metadata: %#v", created)
	}
	if _, err := service.AuthenticateClient(ctx, created.ID, created.Secret); err != nil {
		t.Fatalf("authenticate initial secret: %v", err)
	}

	rotated, err := service.RotateSecretForOwner(ctx, created.ID, ownerID.String())
	if err != nil {
		t.Fatalf("rotate secret: %v", err)
	}
	if rotated.Secret == "" || rotated.Secret == created.Secret || rotated.SecretVersion != 2 {
		t.Fatalf("unexpected rotation response: %#v", rotated)
	}
	if _, err := service.AuthenticateClient(ctx, created.ID, created.Secret); err == nil {
		t.Fatal("old secret remained valid after committed rotation")
	}
	authenticated, err := service.AuthenticateClient(ctx, created.ID, rotated.Secret)
	if err != nil {
		t.Fatalf("authenticate rotated secret: %v", err)
	}
	if authenticated.SecretVersion != 2 || authenticated.SecretLastUsedAt == nil {
		t.Fatalf("rotated secret metadata was not persisted: %#v", authenticated)
	}
	actorID := uuid.New()
	badMutation := audit.MutationAudit{
		Event: models.AuditClientSecretRotated, ActorID: actorID, ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", Details: map[string]any{"client_secret": "forbidden"},
	}
	if _, err := service.RotateSecret(ctx, created.ID, badMutation); err == nil {
		t.Fatal("admin rotation succeeded after audit payload rejection")
	}
	afterRollback, err := service.AuthenticateClient(ctx, created.ID, rotated.Secret)
	if err != nil || afterRollback.SecretVersion != 2 {
		t.Fatalf("failed audit did not roll secret rotation back: client=%#v err=%v", afterRollback, err)
	}
	adminRotated, err := service.RotateSecret(ctx, created.ID, audit.MutationAudit{
		Event: models.AuditClientSecretRotated, ActorID: actorID, ActorName: "integration-admin",
		Result: "success", RiskLevel: "high", IPAddress: "203.0.113.21", UserAgent: "nyauth-integration-test",
	})
	if err != nil {
		t.Fatalf("admin rotate secret: %v", err)
	}
	if adminRotated.SecretVersion != 3 || adminRotated.Secret == "" {
		t.Fatalf("unexpected admin rotation response: %#v", adminRotated)
	}
	if _, err := service.AuthenticateClient(ctx, created.ID, rotated.Secret); err == nil {
		t.Fatal("pre-admin-rotation secret remained valid")
	}
	var auditPayload []byte
	if err := schema.pool.QueryRow(ctx, `
		SELECT payload FROM audit_event_outbox
		WHERE event=$1 AND aggregate_type='client' AND aggregate_id=$2
	`, models.AuditClientSecretRotated, created.ID).Scan(&auditPayload); err != nil {
		t.Fatalf("read client rotation audit: %v", err)
	}
	serializedPayload := string(auditPayload)
	for _, forbidden := range []string{adminRotated.Secret, crypto.HashClientSecret(adminRotated.Secret), adminRotated.SecretHint} {
		if forbidden != "" && strings.Contains(serializedPayload, forbidden) {
			t.Fatalf("client rotation audit payload contains secret material: %s", serializedPayload)
		}
	}
	if _, err := service.RotateSecretForOwner(ctx, created.ID, uuid.NewString()); !errors.Is(err, client.ErrClientNotOwned) {
		t.Fatalf("cross-owner rotation error = %v", err)
	}

	publicClient, err := service.CreateForOwner(ctx, ownerID.String(), 10, models.CreateClientRequest{
		Name: "Public client", RedirectURIs: []string{"https://public.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create public client: %v", err)
	}
	if _, err := service.RotateSecretForOwner(ctx, publicClient.ID, ownerID.String()); !errors.Is(err, client.ErrPublicClientSecret) {
		t.Fatalf("public client rotation error = %v", err)
	}
}

func TestProviderMutationAuditIsAtomicAndSnapshotFollowsCommit(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	manager := provider.NewManager(schema.pool, []byte("0123456789abcdef0123456789abcdef"))
	actorID := uuid.New()
	mutation := func(event string, details map[string]any) audit.MutationAudit {
		return audit.MutationAudit{
			Event: event, ActorID: actorID, ActorName: "integration-admin", Result: "success",
			RiskLevel: "high", IPAddress: "203.0.113.22", UserAgent: "nyauth-integration-test", Details: details,
		}
	}
	const providerName = "integration-github"
	const plaintextSecret = "provider-secret-must-not-enter-audit"
	enabledOnCreate := true
	created, err := manager.CreateProvider(ctx, models.CreateProviderRequest{
		Name: providerName, DisplayName: "Integration GitHub", IconKey: "github",
		Type: "github", ClientID: "provider-client", ClientSecret: plaintextSecret,
		Enabled: &enabledOnCreate, Scopes: []string{"read:user", "user:email"},
	}, mutation(models.AuditProviderCreated, nil))
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if _, ok := manager.Get(providerName); !ok {
		t.Fatal("committed enabled provider was not installed in runtime snapshot")
	}
	if created.DisplayName != "Integration GitHub" || created.IconKey != "github" {
		t.Fatalf("created provider presentation = %q/%q", created.DisplayName, created.IconKey)
	}
	listed := manager.List()
	if len(listed) != 1 || listed[0].DisplayName != created.DisplayName || listed[0].IconKey != created.IconKey {
		t.Fatalf("runtime provider presentation = %#v", listed)
	}
	var createPayload []byte
	if err := schema.pool.QueryRow(ctx, `SELECT payload FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2`, models.AuditProviderCreated, providerName).Scan(&createPayload); err != nil {
		t.Fatalf("read provider creation audit: %v", err)
	}
	for _, forbidden := range []string{plaintextSecret, created.ClientSecret} {
		if forbidden != "" && strings.Contains(string(createPayload), forbidden) {
			t.Fatalf("provider audit payload contains secret material: %s", createPayload)
		}
	}

	disabled := false
	const disabledProviderName = "integration-github-disabled"
	disabledProvider, err := manager.CreateProvider(ctx, models.CreateProviderRequest{
		Name: disabledProviderName, Type: "github", ClientID: "disabled-client", ClientSecret: plaintextSecret,
		Enabled: &disabled, Scopes: []string{"read:user"},
	}, mutation(models.AuditProviderCreated, nil))
	if err != nil {
		t.Fatalf("CreateProvider(disabled): %v", err)
	}
	if disabledProvider.Enabled {
		t.Fatal("disabled provider was persisted as enabled")
	}
	if _, ok := manager.Get(disabledProviderName); ok {
		t.Fatal("disabled provider entered the runtime snapshot during creation")
	}
	var persistedDisabled bool
	if err := schema.pool.QueryRow(ctx, `SELECT enabled FROM oauth_providers WHERE name=$1`, disabledProviderName).Scan(&persistedDisabled); err != nil {
		t.Fatalf("read disabled provider state: %v", err)
	}
	if persistedDisabled {
		t.Fatal("disabled provider database row is enabled")
	}
	var disabledAuditEvents int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE event=$1 AND aggregate_id=$2`, models.AuditProviderCreated, disabledProviderName).Scan(&disabledAuditEvents); err != nil {
		t.Fatalf("count disabled provider audit events: %v", err)
	}
	if disabledAuditEvents != 1 {
		t.Fatalf("disabled provider audit events = %d, want 1", disabledAuditEvents)
	}

	updatedDisplayName, updatedIconKey := "GitHub for Employees", "link"
	created, err = manager.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{
		DisplayName: &updatedDisplayName, IconKey: &updatedIconKey,
	}, mutation(models.AuditProviderUpdated, nil))
	if err != nil {
		t.Fatalf("update provider presentation: %v", err)
	}
	if created.DisplayName != updatedDisplayName || created.IconKey != updatedIconKey {
		t.Fatalf("updated provider presentation = %q/%q", created.DisplayName, created.IconKey)
	}

	if _, err := manager.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{Enabled: &disabled}, mutation(models.AuditProviderUpdated, map[string]any{"provider_secret": "forbidden"})); err == nil {
		t.Fatal("provider update succeeded after audit payload rejection")
	}
	var enabled bool
	var revision int64
	if err := schema.pool.QueryRow(ctx, `SELECT enabled,revision FROM oauth_providers WHERE name=$1`, providerName).Scan(&enabled, &revision); err != nil {
		t.Fatal(err)
	}
	if !enabled || revision != created.Revision {
		t.Fatalf("failed provider audit did not roll update back: enabled=%v revision=%d", enabled, revision)
	}
	if _, ok := manager.Get(providerName); !ok {
		t.Fatal("runtime snapshot changed before failed transaction committed")
	}
	if _, err := manager.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{Enabled: &disabled}, mutation(models.AuditProviderUpdated, nil)); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	if _, ok := manager.Get(providerName); ok {
		t.Fatal("disabled provider remained in runtime snapshot")
	}
	enabledValue := true
	if _, err := manager.UpdateProvider(ctx, providerName, models.UpdateProviderRequest{Enabled: &enabledValue}, mutation(models.AuditProviderUpdated, nil)); err != nil {
		t.Fatalf("re-enable provider: %v", err)
	}
	if _, ok := manager.Get(providerName); !ok {
		t.Fatal("re-enabled provider was not restored to runtime snapshot")
	}
	if err := manager.DeleteProvider(ctx, providerName, mutation(models.AuditProviderDeleted, map[string]any{"client_secret": "forbidden"})); err == nil {
		t.Fatal("provider deletion succeeded after audit payload rejection")
	}
	if _, ok := manager.Get(providerName); !ok {
		t.Fatal("failed provider deletion removed runtime snapshot entry")
	}
	if err := manager.DeleteProvider(ctx, providerName, mutation(models.AuditProviderDeleted, nil)); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, ok := manager.Get(providerName); ok {
		t.Fatal("deleted provider remained in runtime snapshot")
	}
	var providerRows int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_providers WHERE name=$1`, providerName).Scan(&providerRows); err != nil {
		t.Fatal(err)
	}
	if providerRows != 0 {
		t.Fatalf("deleted provider rows=%d", providerRows)
	}
}

func TestSecurityNotificationsShareUserAndIdentityMutationTransactions(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	accountService, err := account.NewService(account.NewStore(schema.pool), account.ServiceOptions{
		PublicBaseURL: "https://auth.example.test", ActiveKeyID: "primary",
		MasterKeys: map[string][]byte{"primary": []byte("0123456789abcdef0123456789abcdef")},
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	verifiedAt := time.Now().UTC().Add(-time.Hour)
	primaryUserID, passwordlessUserID := uuid.New(), uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,email,email_verified_at,password_hash,password_changed_at,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES
		($1,$2,$3,$4,'initial-hash',$4,'active','user',1,FALSE,'{}'::jsonb,'legacy'),
		($5,$6,$7,$4,NULL,NULL,'active','admin',1,FALSE,'{}'::jsonb,'legacy')
	`, primaryUserID, "notice-primary-"+primaryUserID.String(), "primary@example.test", verifiedAt,
		passwordlessUserID, "notice-passwordless-"+passwordlessUserID.String(), "passwordless@example.test"); err != nil {
		t.Fatalf("insert notification users: %v", err)
	}
	actorID := uuid.New()
	mutation := func(event string) audit.MutationAudit {
		return audit.MutationAudit{
			Event: event, ActorID: actorID, ActorName: "integration-admin", Result: "success",
			RiskLevel: "high", IPAddress: "203.0.113.23", UserAgent: "nyauth-integration-test",
		}
	}
	userStore := user.NewStore(schema.pool)
	userStore.SetSecurityNotificationBuilder(accountService)
	role := "admin"
	if _, err := userStore.UpdateAdmin(ctx, primaryUserID, models.AdminUpdateUserRequest{Role: &role}, mutation(models.AuditUserRoleChanged)); err != nil {
		t.Fatalf("role update with notification: %v", err)
	}
	unverifiedUserID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,email,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,$3,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, unverifiedUserID, "notice-unverified-"+unverifiedUserID.String(), "unverified@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := userStore.UpdateAdmin(ctx, unverifiedUserID, models.AdminUpdateUserRequest{Role: &role}, mutation(models.AuditUserRoleChanged)); err != nil {
		t.Fatalf("unverified user role update: %v", err)
	}
	var skippedEmails int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_outbox WHERE user_id=$1`, unverifiedUserID).Scan(&skippedEmails); err != nil {
		t.Fatal(err)
	}
	if skippedEmails != 0 {
		t.Fatalf("unverified user queued %d security emails", skippedEmails)
	}
	if _, err := userStore.ResetPassword(ctx, primaryUserID, "administrator-reset-hash", mutation(models.AuditUserPasswordReset)); err != nil {
		t.Fatalf("admin password reset with notification: %v", err)
	}
	if _, err := userStore.UpdatePassword(ctx, primaryUserID, "self-password-change-hash", false, mutation(models.AuditUserPasswordChanged)); err != nil {
		t.Fatalf("self password change with notification: %v", err)
	}
	if _, err := userStore.SetPasswordIfMissing(ctx, passwordlessUserID, "configured-password-hash", mutation(models.AuditUserPasswordSet)); err != nil {
		t.Fatalf("password configuration with notification: %v", err)
	}

	identityStore := identity.NewStore(schema.pool)
	identityStore.SetSecurityNotificationBuilder(accountService)
	binding := &models.Identity{
		ID: uuid.New(), UserID: primaryUserID, Provider: "github", ExternalID: "external-stable-id",
		Metadata: map[string]string{},
	}
	if err := identityStore.Create(ctx, binding, mutation(models.AuditIdentityBound)); err != nil {
		t.Fatalf("identity binding with notification: %v", err)
	}
	if err := identityStore.DeleteOwned(ctx, primaryUserID, binding.ID, mutation(models.AuditIdentityUnbound)); err != nil {
		t.Fatalf("identity removal with notification: %v", err)
	}

	for _, messageType := range []string{
		account.MessageRoleChanged, account.MessagePasswordResetAdmin, account.MessagePasswordChanged,
		account.MessagePasswordConfigured, account.MessageIdentityBound, account.MessageIdentityUnbound,
	} {
		var count int
		if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM email_outbox WHERE message_type=$1`, messageType).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("email outbox %s count=%d, want 1", messageType, count)
		}
	}
	rows, err := schema.pool.Query(ctx, `SELECT encrypted_message FROM email_outbox`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var encrypted string
		if err := rows.Scan(&encrypted); err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"administrator-reset-hash", "self-password-change-hash", "configured-password-hash", "external-stable-id"} {
			if strings.Contains(encrypted, forbidden) {
				t.Fatalf("security notification leaked sensitive value %q", forbidden)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	failingUserStore := user.NewStore(schema.pool)
	failingUserStore.SetSecurityNotificationBuilder(invalidEmailNotificationBuilder{})
	suspended := models.UserStatusSuspended
	if _, err := failingUserStore.UpdateAdmin(ctx, primaryUserID, models.AdminUpdateUserRequest{Status: &suspended}, mutation(models.AuditUserSuspended)); err == nil {
		t.Fatal("user status mutation committed after email outbox failure")
	}
	var storedStatus models.UserStatus
	if err := schema.pool.QueryRow(ctx, `SELECT status FROM users WHERE id=$1`, primaryUserID).Scan(&storedStatus); err != nil {
		t.Fatal(err)
	}
	if storedStatus != models.UserStatusActive {
		t.Fatalf("status mutation was not rolled back: %s", storedStatus)
	}

	failingIdentityStore := identity.NewStore(schema.pool)
	failingIdentityStore.SetSecurityNotificationBuilder(invalidEmailNotificationBuilder{})
	failedBinding := &models.Identity{
		ID: uuid.New(), UserID: primaryUserID, Provider: "google", ExternalID: "failed-external-id", Metadata: map[string]string{},
	}
	if err := failingIdentityStore.Create(ctx, failedBinding, mutation(models.AuditIdentityBound)); err == nil {
		t.Fatal("identity binding committed after email outbox failure")
	}
	var identityRows, auditRows int
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM identities WHERE id=$1`, failedBinding.ID).Scan(&identityRows); err != nil {
		t.Fatal(err)
	}
	if err := schema.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_event_outbox WHERE aggregate_id=$1`, failedBinding.ID.String()).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if identityRows != 0 || auditRows != 0 {
		t.Fatalf("failed identity transaction left state=%d audit=%d", identityRows, auditRows)
	}
}

func TestOAuthAuthorizationStoreUpsertListRevokeAndReauthorize(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, userID, "authorization-user-"+userID.String()); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	clientService := client.NewService(client.NewStore(schema.pool))
	registered, err := clientService.CreateForOwner(ctx, userID.String(), 10, models.CreateClientRequest{
		Name: "Authorization client", RedirectURIs: []string{"https://authorization.example/callback"},
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid", "profile"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	store := authorization.NewStore(schema.pool)
	grantedAt := time.Date(2026, 7, 26, 10, 0, 0, 0, time.UTC)
	if err := store.Upsert(ctx, userID, registered.ID, []string{"profile", "openid", "profile"}, grantedAt); err != nil {
		t.Fatalf("upsert authorization: %v", err)
	}
	items, err := store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list authorizations: %v", err)
	}
	if len(items) != 1 || items[0].ClientName != "Authorization client" || strings.Join(items[0].Scopes, " ") != "openid profile" {
		t.Fatalf("unexpected authorization list: %#v", items)
	}

	revokedAt := grantedAt.Add(time.Hour)
	if err := store.Revoke(ctx, userID, registered.ID, revokedAt); err != nil {
		t.Fatalf("revoke authorization: %v", err)
	}
	items, err = store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list revoked authorizations: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("revoked authorization remained active: %#v", items)
	}
	if err := store.Upsert(ctx, userID, registered.ID, []string{"profile"}, grantedAt.Add(30*time.Minute)); err != nil {
		t.Fatalf("apply stale consent after revocation: %v", err)
	}
	items, err = store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list after stale consent: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("stale consent reactivated a newer revocation: %#v", items)
	}

	reauthorizedAt := revokedAt.Add(time.Hour)
	if err := store.Upsert(ctx, userID, registered.ID, []string{"openid"}, reauthorizedAt); err != nil {
		t.Fatalf("reauthorize: %v", err)
	}
	items, err = store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list reauthorized grant: %v", err)
	}
	if len(items) != 1 || items[0].RevokedAt != nil || !items[0].GrantedAt.Equal(reauthorizedAt) || strings.Join(items[0].Scopes, " ") != "openid" {
		t.Fatalf("unexpected reauthorized grant: %#v", items)
	}
	if err := store.Revoke(ctx, userID, registered.ID, revokedAt); !errors.Is(err, authorization.ErrAuthorizationNewer) {
		t.Fatalf("stale concurrent revocation error = %v", err)
	}
	items, err = store.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list after stale revocation: %v", err)
	}
	if len(items) != 1 || !items[0].GrantedAt.Equal(reauthorizedAt) {
		t.Fatalf("stale revocation removed newer grant: %#v", items)
	}
}

func TestConsentPersistsAuthorizationAndBindsIssuedTimeToCode(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := schema.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,auth_version,must_change_password,metadata,creation_source)
		VALUES ($1,$2,'active','user',1,FALSE,'{}'::jsonb,'legacy')
	`, userID, "consent-user-"+userID.String()); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	clientStore := client.NewStore(schema.pool)
	clientService := client.NewService(clientStore)
	registered, err := clientService.CreateForOwner(ctx, userID.String(), 10, models.CreateClientRequest{
		Name: "Consent client", RedirectURIs: []string{"https://consent.example/callback?tenant=one"},
		Grants: []string{models.GrantAuthorizationCode, models.GrantRefreshToken},
		Scopes: []string{"openid", "offline_access"}, IsPublic: true,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	mini := miniredis.RunT(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })
	sessionStore := session.NewStore(redisClient)
	sessionData := &session.SessionData{UserID: userID.String(), Username: "alice", AuthVersion: 1, CSRFToken: "csrf-token"}
	if err := sessionStore.SaveSession(ctx, "session-secret", sessionData, time.Hour); err != nil {
		t.Fatalf("save session: %v", err)
	}
	consentData := &session.ConsentData{
		ClientID: registered.ID, UserID: userID.String(), RedirectURI: registered.RedirectURIs[0],
		Scopes: []string{"openid", "offline_access"}, State: "opaque-state", CodeChallenge: strings.Repeat("a", 43),
		ChallengeMethod: "S256", Nonce: "nonce", AuthVersion: 1,
	}
	if err := sessionStore.SaveConsent(ctx, "consent-challenge", consentData, 10*time.Minute); err != nil {
		t.Fatalf("save consent challenge: %v", err)
	}
	authorizationStore := authorization.NewStore(schema.pool)
	handler := auth.NewConsentHandler(sessionStore, nil, clientStore, authorizationStore, &config.Config{
		Auth: config.AuthConfig{AuthorizationCodeTTL: time.Minute},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/consent/accept", strings.NewReader(`{"challenge":"consent-challenge"}`))
	request.AddCookie(&http.Cookie{Name: "nyauth_session", Value: "session-secret"})
	request.Header.Set("X-CSRF-Token", "csrf-token")
	response := httptest.NewRecorder()
	handler.AcceptConsent(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("consent status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		RedirectURL string `json:"redirect_url"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode consent response: %v", err)
	}
	redirect, err := url.Parse(payload.RedirectURL)
	if err != nil {
		t.Fatalf("parse consent redirect: %v", err)
	}
	if redirect.Query().Get("tenant") != "one" || redirect.Query().Get("state") != "opaque-state" {
		t.Fatalf("redirect parameters were not preserved: %s", payload.RedirectURL)
	}
	code := redirect.Query().Get("code")
	if code == "" {
		t.Fatalf("authorization code missing from redirect: %s", payload.RedirectURL)
	}
	storedCode, err := sessionStore.GetAuthorizationCode(ctx, code)
	if err != nil {
		t.Fatalf("load authorization code: %v", err)
	}
	if storedCode.AuthorizationIssuedAt <= 0 || storedCode.ClientID != registered.ID || storedCode.UserID != userID.String() {
		t.Fatalf("authorization code is missing grant binding: %#v", storedCode)
	}
	items, err := authorizationStore.ListByUser(ctx, userID)
	if err != nil {
		t.Fatalf("list persisted authorization: %v", err)
	}
	if len(items) != 1 || items[0].ClientID != registered.ID || items[0].GrantedAt.UnixMicro() != storedCode.AuthorizationIssuedAt {
		t.Fatalf("persisted grant does not match code: items=%#v code=%#v", items, storedCode)
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
