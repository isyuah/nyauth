package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/invite"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/internal/telemetry"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

type registrationHTTPTestApp struct {
	app  *Server
	pool *pgxpool.Pool
	mini *miniredis.Miniredis
}

func newRegistrationHTTPTestApp(t *testing.T) *registrationHTTPTestApp {
	t.Helper()
	baseDSN := strings.TrimSpace(os.Getenv("NYAUTH_TEST_DATABASE_DSN"))
	if baseDSN == "" {
		t.Skip("NYAUTH_TEST_DATABASE_DSN is required for registration HTTP integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	basePool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("connect registration HTTP PostgreSQL: %v", err)
	}
	if err := basePool.Ping(ctx); err != nil {
		basePool.Close()
		t.Fatalf("ping registration HTTP PostgreSQL: %v", err)
	}
	schemaName := "nyauth_registration_http_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := basePool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		basePool.Close()
		t.Fatalf("create registration HTTP schema: %v", err)
	}

	scopedDSN := registrationHTTPDSNWithSearchPath(t, baseDSN, schemaName)
	if err := database.RunMigrations(scopedDSN); err != nil {
		_, _ = basePool.Exec(context.Background(), "DROP SCHEMA "+identifier+" CASCADE")
		basePool.Close()
		t.Fatalf("migrate registration HTTP schema: %v", err)
	}
	poolConfig, err := pgxpool.ParseConfig(baseDSN)
	if err != nil {
		t.Fatalf("parse registration HTTP PostgreSQL DSN: %v", err)
	}
	if poolConfig.ConnConfig.RuntimeParams == nil {
		poolConfig.ConnConfig.RuntimeParams = make(map[string]string)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schemaName
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("connect registration HTTP schema: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping registration HTTP schema: %v", err)
	}

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	telemetryRuntime, err := telemetry.New(ctx, telemetry.Options{})
	if err != nil {
		_ = rdb.Close()
		pool.Close()
		t.Fatalf("create registration HTTP telemetry: %v", err)
	}
	cfg := &config.Config{
		Environment: "test",
		Server: config.ServerConfig{
			SecureCookie: false, ReadinessTimeout: 2 * time.Second, ShutdownTimeout: 2 * time.Second,
		},
		Auth: config.AuthConfig{
			Issuer: "https://auth.example.test", MasterKey: []byte("0123456789abcdef0123456789abcdef"),
			Argon2Concurrency: 2, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour,
			AuthorizationCodeTTL: time.Minute,
			JWK: config.JWKConfig{
				Algorithm: "RS256", KeySize: 2048, RotationInterval: 24 * time.Hour,
			},
		},
		Mail: config.MailConfig{
			Enabled: true, FromAddress: "noreply@example.test", FromName: "Nyauth",
			PublicBaseURL: "https://auth.example.test",
			SMTP: config.SMTPConfig{
				Host: "smtp.example.test", Port: 587, TLSMode: "starttls",
				ConnectTimeout: time.Second, SendTimeout: time.Second,
			},
		},
	}
	app, err := New(cfg, pool, rdb, embed.FS{}, telemetryRuntime)
	if err != nil {
		_ = telemetryRuntime.Shutdown(context.Background())
		_ = rdb.Close()
		pool.Close()
		t.Fatalf("create registration HTTP app: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cleanupCancel()
		if err := telemetryRuntime.Shutdown(cleanupCtx); err != nil {
			t.Errorf("shutdown registration HTTP telemetry: %v", err)
		}
		_ = rdb.Close()
		pool.Close()
		if _, err := basePool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE"); err != nil {
			t.Errorf("drop registration HTTP schema %s: %v", schemaName, err)
		}
		basePool.Close()
	})
	return &registrationHTTPTestApp{app: app, pool: pool, mini: mini}
}

func registrationHTTPDSNWithSearchPath(t *testing.T, dsn, schemaName string) string {
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

func (testApp *registrationHTTPTestApp) setRegistration(t *testing.T, value settings.Registration) {
	t.Helper()
	if err := testApp.app.settingsMgr.SetRegistration(context.Background(), value, "integration-admin"); err != nil {
		t.Fatalf("set registration settings: %v", err)
	}
}

func registrationHTTPRequest(app *Server, method, path, body, origin, remoteAddress string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	request.RemoteAddr = remoteAddress
	recorder := httptest.NewRecorder()
	app.router.ServeHTTP(recorder, request)
	return recorder
}

func createHTTPTestInvite(t *testing.T, testApp *registrationHTTPTestApp, maxUses int) string {
	t.Helper()
	code := "http-invite-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Now().UTC()
	if _, err := testApp.pool.Exec(context.Background(), `
		INSERT INTO invites (id,code_hash,note,max_uses,expires_at,created_at)
		VALUES ($1,$2,'HTTP registration invite',$3,$4,$5)
	`, uuid.New(), invite.HashCode(code), maxUses, now.Add(time.Hour), now.Add(-time.Minute)); err != nil {
		t.Fatalf("create HTTP registration invite: %v", err)
	}
	return code
}

func TestRegistrationHTTPModesAndExactDeadline(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	defaults := settings.DefaultRegistration()

	testApp.setRegistration(t, defaults)
	closed := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"closed-user","email":"closed@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.40:12345",
	)
	if closed.Code != http.StatusForbidden {
		t.Fatalf("closed registration status = %d, body=%s", closed.Code, closed.Body.String())
	}

	inviteSettings := defaults
	inviteSettings.Mode = settings.RegistrationInviteOnly
	inviteSettings.PendingRegistrationTTL = "4h"
	testApp.setRegistration(t, inviteSettings)
	missingInvite := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"missing-invite","email":"missing@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.41:12345",
	)
	if missingInvite.Code != http.StatusBadRequest {
		t.Fatalf("missing invite status = %d, body=%s", missingInvite.Code, missingInvite.Body.String())
	}
	code := createHTTPTestInvite(t, testApp, 1)
	inviteResponse := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"invited-user","email":"invited@example.test","password":"a-valid-password-123","invite_code":"`+code+`"}`,
		"https://auth.example.test", "192.0.2.42:12345",
	)
	if inviteResponse.Code != http.StatusCreated {
		t.Fatalf("invite-only registration status = %d, body=%s", inviteResponse.Code, inviteResponse.Body.String())
	}

	openSettings := defaults
	openSettings.Mode = settings.RegistrationOpen
	openSettings.PendingRegistrationTTL = "2h"
	testApp.setRegistration(t, openSettings)
	startedAt := time.Now().UTC()
	openResponse := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"open-user","email":"open@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.43:12345",
	)
	finishedAt := time.Now().UTC()
	if openResponse.Code != http.StatusCreated {
		t.Fatalf("open registration status = %d, body=%s", openResponse.Code, openResponse.Body.String())
	}
	var result models.RegisterResponse
	if err := json.Unmarshal(openResponse.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode open registration response: %v", err)
	}
	if result.Status != "pending_verification" || result.VerificationExpiresAt == nil {
		t.Fatalf("open registration response = %#v", result)
	}
	minimum := startedAt.Add(2 * time.Hour)
	maximum := finishedAt.Add(2 * time.Hour)
	if result.VerificationExpiresAt.Before(minimum) || result.VerificationExpiresAt.After(maximum) {
		t.Fatalf("verification expiry %s outside [%s,%s]", result.VerificationExpiresAt, minimum, maximum)
	}
	var persistedExpiry time.Time
	if err := testApp.pool.QueryRow(context.Background(), `
		SELECT registration.expires_at
		FROM self_registrations AS registration
		JOIN users ON users.id=registration.user_id
		WHERE users.username='open-user'
	`).Scan(&persistedExpiry); err != nil {
		t.Fatalf("read persisted registration deadline: %v", err)
	}
	if difference := persistedExpiry.Sub(*result.VerificationExpiresAt); difference < -time.Microsecond || difference > time.Microsecond {
		t.Fatalf("persisted expiry = %s, response expiry = %s", persistedExpiry, result.VerificationExpiresAt)
	}
}

func TestRegistrationHTTPRejectsUnknownModeCrossOriginAndRateLimit(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	defaults := settings.DefaultRegistration()
	unknown := defaults
	unknown.Mode = "unknown"
	testApp.setRegistration(t, unknown)
	unknownResponse := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"unknown-mode","email":"unknown@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.50:12345",
	)
	if unknownResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("unknown mode status = %d, body=%s", unknownResponse.Code, unknownResponse.Body.String())
	}

	openSettings := defaults
	openSettings.Mode = settings.RegistrationOpen
	testApp.setRegistration(t, openSettings)
	crossOrigin := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"cross-origin","email":"cross@example.test","password":"a-valid-password-123"}`,
		"https://evil.example.test", "192.0.2.51:12345",
	)
	if crossOrigin.Code != http.StatusForbidden {
		t.Fatalf("cross-origin registration status = %d, body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}

	for attempt := 1; attempt <= 6; attempt++ {
		limited := registrationHTTPRequest(
			testApp.app, http.MethodPost, "/api/register",
			`{"username":"x","email":"rate@example.test","password":"a-valid-password-123"}`,
			"https://auth.example.test", "192.0.2.52:12345",
		)
		if attempt <= 5 && limited.Code != http.StatusBadRequest {
			t.Fatalf("registration attempt %d status = %d, body=%s", attempt, limited.Code, limited.Body.String())
		}
		if attempt == 6 && (limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "") {
			t.Fatalf("limited registration: status=%d retry=%q body=%s", limited.Code, limited.Header().Get("Retry-After"), limited.Body.String())
		}
	}

	testApp.mini.Close()
	redisFailure := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"redis-failure","email":"redis@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.53:12345",
	)
	if redisFailure.Code != http.StatusServiceUnavailable {
		t.Fatalf("Redis failure status = %d, body=%s", redisFailure.Code, redisFailure.Body.String())
	}
}

func TestRegistrationHTTPInfrastructureFailureRollsBackAndReturnsUnavailable(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	registrationSettings := settings.DefaultRegistration()
	registrationSettings.Mode = settings.RegistrationOpen
	testApp.setRegistration(t, registrationSettings)
	if _, err := testApp.pool.Exec(context.Background(), `DROP TABLE email_outbox`); err != nil {
		t.Fatalf("remove email outbox for failure injection: %v", err)
	}

	response := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/register",
		`{"username":"transaction-failure","email":"transaction-failure@example.test","password":"a-valid-password-123"}`,
		"https://auth.example.test", "192.0.2.54:12345",
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("infrastructure failure status = %d, body=%s", response.Code, response.Body.String())
	}
	for name, query := range map[string]string{
		"user":         `SELECT COUNT(*) FROM users WHERE username='transaction-failure'`,
		"registration": `SELECT COUNT(*) FROM self_registrations`,
		"token":        `SELECT COUNT(*) FROM account_action_tokens`,
		"audit":        `SELECT COUNT(*) FROM audit_event_outbox WHERE event IN ('user.registered','account.action_requested')`,
	} {
		var count int
		if err := testApp.pool.QueryRow(context.Background(), query).Scan(&count); err != nil {
			t.Fatalf("count %s rows after infrastructure rollback: %v", name, err)
		}
		if count != 0 {
			t.Fatalf("%s rows after infrastructure rollback = %d", name, count)
		}
	}
}

func TestRegistrationAdministrationRequiresRecentAuthenticationButRevocationDoesNot(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	admin := &models.User{ID: uuid.New(), Username: "registration-admin", Status: models.UserStatusActive, Role: "admin", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{}}
	if _, err := testApp.pool.Exec(context.Background(), `
		INSERT INTO users (id,username,status,role,auth_version,session_version,metadata)
		VALUES ($1,$2,'active','admin',1,1,'{}'::jsonb)
	`, admin.ID, admin.Username); err != nil {
		t.Fatalf("insert registration administrator: %v", err)
	}

	requestWithAuthentication := func(method, path, body string, authenticatedAt time.Time, mutation audit.MutationAudit) *http.Request {
		request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		request.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
		ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{
			ID: "registration-admin-session",
			Data: &session.SessionData{
				UserID: admin.ID.String(), Username: admin.Username,
				AuthenticatedAt: authenticatedAt, AuthVersion: admin.AuthVersion,
			},
		})
		ctx = audit.WithMutationAudit(ctx, mutation)
		return request.WithContext(ctx)
	}

	createMutation := audit.MutationAudit{
		Event: models.AuditInviteCreated, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "medium",
	}
	staleCreate := requestWithAuthentication(http.MethodPost, "/api/admin/invites", `{"note":"stale"}`, time.Now().Add(-11*time.Minute), createMutation)
	staleCreateRecorder := httptest.NewRecorder()
	testApp.app.handleCreateInvite(staleCreateRecorder, staleCreate)
	if staleCreateRecorder.Code != http.StatusForbidden {
		t.Fatalf("stale invite creation status = %d, body=%s", staleCreateRecorder.Code, staleCreateRecorder.Body.String())
	}

	recentCreate := requestWithAuthentication(http.MethodPost, "/api/admin/invites", `{"note":"recent"}`, time.Now(), createMutation)
	recentCreateRecorder := httptest.NewRecorder()
	testApp.app.handleCreateInvite(recentCreateRecorder, recentCreate)
	if recentCreateRecorder.Code != http.StatusCreated {
		t.Fatalf("recent invite creation status = %d, body=%s", recentCreateRecorder.Code, recentCreateRecorder.Body.String())
	}
	var created models.CreateInviteResponse
	if err := json.Unmarshal(recentCreateRecorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created invite: %v", err)
	}

	settingsMutation := audit.MutationAudit{
		Event: models.AuditSettingsUpdated, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "high", TargetType: "settings", TargetID: "registration",
	}
	settingsBody := `{"mode":"open","require_email_verification":true,"allowed_email_domains":[],"pending_registration_ttl":"72h","invite_default_ttl":"168h","invite_default_max_uses":1}`
	staleSettings := requestWithAuthentication(http.MethodPut, "/api/admin/settings/registration", settingsBody, time.Now().Add(-11*time.Minute), settingsMutation)
	staleSettingsRecorder := httptest.NewRecorder()
	testApp.app.handleUpdateRegistrationSettings(staleSettingsRecorder, staleSettings)
	if staleSettingsRecorder.Code != http.StatusForbidden {
		t.Fatalf("stale registration settings status = %d, body=%s", staleSettingsRecorder.Code, staleSettingsRecorder.Body.String())
	}
	recentSettings := requestWithAuthentication(http.MethodPut, "/api/admin/settings/registration", settingsBody, time.Now(), settingsMutation)
	recentSettingsRecorder := httptest.NewRecorder()
	testApp.app.handleUpdateRegistrationSettings(recentSettingsRecorder, recentSettings)
	if recentSettingsRecorder.Code != http.StatusOK {
		t.Fatalf("recent registration settings status = %d, body=%s", recentSettingsRecorder.Code, recentSettingsRecorder.Body.String())
	}

	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", created.ID.String())
	revokeRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/invites/"+created.ID.String(), nil)
	revokeRequest = revokeRequest.WithContext(context.WithValue(revokeRequest.Context(), chi.RouteCtxKey, routeContext))
	revokeRequest = revokeRequest.WithContext(audit.WithMutationAudit(revokeRequest.Context(), audit.MutationAudit{
		Event: models.AuditInviteRevoked, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "medium", TargetType: "invite", TargetID: created.ID.String(),
	}))
	revokeRecorder := httptest.NewRecorder()
	testApp.app.handleRevokeInvite(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusNoContent {
		t.Fatalf("invite revocation without recent session status = %d, body=%s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
}
