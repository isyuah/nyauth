package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

func TestMetricsUseRoutePatternAndExposePrometheus(t *testing.T) {
	runtime, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })

	handler := runtime.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health-check", nil))

	recorder := httptest.NewRecorder()
	runtime.PrometheusHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "nyauth_http_server_requests") || !strings.Contains(body, "status_class=\"2xx\"") {
		t.Fatalf("expected HTTP metric was not exported:\n%s", body)
	}
	if strings.Contains(body, "health-check") || !strings.Contains(body, `route="unmatched"`) {
		t.Fatalf("raw unmatched route leaked into HTTP metric:\n%s", body)
	}
}

func TestHTTPMetricsBoundUnknownMethodsAndUnmatchedPaths(t *testing.T) {
	runtime, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })
	handler := runtime.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("PRIVATE-METHOD-123", "/users/private-user-123", nil))
	body := scrapeMetrics(t, runtime)
	if strings.Contains(body, "PRIVATE-METHOD-123") || strings.Contains(body, "private-user-123") {
		t.Fatalf("unbounded HTTP label was exported:\n%s", body)
	}
	if !strings.Contains(body, `method="OTHER"`) || !strings.Contains(body, `route="unmatched"`) {
		t.Fatalf("bounded HTTP labels were not exported:\n%s", body)
	}
}

func TestNewRejectsIncompleteOTLPConfiguration(t *testing.T) {
	_, err := New(context.Background(), Options{
		OTLPEnabled:        true,
		OTLPExportInterval: time.Second,
		OTLPTimeout:        time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "endpoint is required") {
		t.Fatalf("New() error = %v", err)
	}
}

func TestSecurityMetricsBoundAllLabelValues(t *testing.T) {
	runtime, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })

	runtime.RecordCSRFReject(t.Context(), "token-for-user-123")
	runtime.RecordOAuthGrant(t.Context(), "private_extension", "unexpected", "refresh-token-secret")
	runtime.RecordOAuthGrant(t.Context(), "refresh_token", "failure", "refresh_reuse")
	runtime.RecordProviderEvent(t.Context(), "callback", "login", "failure", "provider_authentication_failed", time.Millisecond)
	runtime.RecordProviderEvent(t.Context(), "provider-name-123", "user-id-123", "unexpected", "upstream-secret", time.Millisecond)
	runtime.RecordJWKRotation(t.Context(), "scheduled", "success", "none", time.Millisecond)
	runtime.RecordRateLimit(t.Context(), "account_action", "email_change", "rejected")
	runtime.RecordRateLimit(t.Context(), "account_action", "register", "rejected")
	runtime.RecordRateLimit(t.Context(), "ip-address", "user-id", "unexpected")
	runtime.RecordRegistrationOutcome(t.Context(), "success", "pending_verification")
	runtime.RecordRegistrationOutcome(t.Context(), "unexpected", "private-registration-reason")
	runtime.RecordEmailVerificationDuration(t.Context(), 15*time.Minute)
	runtime.RecordSMTPDelivery(t.Context(), "failure", true)
	runtime.RecordSMTPError(t.Context(), "transport")
	runtime.RecordSMTPError(t.Context(), "smtp-host-secret")
	runtime.RecordSMTPCircuitState(t.Context(), "open")
	runtime.RecordSMTPBacklog(t.Context(), 7, 12*time.Minute)

	body := scrapeMetrics(t, runtime)
	for _, metricName := range []string{
		"nyauth_security_csrf_rejections", "nyauth_oauth_grants", "nyauth_oauth_refresh_token_reuse",
		"nyauth_provider_events", "nyauth_jwk_rotations", "nyauth_rate_limit_events",
		"nyauth_registration_outcomes", "nyauth_registration_verification_duration",
		"nyauth_smtp_outbox_deliveries", "nyauth_smtp_outbox_retries", "nyauth_smtp_outbox_failures",
		"nyauth_smtp_outbox_backlog", "nyauth_smtp_outbox_oldest_pending_age", "nyauth_smtp_circuit_open",
	} {
		if !strings.Contains(body, metricName) {
			t.Fatalf("expected metric %q was not exported:\n%s", metricName, body)
		}
	}
	for _, secret := range []string{"token-for-user-123", "refresh-token-secret", "provider-name-123", "user-id-123", "upstream-secret", "ip-address", "private-registration-reason", "smtp-host-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("unbounded or sensitive metric label %q was exported:\n%s", secret, body)
		}
	}
	if !strings.Contains(body, `reason="other"`) || !strings.Contains(body, `grant_type="unsupported"`) ||
		!strings.Contains(body, `rate_limit_action="register"`) || !strings.Contains(body, `smtp_error_category="unknown"`) ||
		!metricHasValue(body, "nyauth_smtp_circuit_open", "1") {
		t.Fatalf("unexpected bounded labels:\n%s", body)
	}
}

func TestPoolObserversExportOnlyBoundedConnectionStates(t *testing.T) {
	runtime, err := New(context.Background(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })

	databaseConfig, err := pgxpool.ParseConfig("postgres://nyauth:password@127.0.0.1:1/nyauth?connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	databaseConfig.MinConns = 0
	db, err := pgxpool.NewWithConfig(t.Context(), databaseConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	t.Cleanup(func() { _ = rdb.Close() })

	if err := runtime.BindPoolObservers(db, rdb); err != nil {
		t.Fatal(err)
	}
	body := scrapeMetrics(t, runtime)
	if !strings.Contains(body, "nyauth_postgresql_pool_connections") || !strings.Contains(body, "nyauth_redis_pool_connections") {
		t.Fatalf("pool metrics were not exported:\n%s", body)
	}
	for _, state := range []string{`state="total"`, `state="idle"`} {
		if !strings.Contains(body, state) {
			t.Fatalf("expected bounded pool state %s:\n%s", state, body)
		}
	}
}

func scrapeMetrics(t *testing.T, runtime *Runtime) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	runtime.PrometheusHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics status = %d", recorder.Code)
	}
	return recorder.Body.String()
}

func metricHasValue(body, name, value string) bool {
	for _, line := range strings.Split(body, "\n") {
		if (strings.HasPrefix(line, name+"{") || strings.HasPrefix(line, name+" ")) && strings.HasSuffix(line, " "+value) {
			return true
		}
	}
	return false
}
