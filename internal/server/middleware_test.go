package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

func TestUserAuthMiddlewareDistinguishesMissingAndExpiredSessions(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	server := &Server{sessionMiddleware: NewSessionMiddleware(session.NewStore(rdb), false)}
	handler := server.userAuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("authenticated handler must not run")
	}))

	t.Run("missing cookie", func(t *testing.T) {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/session", nil))
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "authentication required") {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
		if response.Header().Get("Set-Cookie") != "" {
			t.Fatal("missing session unexpectedly cleared a cookie")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodGet, "/api/session", nil)
		request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "expired-session"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "session expired") {
			t.Fatalf("response = %d %s", response.Code, response.Body.String())
		}
		if !strings.Contains(response.Header().Get("Set-Cookie"), "Max-Age=0") {
			t.Fatalf("expired session cookie was not cleared: %q", response.Header().Get("Set-Cookie"))
		}
	})
}

func TestUserAuthMiddlewarePreservesCookieWhenRedisIsUnavailable(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{
		Addr: "127.0.0.1:1", MaxRetries: -1,
		DialTimeout: 50 * time.Millisecond, ReadTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() { _ = rdb.Close() })
	server := &Server{sessionMiddleware: NewSessionMiddleware(session.NewStore(rdb), false)}
	handler := server.userAuthMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("authenticated handler must not run")
	}))
	request := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "existing-session"})
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "session service unavailable") {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("Set-Cookie") != "" {
		t.Fatalf("temporary Redis failure cleared the session cookie: %q", response.Header().Get("Set-Cookie"))
	}
}

func TestCSRFMiddlewareRecordsBoundedRejectionReason(t *testing.T) {
	runtime, err := telemetry.New(context.Background(), telemetry.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Shutdown(t.Context()) })
	server := &Server{telemetry: runtime}
	handler := server.csrfMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("CSRF-rejected handler must not run")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/me", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	metrics := httptest.NewRecorder()
	runtime.PrometheusHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := metrics.Body.String(); !strings.Contains(body, "nyauth_security_csrf_rejections") || !strings.Contains(body, `reason="missing_session"`) {
		t.Fatalf("CSRF rejection metric was not exported:\n%s", body)
	}
}
