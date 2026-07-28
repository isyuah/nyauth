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
	"github.com/nyasharp/nyauth/pkg/models"
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
	if !strings.Contains(response.Body.String(), `"code":"security.csrf_validation_failed"`) {
		t.Fatalf("CSRF response lacks stable error code: %s", response.Body.String())
	}
	metrics := httptest.NewRecorder()
	runtime.PrometheusHandler().ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if body := metrics.Body.String(); !strings.Contains(body, "nyauth_security_csrf_rejections") || !strings.Contains(body, `reason="missing_session"`) {
		t.Fatalf("CSRF rejection metric was not exported:\n%s", body)
	}
}

func TestRequireCurrentPasswordChangeReturnsStableErrorCode(t *testing.T) {
	server := &Server{}
	handler := server.requireCurrentPasswordChange(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("password-change-gated handler must not run")
	}))
	request := httptest.NewRequest(http.MethodPost, "/api/me/email/change", nil)
	request = request.WithContext(context.WithValue(request.Context(), currentUserContextKey, &models.User{MustChangePassword: true}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), `"code":"account.password_change_required"`) {
		t.Fatalf("password-change response = %d %s", response.Code, response.Body.String())
	}
}

func TestResolveClientIPTrustedProxyChain(t *testing.T) {
	server := &Server{trustedProxies: parseTrustedProxyCIDRs([]string{"10.0.0.0/8", "192.0.2.0/24"})}
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xRealIP    string
		want       string
	}{
		{name: "untrusted peer ignores headers", remoteAddr: "203.0.113.9:443", xff: "198.51.100.4", want: "203.0.113.9"},
		{name: "trusted chain returns first untrusted hop", remoteAddr: "10.0.0.2:8080", xff: "198.51.100.4, 192.0.2.8", want: "198.51.100.4"},
		{name: "forwarded ipv4 port is accepted", remoteAddr: "10.0.0.2:8080", xff: "198.51.100.4:443", want: "198.51.100.4"},
		{name: "forwarded bracketed ipv6 port is accepted", remoteAddr: "10.0.0.2:8080", xff: "[2001:db8::8]:443", want: "2001:db8::8"},
		{name: "malformed chain fails closed to peer", remoteAddr: "10.0.0.2:8080", xff: "198.51.100.4, malformed", want: "10.0.0.2"},
		{name: "x real ip fallback", remoteAddr: "10.0.0.2:8080", xRealIP: "198.51.100.7", want: "198.51.100.7"},
		{name: "malformed real ip keeps peer", remoteAddr: "10.0.0.2:8080", xRealIP: "malformed", want: "10.0.0.2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest("GET", "https://auth.example.test/", nil)
			request.RemoteAddr = test.remoteAddr
			request.Header.Set("X-Forwarded-For", test.xff)
			request.Header.Set("X-Real-IP", test.xRealIP)
			if got := server.resolveClientIP(request); got != test.want {
				t.Fatalf("resolveClientIP() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	recorder := httptest.NewRecorder()
	securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
		"Permissions-Policy":     "camera=(), geolocation=(), microphone=()",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}
