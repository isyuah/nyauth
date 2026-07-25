package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestProviderSessionDigestBindsExactSession(t *testing.T) {
	t.Parallel()
	first := providerSessionDigest("session-one")
	if first == "" || first != providerSessionDigest("session-one") {
		t.Fatal("session digest is empty or unstable")
	}
	if first == providerSessionDigest("session-two") {
		t.Fatal("different sessions produced the same digest")
	}
}

func TestProviderFlowCookieBindsInitiatingBrowser(t *testing.T) {
	t.Parallel()
	digest := providerSessionDigest("browser-a-secret")
	if !validProviderFlowCookie("browser-a-secret", digest) {
		t.Fatal("initiating browser flow cookie was rejected")
	}
	if validProviderFlowCookie("browser-b-secret", digest) {
		t.Fatal("another browser flow cookie was accepted")
	}
}

func TestProviderCallbackFromWrongBrowserDoesNotCreateSession(t *testing.T) {
	t.Parallel()
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	stateStore := session.NewStore(rdb)
	if err := stateStore.SaveCSRFState(context.Background(), "state-value", map[string]string{
		"provider": "test", "intent": "login", "return_to": "/dashboard",
		"flow_digest": providerSessionDigest("browser-a-secret"),
	}, time.Minute); err != nil {
		t.Fatal(err)
	}
	server := &Server{cfg: &config.Config{}, sessionStore: stateStore}
	router := chi.NewRouter()
	router.Get("/auth/{provider}/callback", server.handleProviderCallback)
	request := httptest.NewRequest(http.MethodGet, "/auth/test/callback?state=state-value&code=code", nil)
	request.AddCookie(&http.Cookie{Name: providerFlowCookie, Value: "browser-b-secret"})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			t.Fatalf("wrong browser received a first-party session cookie: %#v", cookie)
		}
	}
	cleared := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == providerFlowCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("provider flow cookie was not cleared on callback")
	}
}

func TestEmptyProviderUpdate(t *testing.T) {
	t.Parallel()
	if !emptyProviderUpdate(models.UpdateProviderRequest{}) {
		t.Fatal("empty provider update was accepted")
	}
	enabled := false
	if emptyProviderUpdate(models.UpdateProviderRequest{Enabled: &enabled}) {
		t.Fatal("enabled=false was mistaken for an empty update")
	}
	emptyScopes := []string{}
	if emptyProviderUpdate(models.UpdateProviderRequest{Scopes: emptyScopes}) {
		t.Fatal("an explicit empty scope list was mistaken for an empty update")
	}
}
