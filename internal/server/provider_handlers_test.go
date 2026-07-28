package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/servicecontrol"
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

func TestSafeReturnPathRejectsCrossOriginAndAmbiguousPaths(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "/profile/security?from=provider#passkeys", want: "/profile/security?from=provider#passkeys"},
		{value: "https://evil.example/path", want: "/profile"},
		{value: "//evil.example/path", want: "/profile"},
		{value: `/\\evil.example/path`, want: "/profile"},
		{value: "/profile\nadmin", want: "/profile"},
		{value: "/%2f%2fevil.example", want: "/%2f%2fevil.example"},
	} {
		if got := safeReturnPath(test.value, "/profile"); got != test.want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", test.value, got, test.want)
		}
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

func TestProviderCallbackCapabilityDependsOnIntent(t *testing.T) {
	for _, test := range []struct {
		name         string
		intent       string
		wantError    string
		wantAcquired servicecontrol.Capability
		wantAcquireN int
	}{
		{name: "login is issuance controlled", intent: "login", wantError: "service_paused", wantAcquired: servicecontrol.CapabilityAuthIssuance, wantAcquireN: 1},
		{name: "reauth is exempt", intent: "reauth", wantError: "missing_code", wantAcquireN: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			mini := miniredis.RunT(t)
			rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
			t.Cleanup(func() { _ = rdb.Close() })
			stateStore := session.NewStore(rdb)
			state := "state-" + test.intent
			flowSecret := "flow-" + test.intent
			if err := stateStore.SaveCSRFState(context.Background(), state, map[string]string{
				"provider": "test", "intent": test.intent, "return_to": "/profile",
				"flow_digest": providerSessionDigest(flowSecret),
			}, time.Minute); err != nil {
				t.Fatal(err)
			}
			runtime := &fakeServiceControlRuntime{acquireErr: &servicecontrol.PausedError{
				Capabilities: []servicecontrol.Capability{servicecontrol.CapabilityAuthIssuance},
				RetryAfter:   time.Minute,
			}}
			server := &Server{cfg: &config.Config{}, sessionStore: stateStore, serviceControl: runtime}
			router := chi.NewRouter()
			router.Get("/auth/{provider}/callback", server.handleProviderCallback)
			request := httptest.NewRequest(http.MethodGet, "/auth/test/callback?state="+state, nil)
			request.AddCookie(&http.Cookie{Name: providerFlowCookie, Value: flowSecret})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusFound || !strings.Contains(response.Header().Get("Location"), "auth_error="+test.wantError) {
				t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
			}
			if len(runtime.acquired) != test.wantAcquireN {
				t.Fatalf("acquired=%v, want count %d", runtime.acquired, test.wantAcquireN)
			}
			if test.wantAcquireN == 1 && runtime.acquired[0][0] != test.wantAcquired {
				t.Fatalf("acquired=%v, want %s", runtime.acquired, test.wantAcquired)
			}
		})
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
	displayName := "Company SSO"
	if emptyProviderUpdate(models.UpdateProviderRequest{DisplayName: &displayName}) {
		t.Fatal("a display-name update was mistaken for an empty update")
	}
}

func TestValidateProviderRequestRequiresExplicitEnabled(t *testing.T) {
	t.Parallel()
	request := models.CreateProviderRequest{
		Name: "github", Type: "github", ClientID: "client", ClientSecret: "secret",
	}
	if err := validateProviderRequest(request); err == nil {
		t.Fatal("provider creation accepted a missing enabled state")
	}
	enabled := false
	request.Enabled = &enabled
	if err := validateProviderRequest(request); err != nil {
		t.Fatalf("provider creation rejected explicit enabled=false: %v", err)
	}
}
