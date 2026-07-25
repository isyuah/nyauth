package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/redis/go-redis/v9"
)

func TestValidatePKCES256RFC7636(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !validatePKCE(verifier, challenge, "S256") {
		t.Fatal("RFC 7636 S256 vector was rejected")
	}
	for _, method := range []string{"", "plain", "s256"} {
		if validatePKCE(verifier, challenge, method) {
			t.Fatalf("method %q must be rejected", method)
		}
	}
	if validatePKCE(verifier+"x", challenge, "S256") {
		t.Fatal("incorrect verifier was accepted")
	}
}

func TestIDTokenUserInfoIsLimitedByGrantedScopes(t *testing.T) {
	all := map[string]interface{}{
		"preferred_username": "alice", "name": "Alice", "picture": "https://example/avatar",
		"email": "alice@example.com", "email_verified": true, "role": "admin",
	}
	openidOnly := scopedIDTokenUserInfo([]string{"openid"}, all)
	if len(openidOnly) != 0 {
		t.Fatalf("openid-only claims leaked user info: %#v", openidOnly)
	}
	profile := scopedIDTokenUserInfo([]string{"openid", "profile"}, all)
	if profile["preferred_username"] != "alice" || profile["name"] != "Alice" || profile["picture"] == nil {
		t.Fatalf("profile claims missing: %#v", profile)
	}
	if _, ok := profile["email"]; ok {
		t.Fatalf("profile scope leaked email: %#v", profile)
	}
	email := scopedIDTokenUserInfo([]string{"openid", "email"}, all)
	if email["email"] != "alice@example.com" || len(email) != 1 {
		t.Fatalf("email claims were not minimized: %#v", email)
	}
	if _, ok := email["email_verified"]; ok {
		t.Fatalf("unpersisted verification state was asserted: %#v", email)
	}
}

func TestRefreshRejectsRemovedScopesBeforeRotation(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "client", UserID: "client", Scopes: []string{"openid", "offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := &TokenService{session: store, refreshTTL: time.Hour}
	if _, err := service.RefreshToken(ctx, "refresh", "client", []string{"openid"}); err == nil {
		t.Fatal("refresh token retained a removed scope")
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err == nil {
		t.Fatal("scope-invalid refresh family was not revoked")
	}
}

func TestRefreshWrongClientDoesNotMutateToken(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "owner", UserID: "owner", Scopes: []string{"offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := &TokenService{session: store, refreshTTL: time.Hour}
	if _, err := service.RefreshToken(ctx, "refresh", "attacker", []string{"offline_access"}); !errors.Is(err, ErrClientMismatch) {
		t.Fatalf("wrong-client refresh error = %v", err)
	}
	if _, err := store.GetRefreshToken(ctx, "refresh"); err != nil {
		t.Fatalf("wrong-client attempt mutated token: %v", err)
	}
}

func TestConfidentialIntrospectionSupportsOwnedRefreshTokens(t *testing.T) {
	mini := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := session.NewStore(client)
	ctx := context.Background()
	data := &session.TokenData{ClientID: "owner", UserID: "owner", Scopes: []string{"offline_access"}, TokenUse: "refresh"}
	if err := store.SaveRefreshToken(ctx, "refresh", data, time.Hour); err != nil {
		t.Fatal(err)
	}
	service := &TokenService{session: store}
	owned, err := service.IntrospectTokenForClient(ctx, "refresh", "owner", []string{"offline_access"})
	if err != nil || owned["active"] != true || owned["token_type"] != "refresh_token" {
		t.Fatalf("owned refresh introspection = %#v, err=%v", owned, err)
	}
	crossClient, err := service.IntrospectTokenForClient(ctx, "refresh", "attacker", []string{"offline_access"})
	if err != nil || crossClient["active"] != false {
		t.Fatalf("cross-client refresh introspection = %#v, err=%v", crossClient, err)
	}
}

func TestPKCEVerifierBoundsAndAlphabet(t *testing.T) {
	valid := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(valid))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	if !validPKCEVerifier(valid) || !validPKCEChallenge(challenge) {
		t.Fatal("valid PKCE inputs rejected")
	}
	for _, verifier := range []string{strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 42) + "/"} {
		if validPKCEVerifier(verifier) {
			t.Fatalf("invalid verifier accepted: %q", verifier)
		}
	}
}

func TestParseAndValidateScopes(t *testing.T) {
	scopes, err := parseAndValidateScopes("email openid", []string{"openid", "profile", "email"})
	if err != nil || strings.Join(scopes, " ") != "email openid" {
		t.Fatalf("unexpected scopes %v, err=%v", scopes, err)
	}
	for _, raw := range []string{"openid admin", "openid openid"} {
		if _, err := parseAndValidateScopes(raw, []string{"openid"}); err == nil {
			t.Fatalf("invalid scope request %q accepted", raw)
		}
	}
}

func TestAddQueryPreservesExistingParameters(t *testing.T) {
	got, err := addQuery("https://client.example/cb?tenant=one", map[string]string{"code": "a+b&c", "state": "x y"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://client.example/cb?code=a%2Bb%26c&state=x+y&tenant=one" {
		t.Fatalf("unexpected redirect URL: %s", got)
	}
}

func TestDiscoveryAdvertisesOnlySupportedFlows(t *testing.T) {
	handler := &Handler{config: &config.Config{Auth: config.AuthConfig{Issuer: "https://issuer.example"}}}
	recorder := httptest.NewRecorder()
	handler.Discovery(recorder, httptest.NewRequest("GET", "/.well-known/openid-configuration", nil))
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	responses := body["response_types_supported"].([]interface{})
	if len(responses) != 1 || responses[0] != "code" {
		t.Fatalf("unexpected response types: %v", responses)
	}
	methods := body["code_challenge_methods_supported"].([]interface{})
	if len(methods) != 1 || methods[0] != "S256" {
		t.Fatalf("unexpected PKCE methods: %v", methods)
	}
}

func TestJWKVerificationRetentionUsesSignedTokenTTL(t *testing.T) {
	manager := NewJWKManager(nil, 2048, 24*time.Hour)
	masterKey := make([]byte, 32)
	if err := manager.Configure(masterKey, time.Hour); err != nil {
		t.Fatal(err)
	}
	if manager.verificationRetention != time.Hour+defaultClockSkew {
		t.Fatalf("verification retention = %v, want %v", manager.verificationRetention, time.Hour+defaultClockSkew)
	}
}

func TestEndSessionWithoutHintDoesNotDeleteAmbientSession(t *testing.T) {
	handler := &Handler{config: &config.Config{}}
	request := httptest.NewRequest("GET", "/end_session", nil)
	request.AddCookie(&http.Cookie{Name: oauthSessionCookie, Value: "ambient-session"})
	recorder := httptest.NewRecorder()
	handler.EndSession(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Set-Cookie"); got != "" {
		t.Fatalf("hint-less GET cleared session cookie: %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Fatalf("Referrer-Policy = %q", got)
	}

	redirectRequest := httptest.NewRequest("GET", "/end_session?post_logout_redirect_uri=https%3A%2F%2Fclient.example%2Flogout", nil)
	redirectRequest.AddCookie(&http.Cookie{Name: oauthSessionCookie, Value: "ambient-session"})
	redirectRecorder := httptest.NewRecorder()
	handler.EndSession(redirectRecorder, redirectRequest)
	if redirectRecorder.Code != http.StatusBadRequest || redirectRecorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("hint-less redirect status=%d set-cookie=%q", redirectRecorder.Code, redirectRecorder.Header().Get("Set-Cookie"))
	}
}

func TestUserInfoResponsesDisableCaching(t *testing.T) {
	t.Parallel()
	handler := &Handler{tokenService: &TokenService{}}
	request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	recorder := httptest.NewRecorder()
	handler.UserInfo(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusUnauthorized)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := recorder.Header().Get("Pragma"); got != "no-cache" {
		t.Fatalf("Pragma = %q", got)
	}
}

func TestValidateEndSessionSessionFailsClosedOnStoreErrors(t *testing.T) {
	t.Parallel()
	subject := "user-id"
	if err := validateEndSessionSession(nil, session.ErrNotFound, subject); err != nil {
		t.Fatalf("stale session cookie was rejected: %v", err)
	}
	if err := validateEndSessionSession(&session.SessionData{UserID: subject}, nil, subject); err != nil {
		t.Fatalf("matching session was rejected: %v", err)
	}
	if err := validateEndSessionSession(&session.SessionData{UserID: "other-user"}, nil, subject); !errors.Is(err, errEndSessionSubjectMismatch) {
		t.Fatalf("subject mismatch error = %v", err)
	}
	storeErr := errors.New("redis unavailable")
	if err := validateEndSessionSession(nil, storeErr, subject); !errors.Is(err, storeErr) {
		t.Fatalf("store error = %v, want %v", err, storeErr)
	}
}

func TestOAuthFormBodyLimit(t *testing.T) {
	payload := "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)
	request := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	err := parseOAuthForm(recorder, request)
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) {
		t.Fatalf("oversized OAuth form error = %v, want *http.MaxBytesError", err)
	}
	if tooLarge.Limit != maxOAuthFormBodyBytes {
		t.Fatalf("body limit = %d, want %d", tooLarge.Limit, maxOAuthFormBodyBytes)
	}
}

func TestOAuthFormEndpointsRejectOversizedBodies(t *testing.T) {
	handler := &Handler{}
	payload := "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)
	tests := []struct {
		name       string
		handle     func(http.ResponseWriter, *http.Request)
		wantStatus int
	}{
		{name: "token", handle: handler.Token, wantStatus: http.StatusBadRequest},
		{name: "revoke", handle: handler.Revoke, wantStatus: http.StatusBadRequest},
		{name: "introspect", handle: handler.Introspect, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/"+test.name, strings.NewReader(payload))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			test.handle(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, test.wantStatus)
			}
		})
	}
}

func TestTokenAndIntrospectionResponsesDisableCaching(t *testing.T) {
	handler := &Handler{}
	tests := []struct {
		name   string
		handle func(http.ResponseWriter, *http.Request)
		body   string
	}{
		{name: "token", handle: handler.Token, body: "grant_type=unsupported"},
		{name: "introspect", handle: handler.Introspect, body: "token=" + strings.Repeat("x", int(maxOAuthFormBodyBytes)+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/"+test.name, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			recorder := httptest.NewRecorder()
			test.handle(recorder, request)
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if got := recorder.Header().Get("Pragma"); got != "no-cache" {
				t.Fatalf("Pragma = %q", got)
			}
		})
	}
}
