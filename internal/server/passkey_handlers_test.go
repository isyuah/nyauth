package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	nyacrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestBeginPasskeyLoginOptionsEnforceOriginAndReturnSecureContract(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)

	crossOrigin := registrationHTTPRequest(
		testApp.app, http.MethodPost, "/api/login/passkey/options", `{"conditional":true}`,
		"https://attacker.example", "192.0.2.50:42000",
	)
	if crossOrigin.Code != http.StatusForbidden || !bytes.Contains(crossOrigin.Body.Bytes(), []byte(`"error":"invalid request origin"`)) {
		t.Fatalf("cross-origin options=%d body=%s", crossOrigin.Code, crossOrigin.Body.String())
	}

	response := mfaHTTPRequest(
		testApp.app, http.MethodPost, "/api/login/passkey/options",
		`{"conditional":true,"return_to":"https://attacker.example/phish"}`, "", "",
	)
	if response.Code != http.StatusOK {
		t.Fatalf("begin Passkey login=%d body=%s", response.Code, response.Body.String())
	}
	var options struct {
		CeremonyID string         `json:"ceremony_id"`
		PublicKey  map[string]any `json:"public_key"`
		Mediation  string         `json:"mediation"`
		ExpiresAt  string         `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode Passkey options: %v", err)
	}
	if options.CeremonyID == "" || options.ExpiresAt == "" || options.Mediation != "conditional" {
		t.Fatalf("Passkey options envelope=%#v", options)
	}
	if options.PublicKey["rpId"] != "auth.example.test" || options.PublicKey["userVerification"] != "required" {
		t.Fatalf("public-key request options=%#v", options.PublicKey)
	}
	stored, err := testApp.app.sessionStore.GetWebAuthnCeremony(context.Background(), options.CeremonyID)
	if err != nil {
		t.Fatalf("load stored WebAuthn ceremony: %v", err)
	}
	if stored.Purpose != passkeyPurposeLogin || stored.ReturnTo != "/dashboard" {
		t.Fatalf("stored ceremony=%#v", stored)
	}
}

func TestBeginPasskeyLoginOptionsRateLimitAndHideInfrastructureErrors(t *testing.T) {
	t.Run("rate limit", func(t *testing.T) {
		testApp := newRegistrationHTTPTestApp(t)
		testApp.app.loginLimiter.ceremonyLimitTestOverride = 1
		first := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/passkey/options", `{"conditional":false}`, "", "")
		if first.Code != http.StatusOK {
			t.Fatalf("first options request=%d body=%s", first.Code, first.Body.String())
		}
		limited := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/passkey/options", `{"conditional":false}`, "", "")
		if limited.Code != http.StatusTooManyRequests || limited.Header().Get("Retry-After") == "" {
			t.Fatalf("limited options request=%d retry=%q body=%s", limited.Code, limited.Header().Get("Retry-After"), limited.Body.String())
		}
		if !bytes.Contains(limited.Body.Bytes(), []byte(`"error":"too many Passkey ceremonies"`)) {
			t.Fatalf("limited response leaked an unexpected contract: %s", limited.Body.String())
		}
	})

	t.Run("Redis unavailable", func(t *testing.T) {
		testApp := newRegistrationHTTPTestApp(t)
		testApp.mini.Close()
		response := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/login/passkey/options", `{"conditional":false}`, "", "")
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("Redis failure status=%d body=%s", response.Code, response.Body.String())
		}
		var failure struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil ||
			failure.Error != "Passkey ceremony temporarily unavailable" || failure.Code != "passkey.ceremony_unavailable" {
			t.Fatalf("Redis failure was not mapped to the generic API contract: body=%s err=%v", response.Body.String(), err)
		}
	})
}

func TestPasskeyRegistrationRequiresAuthenticatedCSRFAndRecentAuthentication(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	const password = "passkey handler password"
	passwordHash, err := nyacrypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	current := &models.User{
		ID: uuid.New(), Username: "passkey-handler-user", PasswordHash: &passwordHash,
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(context.Background(), current); err != nil {
		t.Fatalf("create Passkey handler user: %v", err)
	}
	login := mfaHTTPRequest(
		testApp.app, http.MethodPost, "/api/login",
		`{"username":"passkey-handler-user","password":"passkey handler password"}`, "", "",
	)
	if login.Code != http.StatusOK {
		t.Fatalf("login=%d body=%s", login.Code, login.Body.String())
	}
	var authenticated models.SessionResponse
	if err := json.Unmarshal(login.Body.Bytes(), &authenticated); err != nil {
		t.Fatalf("decode login session: %v", err)
	}
	cookie := responseCookie(t, login, sessionCookieName)
	cookieHeader := cookie.Name + "=" + cookie.Value

	missingCSRF := mfaHTTPRequest(
		testApp.app, http.MethodPost, "/api/me/passkeys/registration/options",
		`{"name":"Windows Hello"}`, cookieHeader, "",
	)
	if missingCSRF.Code != http.StatusForbidden || !bytes.Contains(missingCSRF.Body.Bytes(), []byte(`"error":"invalid CSRF token"`)) {
		t.Fatalf("missing CSRF=%d body=%s", missingCSRF.Code, missingCSRF.Body.String())
	}

	valid := mfaHTTPRequest(
		testApp.app, http.MethodPost, "/api/me/passkeys/registration/options",
		`{"name":"Windows Hello"}`, cookieHeader, authenticated.CSRFToken,
	)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid registration options=%d body=%s", valid.Code, valid.Body.String())
	}
	var options webAuthnOptionsResponse
	if err := json.Unmarshal(valid.Body.Bytes(), &options); err != nil {
		t.Fatalf("decode registration options: %v", err)
	}
	if options.CeremonyID == "" || options.ExpiresAt.IsZero() {
		t.Fatalf("registration options=%#v", options)
	}

	storedSession, err := testApp.app.sessionStore.GetSession(context.Background(), cookie.Value)
	if err != nil {
		t.Fatalf("load registration session: %v", err)
	}
	storedSession.AuthenticatedAt = time.Now().UTC().Add(-11 * time.Minute)
	if err := testApp.app.sessionStore.SaveSession(context.Background(), cookie.Value, storedSession, sessionTTL); err != nil {
		t.Fatalf("expire recent authentication: %v", err)
	}
	finishRequest := httptest.NewRequest(
		http.MethodPost, "/api/me/passkeys/registration/verify", strings.NewReader(`{}`),
	)
	finishRequest.Header.Set("Origin", "https://auth.example.test")
	finishRequest.Header.Set("Content-Type", "application/json")
	finishRequest.Header.Set("Cookie", cookieHeader)
	finishRequest.Header.Set("X-CSRF-Token", authenticated.CSRFToken)
	finishRequest.Header.Set(webAuthnCeremonyHeader, options.CeremonyID)
	finish := httptest.NewRecorder()
	testApp.app.router.ServeHTTP(finish, finishRequest)
	if finish.Code != http.StatusForbidden || !bytes.Contains(finish.Body.Bytes(), []byte(`"error":"recent authentication is required"`)) {
		t.Fatalf("expired recent authentication=%d body=%s", finish.Code, finish.Body.String())
	}
	if _, err := testApp.app.sessionStore.GetWebAuthnCeremony(context.Background(), options.CeremonyID); err != nil {
		t.Fatalf("recent-authentication rejection consumed registration ceremony: %v", err)
	}

	invalidJSONRequest := httptest.NewRequest(
		http.MethodPost, "/api/login/passkey/options", strings.NewReader(`{"conditional":`),
	)
	invalidJSONRequest.Header.Set("Origin", "https://auth.example.test")
	invalidJSONRequest.Header.Set("Content-Type", "application/json")
	invalidJSONRequest.RemoteAddr = "192.0.2.51:42000"
	invalidJSON := httptest.NewRecorder()
	testApp.app.router.ServeHTTP(invalidJSON, invalidJSONRequest)
	if invalidJSON.Code != http.StatusBadRequest || !bytes.Contains(invalidJSON.Body.Bytes(), []byte(`"error":"invalid request body"`)) {
		t.Fatalf("invalid options JSON=%d body=%s", invalidJSON.Code, invalidJSON.Body.String())
	}
}
