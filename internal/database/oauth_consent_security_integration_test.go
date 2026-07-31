package database_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/auth"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/database"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

const (
	oauthConsentClientID    = "oauth-consent-security-client"
	oauthConsentRedirectURI = "https://client.example/callback"
	oauthSessionCookieName  = "nyauth_session"
)

type oauthConsentSecurityFixture struct {
	authorizeHandler *auth.Handler
	consentHandler   *auth.ConsentHandler
	tokenService     *auth.TokenService
	sessions         *session.Store
}

func TestOAuthAuthorizeAndConsentSecuritySemantics(t *testing.T) {
	schema := newPostgresTestSchema(t)
	if err := database.RunMigrations(schema.migrationDSN); err != nil {
		t.Fatalf("RunMigrations: %v", err)
	}

	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	clientStore := client.NewStore(schema.pool)
	if err := clientStore.Create(context.Background(), &models.OAuthClient{
		ID:                     oauthConsentClientID,
		Name:                   "OAuth consent security integration client",
		RedirectURIs:           []string{oauthConsentRedirectURI},
		PostLogoutRedirectURIs: []string{},
		Grants:                 []string{models.GrantAuthorizationCode},
		Scopes:                 []string{"openid", "profile"},
		AllowedClaims:          []string{"sub", "preferred_username", "name", "picture"},
		IsPublic:               true,
		AccessPolicy:           models.ClientAccessOpen,
		Metadata:               map[string]string{},
	}); err != nil {
		t.Fatalf("create OAuth client: %v", err)
	}

	cfg := &config.Config{Auth: config.AuthConfig{
		Issuer:               "https://issuer.example",
		MasterKey:            []byte("0123456789abcdef0123456789abcdef"),
		AccessTokenTTL:       time.Hour,
		RefreshTokenTTL:      24 * time.Hour,
		AuthorizationCodeTTL: 5 * time.Minute,
	}}
	sessionStore := session.NewStore(rdb)
	jwkManager := auth.NewJWKManager(schema.pool, 2048, 24*time.Hour)
	if err := jwkManager.Configure(cfg.Auth.MasterKey, cfg.Auth.RefreshTokenTTL); err != nil {
		t.Fatalf("configure JWK manager: %v", err)
	}
	if err := jwkManager.EnsureActiveKey(context.Background()); err != nil {
		t.Fatalf("ensure active JWK: %v", err)
	}
	userService := user.NewService(user.NewStore(schema.pool))
	tokenService := auth.NewTokenService(jwkManager, sessionStore, cfg.Auth.Issuer, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)
	tokenService.SetUserService(userService)
	fixture := &oauthConsentSecurityFixture{
		authorizeHandler: auth.NewHandler(tokenService, jwkManager, userService, clientStore, sessionStore, cfg),
		consentHandler:   auth.NewConsentHandler(sessionStore, tokenService, clientStore, authorization.NewStore(schema.pool), cfg),
		tokenService:     tokenService,
		sessions:         sessionStore,
	}

	t.Run("authorize validates client and redirect before redirecting errors", func(t *testing.T) {
		attackerURI := "https://attacker.example/callback"
		requests := []struct {
			name  string
			query url.Values
		}{
			{
				name: "unknown client",
				query: url.Values{
					"client_id":             {"unknown-client"},
					"redirect_uri":          {attackerURI},
					"response_type":         {"code"},
					"scope":                 {"not-allowed"},
					"state":                 {"unknown-client-state"},
					"code_challenge_method": {"plain"},
				},
			},
			{
				name: "registered client with mismatched redirect",
				query: url.Values{
					"client_id":             {oauthConsentClientID},
					"redirect_uri":          {attackerURI},
					"response_type":         {"code"},
					"scope":                 {"not-allowed"},
					"state":                 {"mismatched-redirect-state"},
					"code_challenge_method": {"plain"},
				},
			},
		}

		for _, testCase := range requests {
			t.Run(testCase.name, func(t *testing.T) {
				recorder := fixture.authorize(testCase.query)
				if recorder.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
				}
				if location := recorder.Header().Get("Location"); location != "" {
					t.Fatalf("unverified redirect was used: %q", location)
				}
				body := decodeOAuthSecurityJSON(t, recorder)
				if body["error"] != "invalid_request" {
					t.Fatalf("error = %#v, want invalid_request; body=%s", body["error"], recorder.Body.String())
				}
			})
		}
	})

	t.Run("authorize redirects protocol errors only after redirect validation", func(t *testing.T) {
		validChallenge := strings.Repeat("A", 43)

		t.Run("invalid scope preserves state on registered redirect", func(t *testing.T) {
			recorder := fixture.authorize(url.Values{
				"client_id":             {oauthConsentClientID},
				"redirect_uri":          {oauthConsentRedirectURI},
				"response_type":         {"code"},
				"scope":                 {"profile not-allowed"},
				"state":                 {"scope-state"},
				"code_challenge":        {validChallenge},
				"code_challenge_method": {"S256"},
			})
			assertOAuthSecurityRedirect(t, recorder, "invalid_scope", "scope-state")
		})

		pkceCases := []struct {
			name      string
			challenge string
			method    string
		}{
			{name: "missing PKCE", challenge: "", method: ""},
			{name: "non S256 PKCE", challenge: validChallenge, method: "plain"},
			{name: "malformed S256 challenge", challenge: "too-short", method: "S256"},
		}
		for _, testCase := range pkceCases {
			t.Run(testCase.name, func(t *testing.T) {
				state := "pkce-" + strings.ReplaceAll(testCase.name, " ", "-")
				recorder := fixture.authorize(url.Values{
					"client_id":             {oauthConsentClientID},
					"redirect_uri":          {oauthConsentRedirectURI},
					"response_type":         {"code"},
					"scope":                 {"profile"},
					"state":                 {state},
					"code_challenge":        {testCase.challenge},
					"code_challenge_method": {testCase.method},
				})
				assertOAuthSecurityRedirect(t, recorder, "invalid_request", state)
			})
		}
	})

	t.Run("deny consent consumes a matching challenge exactly once", func(t *testing.T) {
		userID := uuid.NewString()
		sessionID, csrf := fixture.saveSession(t, userID, 1)
		challenge := "deny-once-" + uuid.NewString()
		fixture.saveConsent(t, challenge, userID, 1, "deny-state")

		first := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, sessionID, csrf, challenge)
		if first.Code != http.StatusOK {
			t.Fatalf("first deny status = %d, body=%s", first.Code, first.Body.String())
		}
		redirectURL, ok := decodeOAuthSecurityJSON(t, first)["redirect_url"].(string)
		if !ok {
			t.Fatalf("deny response has no string redirect_url: %s", first.Body.String())
		}
		parsed, err := url.Parse(redirectURL)
		if err != nil {
			t.Fatalf("parse deny redirect: %v", err)
		}
		if parsed.Scheme+"://"+parsed.Host+parsed.Path != oauthConsentRedirectURI || parsed.Query().Get("error") != "access_denied" || parsed.Query().Get("state") != "deny-state" {
			t.Fatalf("unexpected deny redirect: %s", parsed.String())
		}

		second := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, sessionID, csrf, challenge)
		assertOAuthSecurityJSONError(t, second, http.StatusBadRequest, "invalid_or_expired_challenge")
		if _, err := fixture.sessions.GetConsent(context.Background(), challenge); err != session.ErrNotFound {
			t.Fatalf("consumed challenge lookup error = %v, want ErrNotFound", err)
		}
	})

	t.Run("wrong session cannot consume another users challenge", func(t *testing.T) {
		ownerID := uuid.NewString()
		attackerID := uuid.NewString()
		ownerSession, ownerCSRF := fixture.saveSession(t, ownerID, 1)
		attackerSession, attackerCSRF := fixture.saveSession(t, attackerID, 1)
		challenge := "user-binding-" + uuid.NewString()
		fixture.saveConsent(t, challenge, ownerID, 1, "owner-state")

		wrongUser := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, attackerSession, attackerCSRF, challenge)
		assertOAuthSecurityJSONError(t, wrongUser, http.StatusBadRequest, "invalid_or_expired_challenge")
		stored, err := fixture.sessions.GetConsent(context.Background(), challenge)
		if err != nil || stored.UserID != ownerID {
			t.Fatalf("wrong-user attempt changed challenge: data=%#v err=%v", stored, err)
		}

		owner := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, ownerSession, ownerCSRF, challenge)
		if owner.Code != http.StatusOK {
			t.Fatalf("owner deny status = %d, body=%s", owner.Code, owner.Body.String())
		}
		got, ok := decodeOAuthSecurityJSON(t, owner)["redirect_url"].(string)
		if !ok || !strings.Contains(got, "error=access_denied") || !strings.Contains(got, "state=owner-state") {
			t.Fatalf("owner redirect = %q", got)
		}
	})

	t.Run("accept rejects and invalidates stale auth version", func(t *testing.T) {
		userID := uuid.NewString()
		sessionID, csrf := fixture.saveSession(t, userID, 2)
		challenge := "stale-auth-version-" + uuid.NewString()
		fixture.saveConsent(t, challenge, userID, 1, "stale-state")

		response := fixture.consentMutation(t, fixture.consentHandler.AcceptConsent, sessionID, csrf, challenge)
		assertOAuthSecurityJSONError(t, response, http.StatusBadRequest, "invalid_or_expired_challenge")
		if _, err := fixture.sessions.GetConsent(context.Background(), challenge); err != session.ErrNotFound {
			t.Fatalf("stale challenge lookup error = %v, want ErrNotFound", err)
		}
		var count int
		if err := schema.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM oauth_authorizations WHERE user_id=$1`, userID).Scan(&count); err != nil {
			t.Fatalf("count stale-version authorizations: %v", err)
		}
		if count != 0 {
			t.Fatalf("stale auth version created %d authorization records", count)
		}
	})

	t.Run("csrf failure leaves challenge usable", func(t *testing.T) {
		userID := uuid.NewString()
		sessionID, csrf := fixture.saveSession(t, userID, 1)
		challenge := "csrf-retry-" + uuid.NewString()
		fixture.saveConsent(t, challenge, userID, 1, "csrf-state")

		failed := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, sessionID, "wrong-csrf", challenge)
		assertOAuthSecurityJSONError(t, failed, http.StatusForbidden, "csrf_validation_failed")
		if stored, err := fixture.sessions.GetConsent(context.Background(), challenge); err != nil || stored.State != "csrf-state" {
			t.Fatalf("CSRF failure changed challenge: data=%#v err=%v", stored, err)
		}

		retried := fixture.consentMutation(t, fixture.consentHandler.DenyConsent, sessionID, csrf, challenge)
		if retried.Code != http.StatusOK {
			t.Fatalf("correct-CSRF retry status = %d, body=%s", retried.Code, retried.Body.String())
		}
		if _, err := fixture.sessions.GetConsent(context.Background(), challenge); err != session.ErrNotFound {
			t.Fatalf("successfully retried challenge lookup error = %v, want ErrNotFound", err)
		}
	})

	t.Run("accepting selected optional scopes narrows the authorization grant", func(t *testing.T) {
		userID := uuid.New()
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO users (id,username,status,role,creation_source)
			VALUES ($1,$2,'active','user','legacy')
		`, userID, "optional-consent-"+strings.ReplaceAll(userID.String(), "-", "")); err != nil {
			t.Fatalf("insert optional consent user: %v", err)
		}
		sessionID, csrf := fixture.saveSession(t, userID.String(), 1)
		challenge := "optional-scope-" + uuid.NewString()
		if err := fixture.sessions.SaveConsent(context.Background(), challenge, &session.ConsentData{
			ClientID: oauthConsentClientID, UserID: userID.String(), RedirectURI: oauthConsentRedirectURI,
			Scopes:         []string{"email", "offline_access", "openid", "profile"},
			OptionalScopes: []string{"email", "offline_access", "profile"},
			State:          "optional-state", CodeChallenge: strings.Repeat("A", 43), ChallengeMethod: "S256",
			Nonce: "optional-nonce", AuthVersion: 1,
		}, 10*time.Minute); err != nil {
			t.Fatalf("save optional consent: %v", err)
		}

		getRequest := httptest.NewRequest(http.MethodGet, "/api/consent?challenge="+url.QueryEscape(challenge), nil)
		getRequest.AddCookie(&http.Cookie{Name: oauthSessionCookieName, Value: sessionID})
		getRecorder := httptest.NewRecorder()
		fixture.consentHandler.GetConsent(getRecorder, getRequest)
		if getRecorder.Code != http.StatusOK {
			t.Fatalf("get consent status = %d, body=%s", getRecorder.Code, getRecorder.Body.String())
		}
		if getRecorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("get consent Cache-Control = %q", getRecorder.Header().Get("Cache-Control"))
		}
		getBody := decodeOAuthSecurityJSON(t, getRecorder)
		permissions, ok := getBody["permissions"].([]any)
		if !ok || len(permissions) != 4 {
			t.Fatalf("consent permissions = %#v", getBody["permissions"])
		}
		for _, rawPermission := range permissions {
			permission, ok := rawPermission.(map[string]any)
			if !ok {
				t.Fatalf("consent permission = %#v", rawPermission)
			}
			if _, ok := permission["claims"].([]any); !ok {
				t.Fatalf("consent permission claims must be a JSON array: %#v", permission)
			}
		}
		openidPermission, ok := permissions[2].(map[string]any)
		if !ok || openidPermission["required"] != true {
			t.Fatalf("openid permission = %#v", permissions[2])
		}

		accepted := fixture.consentDecisionMutation(t, sessionID, csrf, challenge, []string{"profile"})
		if accepted.Code != http.StatusOK {
			t.Fatalf("accept status = %d, body=%s", accepted.Code, accepted.Body.String())
		}
		if accepted.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("accept consent Cache-Control = %q", accepted.Header().Get("Cache-Control"))
		}
		redirectValue, ok := decodeOAuthSecurityJSON(t, accepted)["redirect_url"].(string)
		if !ok {
			t.Fatalf("accept response has no redirect URL: %s", accepted.Body.String())
		}
		redirectURL, err := url.Parse(redirectValue)
		if err != nil {
			t.Fatalf("parse accepted redirect: %v", err)
		}
		if redirectURL.Query().Get("scope") != "openid profile" || redirectURL.Query().Get("state") != "optional-state" {
			t.Fatalf("accepted redirect query = %v", redirectURL.Query())
		}
		codeData, err := fixture.sessions.GetAuthorizationCode(context.Background(), redirectURL.Query().Get("code"))
		if err != nil {
			t.Fatalf("load authorization code: %v", err)
		}
		if strings.Join(codeData.Scopes, " ") != "openid profile" {
			t.Fatalf("authorization code scopes = %#v", codeData.Scopes)
		}
		var storedScopes, storedClaims []string
		if err := schema.pool.QueryRow(context.Background(), `
			SELECT scopes,allowed_claims FROM oauth_authorizations WHERE user_id=$1 AND client_id=$2
		`, userID, oauthConsentClientID).Scan(&storedScopes, &storedClaims); err != nil {
			t.Fatalf("load authorization record: %v", err)
		}
		if strings.Join(storedScopes, " ") != "openid profile" {
			t.Fatalf("authorization record scopes = %#v", storedScopes)
		}
		if strings.Join(storedClaims, " ") != "name picture preferred_username sub" {
			t.Fatalf("authorization record claims = %#v", storedClaims)
		}
	})

	t.Run("userinfo rejects user tokens without the sub claim", func(t *testing.T) {
		userID := uuid.New()
		if _, err := schema.pool.Exec(context.Background(), `
			INSERT INTO users (id,username,status,role,creation_source)
			VALUES ($1,$2,'active','user','legacy')
		`, userID, "userinfo-no-openid-"+strings.ReplaceAll(userID.String(), "-", "")); err != nil {
			t.Fatalf("insert UserInfo user: %v", err)
		}
		pair, err := fixture.tokenService.GenerateAuthorizationCodeTokenPairWithClaims(
			context.Background(), oauthConsentClientID, userID.String(), []string{"profile"},
			[]string{"preferred_username"}, 1, time.Now().UTC().UnixMicro(), false,
		)
		if err != nil {
			t.Fatalf("generate profile-only access token: %v", err)
		}
		request := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		recorder := httptest.NewRecorder()
		fixture.authorizeHandler.UserInfo(recorder, request)
		assertOAuthSecurityJSONError(t, recorder, http.StatusForbidden, "insufficient_scope")
		if got := recorder.Header().Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="openid"` {
			t.Fatalf("WWW-Authenticate = %q", got)
		}
	})
}

func (f *oauthConsentSecurityFixture) authorize(query url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/authorize?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	f.authorizeHandler.Authorize(recorder, request)
	return recorder
}

func (f *oauthConsentSecurityFixture) saveSession(t *testing.T, userID string, authVersion int64) (string, string) {
	t.Helper()
	sessionID := "session-" + uuid.NewString()
	csrf := "csrf-" + uuid.NewString()
	if err := f.sessions.SaveSession(context.Background(), sessionID, &session.SessionData{
		UserID: userID, Username: "oauth-security-user", AuthVersion: authVersion, SessionVersion: 1, CSRFToken: csrf,
	}, time.Hour); err != nil {
		t.Fatalf("save session: %v", err)
	}
	return sessionID, csrf
}

func (f *oauthConsentSecurityFixture) saveConsent(t *testing.T, challenge, userID string, authVersion int64, state string) {
	t.Helper()
	if err := f.sessions.SaveConsent(context.Background(), challenge, &session.ConsentData{
		ClientID: oauthConsentClientID, UserID: userID, RedirectURI: oauthConsentRedirectURI,
		Scopes: []string{"profile"}, State: state, CodeChallenge: strings.Repeat("A", 43), ChallengeMethod: "S256",
		AuthVersion: authVersion,
	}, 10*time.Minute); err != nil {
		t.Fatalf("save consent: %v", err)
	}
}

func (f *oauthConsentSecurityFixture) consentMutation(
	t *testing.T,
	handler func(http.ResponseWriter, *http.Request),
	sessionID, csrf, challenge string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]string{"challenge": challenge})
	if err != nil {
		t.Fatalf("encode consent request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/consent", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: oauthSessionCookieName, Value: sessionID})
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func (f *oauthConsentSecurityFixture) consentDecisionMutation(
	t *testing.T, sessionID, csrf, challenge string, grantedOptionalScopes []string,
) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"challenge": challenge, "granted_optional_scopes": grantedOptionalScopes,
	})
	if err != nil {
		t.Fatalf("encode consent decision: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/consent/accept", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: oauthSessionCookieName, Value: sessionID})
	recorder := httptest.NewRecorder()
	f.consentHandler.AcceptConsent(recorder, request)
	return recorder
}

func assertOAuthSecurityRedirect(t *testing.T, recorder *httptest.ResponseRecorder, wantError, wantState string) {
	t.Helper()
	if recorder.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, http.StatusFound, recorder.Body.String())
	}
	location := recorder.Header().Get("Location")
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", location, err)
	}
	if parsed.Scheme+"://"+parsed.Host+parsed.Path != oauthConsentRedirectURI {
		t.Fatalf("redirect target = %q, want registered URI %q", parsed.Scheme+"://"+parsed.Host+parsed.Path, oauthConsentRedirectURI)
	}
	if parsed.Query().Get("error") != wantError || parsed.Query().Get("state") != wantState {
		t.Fatalf("redirect query = %v, want error=%q state=%q", parsed.Query(), wantError, wantState)
	}
}

func assertOAuthSecurityJSONError(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantError string) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d; body=%s", recorder.Code, wantStatus, recorder.Body.String())
	}
	body := decodeOAuthSecurityJSON(t, recorder)
	if body["error"] != wantError {
		t.Fatalf("error = %#v, want %q; body=%s", body["error"], wantError, recorder.Body.String())
	}
}

func decodeOAuthSecurityJSON(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response JSON: %v; body=%s", err, recorder.Body.String())
	}
	return body
}
