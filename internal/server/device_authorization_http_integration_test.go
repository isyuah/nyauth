package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func TestDeviceAuthorizationHTTPApprovalAndSingleUse(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	clientID := "device-http-client"
	registered := &models.OAuthClient{
		ID: clientID, Name: "Living room television", IsPublic: true,
		Grants: []string{models.GrantDeviceCode, models.GrantRefreshToken},
		Scopes: []string{"openid", "profile", "offline_access"}, OptionalScopes: []string{"profile", "offline_access"},
		AllowedClaims: []string{"sub", "preferred_username", "name"}, AccessPolicy: models.ClientAccessOpen,
		RedirectURIs: []string{}, PostLogoutRedirectURIs: []string{}, Metadata: map[string]string{},
	}
	if err := client.NewStore(testApp.pool).Create(ctx, registered); err != nil {
		t.Fatal(err)
	}
	displayName := "Device User"
	current := &models.User{
		ID: uuid.New(), Username: "device-http-user", DisplayName: &displayName,
		Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1,
		Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	if err := testApp.app.jwkManager.EnsureActiveKey(ctx); err != nil {
		t.Fatal(err)
	}

	createdSession, cookieHeader := createDeviceTestSession(t, testApp.app, current)
	initiation := deviceFormRequest(testApp.app, "/device_authorization", url.Values{
		"client_id": {clientID}, "scope": {"openid profile offline_access"},
	})
	if initiation.Code != http.StatusOK {
		t.Fatalf("device initiation status=%d body=%s", initiation.Code, initiation.Body.String())
	}
	if initiation.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("device initiation cache control = %q", initiation.Header().Get("Cache-Control"))
	}
	var device deviceAuthorizationResponse
	if err := json.Unmarshal(initiation.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.Interval != 5 || device.ExpiresIn != 600 ||
		device.VerificationURI != "https://auth.example.test/device" || !strings.Contains(device.VerificationURIComplete, "user_code=") {
		t.Fatalf("device initiation response = %#v", device)
	}

	prepared := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/device-authorization/prepare",
		`{"user_code":"`+strings.ToLower(strings.ReplaceAll(device.UserCode, "-", " "))+`"}`,
		cookieHeader, createdSession.Data.CSRFToken)
	if prepared.Code != http.StatusOK {
		t.Fatalf("prepare status=%d body=%s", prepared.Code, prepared.Body.String())
	}
	var preparation struct {
		ConsentURL string `json:"consent_url"`
	}
	if err := json.Unmarshal(prepared.Body.Bytes(), &preparation); err != nil {
		t.Fatal(err)
	}
	parsedConsentURL, err := url.Parse(preparation.ConsentURL)
	if err != nil || parsedConsentURL.Path != "/consent" || parsedConsentURL.Query().Get("challenge") == "" {
		t.Fatalf("consent URL = %q, err=%v", preparation.ConsentURL, err)
	}
	challenge := parsedConsentURL.Query().Get("challenge")

	consent := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/consent?challenge="+url.QueryEscape(challenge), "", cookieHeader, "")
	if consent.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consent.Code, consent.Body.String())
	}
	var consentPayload struct {
		Flow        string `json:"flow"`
		ClientID    string `json:"client_id"`
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(consent.Body.Bytes(), &consentPayload); err != nil {
		t.Fatal(err)
	}
	if consentPayload.Flow != "device_authorization" || consentPayload.ClientID != clientID || consentPayload.RedirectURI != "" {
		t.Fatalf("consent payload = %#v", consentPayload)
	}

	accepted := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/consent/accept",
		`{"challenge":"`+challenge+`","granted_optional_scopes":["profile","offline_access"]}`,
		cookieHeader, createdSession.Data.CSRFToken)
	if accepted.Code != http.StatusOK || !strings.Contains(accepted.Body.String(), `"redirect_url":"/device?status=approved"`) {
		t.Fatalf("accept status=%d body=%s", accepted.Code, accepted.Body.String())
	}

	token := deviceFormRequest(testApp.app, "/token", url.Values{
		"grant_type": {models.GrantDeviceCode}, "device_code": {device.DeviceCode}, "client_id": {clientID},
	})
	if token.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", token.Code, token.Body.String())
	}
	var pair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(token.Body.Bytes(), &pair); err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.IDToken == "" || pair.Scope != "offline_access openid profile" {
		t.Fatalf("token pair = %#v", pair)
	}
	if active, err := testApp.app.authorizationStore.GetActive(ctx, current.ID, clientID); err != nil || len(active.Scopes) != 3 {
		t.Fatalf("durable authorization = %#v, err=%v", active, err)
	}

	reused := deviceFormRequest(testApp.app, "/token", url.Values{
		"grant_type": {models.GrantDeviceCode}, "device_code": {device.DeviceCode}, "client_id": {clientID},
	})
	if reused.Code != http.StatusBadRequest || !strings.Contains(reused.Body.String(), `"error":"expired_token"`) {
		t.Fatalf("reused token status=%d body=%s", reused.Code, reused.Body.String())
	}
}

func TestDeviceAuthorizationHTTPPendingAndDenial(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	clientID := "device-http-denial"
	if err := client.NewStore(testApp.pool).Create(ctx, &models.OAuthClient{
		ID: clientID, Name: "Command line client", IsPublic: true,
		Grants: []string{models.GrantDeviceCode}, Scopes: []string{"openid"}, AllowedClaims: []string{"sub"},
		AccessPolicy: models.ClientAccessOpen, RedirectURIs: []string{}, PostLogoutRedirectURIs: []string{}, Metadata: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	current := &models.User{ID: uuid.New(), Username: "device-denial-user", Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{}}
	if err := user.NewStore(testApp.pool).Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	createdSession, cookieHeader := createDeviceTestSession(t, testApp.app, current)

	initiation := deviceFormRequest(testApp.app, "/device_authorization", url.Values{"client_id": {clientID}, "scope": {"openid"}})
	var device deviceAuthorizationResponse
	if initiation.Code != http.StatusOK || json.Unmarshal(initiation.Body.Bytes(), &device) != nil {
		t.Fatalf("initiation status=%d body=%s", initiation.Code, initiation.Body.String())
	}
	pending := deviceFormRequest(testApp.app, "/token", url.Values{
		"grant_type": {models.GrantDeviceCode}, "device_code": {device.DeviceCode}, "client_id": {clientID},
	})
	if pending.Code != http.StatusBadRequest || !strings.Contains(pending.Body.String(), `"error":"slow_down"`) || pending.Header().Get("Retry-After") != "10" {
		t.Fatalf("early poll status=%d retry=%q body=%s", pending.Code, pending.Header().Get("Retry-After"), pending.Body.String())
	}

	prepared := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/device-authorization/prepare",
		`{"user_code":"`+device.UserCode+`"}`, cookieHeader, createdSession.Data.CSRFToken)
	var preparation struct {
		ConsentURL string `json:"consent_url"`
	}
	if prepared.Code != http.StatusOK || json.Unmarshal(prepared.Body.Bytes(), &preparation) != nil {
		t.Fatalf("prepare status=%d body=%s", prepared.Code, prepared.Body.String())
	}
	challenge := strings.TrimPrefix(preparation.ConsentURL, "/consent?challenge=")
	decodedChallenge, err := url.QueryUnescape(challenge)
	if err != nil {
		t.Fatal(err)
	}
	denied := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/consent/deny",
		`{"challenge":"`+decodedChallenge+`"}`, cookieHeader, createdSession.Data.CSRFToken)
	if denied.Code != http.StatusOK || !strings.Contains(denied.Body.String(), `"redirect_url":"/device?status=denied"`) {
		t.Fatalf("deny status=%d body=%s", denied.Code, denied.Body.String())
	}
	poll := deviceFormRequest(testApp.app, "/token", url.Values{
		"grant_type": {models.GrantDeviceCode}, "device_code": {device.DeviceCode}, "client_id": {clientID},
	})
	if poll.Code != http.StatusBadRequest || !strings.Contains(poll.Body.String(), `"error":"access_denied"`) {
		t.Fatalf("denied poll status=%d body=%s", poll.Code, poll.Body.String())
	}
}

func createDeviceTestSession(t *testing.T, app *Server, current *models.User) (*AuthenticatedSession, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/device", nil)
	authenticated, err := app.sessionMiddleware.CreateSession(recorder, request, current)
	if err != nil {
		t.Fatal(err)
	}
	cookie := responseCookie(t, recorder, sessionCookieName)
	return authenticated, cookie.Name + "=" + cookie.Value
}

func deviceFormRequest(app *Server, path string, values url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "192.0.2.90:44000"
	recorder := httptest.NewRecorder()
	app.router.ServeHTTP(recorder, request)
	return recorder
}
