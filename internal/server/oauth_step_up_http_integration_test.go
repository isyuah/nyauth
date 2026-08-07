package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/oauthstepup"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestOAuthStepUpWithoutEnrolledFactorPreservesConsentChallenge(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	clientID := "step-up-http-client"
	registered := &models.OAuthClient{
		ID: clientID, Name: "Step-Up Test", IsPublic: true,
		Grants: []string{models.GrantAuthorizationCode}, Scopes: []string{"openid"},
		AllowedClaims: []string{"sub"}, AccessPolicy: models.ClientAccessOpen,
		RedirectURIs: []string{"https://client.example/callback"}, Metadata: map[string]string{},
	}
	if err := client.NewStore(testApp.pool).Create(ctx, registered); err != nil {
		t.Fatal(err)
	}
	current := &models.User{
		ID: uuid.New(), Username: "step-up-http-user", Status: models.UserStatusActive,
		Role: "user", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{},
	}
	if err := user.NewStore(testApp.pool).Create(ctx, current); err != nil {
		t.Fatal(err)
	}
	createdSession, cookieHeader := createDeviceTestSession(t, testApp.app, current)
	challenge := "step-up-consent-challenge"
	maxAge := int64(300)
	if err := testApp.app.sessionStore.SaveConsent(ctx, challenge, &session.ConsentData{
		ClientID: clientID, UserID: current.ID.String(), RedirectURI: registered.RedirectURIs[0],
		Scopes: []string{"openid"}, ScopeClaims: map[string][]string{"openid": {"sub"}},
		State: "state", CodeChallenge: "challenge", ChallengeMethod: "S256", AuthVersion: current.AuthVersion,
		ClientIdentityRevision: registered.IdentityRevision, ClientAuthorizationRevision: registered.AuthorizationRevision,
		RequiredAuthContext: oauthstepup.ACRLevel2, MaxAgeSeconds: &maxAge, MaxAgeSatisfied: true,
	}, 10*time.Minute); err != nil {
		t.Fatal(err)
	}

	consent := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/consent?challenge="+challenge, "", cookieHeader, "")
	if consent.Code != http.StatusOK {
		t.Fatalf("consent status=%d body=%s", consent.Code, consent.Body.String())
	}
	var consentPayload struct {
		StepUpRequired bool   `json:"step_up_required"`
		RequiredACR    string `json:"required_acr"`
	}
	if err := json.Unmarshal(consent.Body.Bytes(), &consentPayload); err != nil {
		t.Fatal(err)
	}
	if !consentPayload.StepUpRequired || consentPayload.RequiredACR != oauthstepup.ACRLevel2 {
		t.Fatalf("consent step-up payload=%#v", consentPayload)
	}

	stepUp := mfaHTTPRequest(testApp.app, http.MethodPost, "/api/consent/step-up", `{"challenge":"`+challenge+`"}`, cookieHeader, createdSession.Data.CSRFToken)
	var stepUpError struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(stepUp.Body.Bytes(), &stepUpError)
	if stepUp.Code != http.StatusConflict || stepUpError.Code != "oauth.unmet_authentication_requirements" {
		t.Fatalf("step-up status=%d body=%s", stepUp.Code, stepUp.Body.String())
	}
	stillAvailable := mfaHTTPRequest(testApp.app, http.MethodGet, "/api/consent?challenge="+challenge, "", cookieHeader, "")
	if stillAvailable.Code != http.StatusOK {
		t.Fatalf("preserved consent status=%d body=%s", stillAvailable.Code, stillAvailable.Body.String())
	}
}
