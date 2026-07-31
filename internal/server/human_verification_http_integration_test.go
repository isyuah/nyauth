package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/humanverification"
)

func TestAdaptiveHumanVerificationCountsOnlyInvalidCredentialResponses(t *testing.T) {
	testApp := newRegistrationHTTPTestApp(t)
	ctx := context.Background()
	actorID := uuid.New()
	if _, err := testApp.pool.Exec(ctx, `
		INSERT INTO users (id,username,status,role,creation_source)
		VALUES ($1,$2,'active','admin','legacy')
	`, actorID, "adaptive-admin-"+strings.ReplaceAll(actorID.String(), "-", "")); err != nil {
		t.Fatalf("insert human verification administrator: %v", err)
	}
	mutation := func(event string) audit.MutationAudit {
		return audit.MutationAudit{
			Event: event, ActorID: actorID, ActorName: "adaptive-admin", Result: "success", RiskLevel: "high",
			IPAddress: "192.0.2.60", UserAgent: "human-verification-http-integration-test",
		}
	}
	secret := "turnstile-http-integration-secret"
	initial, err := testApp.app.humanVerification.LoadState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := testApp.app.humanVerification.CreateCandidate(ctx, humanverification.CreateCandidateInput{
		ExpectedRevision: initial.Revision,
		Settings: humanverification.Settings{
			Provider: humanverification.ProviderTurnstile, SiteKey: "http-integration-site", WidgetMode: humanverification.WidgetManaged,
		},
		Secret: &secret, Audit: mutation(humanverification.AuditSettingsSaved),
	})
	if err != nil {
		t.Fatal(err)
	}
	tested, err := testApp.app.humanVerification.RecordTest(ctx, humanverification.RecordTestInput{
		ExpectedRevision: candidate.State.Revision, VersionID: candidate.Version.ID,
		Result: humanverification.TestSuccess, Audit: mutation(humanverification.AuditSettingsTested),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = testApp.app.humanVerification.Activate(ctx, humanverification.ActivateInput{
		ExpectedRevision: tested.State.Revision, VersionID: candidate.Version.ID,
		Policy: humanverification.Policy{LoginMode: humanverification.LoginAdaptive, LoginTriggerAfter: 2},
		Audit:  mutation(humanverification.AuditSettingsActivated),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := testApp.app.humanVerification.Load(ctx); err != nil {
		t.Fatal(err)
	}

	password := "a-valid-password-123"
	hash, err := internalcrypto.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	username := "pending-adaptive"
	if _, err := testApp.pool.Exec(ctx, `
		INSERT INTO users (id,username,email,password_hash,password_changed_at,status,role,creation_source)
		VALUES ($1,$2,$3,$4,NOW(),'pending','user','self_registration')
	`, uuid.New(), username, "pending-adaptive@example.test", hash); err != nil {
		t.Fatalf("insert pending user: %v", err)
	}

	login := func(password string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"username": username, "password": password, "return_to": "/dashboard"})
		if err != nil {
			t.Fatal(err)
		}
		return registrationHTTPRequest(testApp.app, http.MethodPost, "/api/login", string(body), "https://auth.example.test", "203.0.113.60:45100")
	}
	pending := login(password)
	if pending.Code != http.StatusForbidden || !strings.Contains(pending.Body.String(), "email verification is required") {
		t.Fatalf("pending login status=%d body=%s", pending.Code, pending.Body.String())
	}
	if keys := humanVerificationFailureKeys(testApp.mini.Keys()); len(keys) != 0 {
		t.Fatalf("pending account accumulated adaptive failures: %#v", keys)
	}

	for attempt := 0; attempt < 2; attempt++ {
		failed := login("wrong-password-123")
		if failed.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d status=%d body=%s", attempt+1, failed.Code, failed.Body.String())
		}
	}
	if keys := humanVerificationFailureKeys(testApp.mini.Keys()); len(keys) != 2 {
		t.Fatalf("adaptive identity/IP failure keys = %#v", keys)
	}
	required := login("wrong-password-123")
	if required.Code != http.StatusPreconditionRequired || !strings.Contains(required.Body.String(), `"code":"human_verification.required"`) {
		t.Fatalf("adaptive challenge status=%d body=%s", required.Code, required.Body.String())
	}
}

func humanVerificationFailureKeys(keys []string) []string {
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if strings.Contains(key, "nyauth:human-verification-login:") {
			result = append(result, key)
		}
	}
	return result
}
