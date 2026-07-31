package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nyasharp/nyauth/internal/humanverification"
)

type humanVerificationRuntimeStub struct {
	humanVerificationRuntime
	challenge humanverification.PublicChallenge
	verifyErr error
	verified  *humanverification.VerifyInput
	attempt   int
}

func (s *humanVerificationRuntimeStub) PublicChallenge(action string, _ int) humanverification.PublicChallenge {
	result := s.challenge
	result.Action = action
	return result
}

func (s *humanVerificationRuntimeStub) Verify(_ context.Context, input humanverification.VerifyInput, attempt int) error {
	s.verified = &input
	s.attempt = attempt
	return s.verifyErr
}

func TestGetHumanVerificationReturnsPublicNoStoreDTO(t *testing.T) {
	server := &Server{humanVerification: &humanVerificationRuntimeStub{challenge: humanverification.PublicChallenge{
		Enabled: true, Required: true, Available: true, Provider: humanverification.ProviderTurnstile,
		SiteKey: "public-site-key", WidgetMode: humanverification.WidgetManaged,
	}}}
	request := httptest.NewRequest(http.MethodGet, "/api/human-verification?action=register", nil)
	recorder := httptest.NewRecorder()
	server.handleGetHumanVerification(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache-control=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["site_key"] != "public-site-key" || response["provider"] != "turnstile" || response["required"] != true {
		t.Fatalf("public challenge = %#v", response)
	}
	for _, forbidden := range []string{"secret", "revision", "active_version_id", "internal_reason"} {
		if _, exists := response[forbidden]; exists {
			t.Fatalf("public challenge exposed %q: %#v", forbidden, response)
		}
	}
}

func TestGetHumanVerificationRejectsUnknownAndAdminActions(t *testing.T) {
	server := &Server{}
	for _, action := range []string{"private_action", humanverification.ActionAdminTest} {
		request := httptest.NewRequest(http.MethodGet, "/api/human-verification?action="+action, nil)
		recorder := httptest.NewRecorder()
		server.handleGetHumanVerification(recorder, request)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("action %q status = %d", action, recorder.Code)
		}
	}
}

func TestRequireHumanVerificationFailsClosedAndForwardsBoundedProof(t *testing.T) {
	challenge := humanverification.PublicChallenge{
		Enabled: true, Required: true, Available: true, Provider: humanverification.ProviderTurnstile,
		SiteKey: "site-key", WidgetMode: humanverification.WidgetManaged,
	}
	tests := []struct {
		name       string
		available  bool
		proof      *humanVerificationProof
		verifyErr  error
		wantOK     bool
		wantStatus int
	}{
		{name: "missing proof", available: true, wantStatus: http.StatusPreconditionRequired},
		{name: "provider unavailable", wantStatus: http.StatusServiceUnavailable},
		{name: "rejected", available: true, proof: &humanVerificationProof{Token: "token", IdempotencyKey: "idempotency"}, verifyErr: humanverification.ErrVerificationRejected, wantStatus: http.StatusUnprocessableEntity},
		{name: "upstream failure", available: true, proof: &humanVerificationProof{Token: "token", IdempotencyKey: "idempotency"}, verifyErr: humanverification.ErrVerificationUnavailable, wantStatus: http.StatusServiceUnavailable},
		{name: "success", available: true, proof: &humanVerificationProof{Token: "token", IdempotencyKey: "idempotency"}, wantOK: true, wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configured := challenge
			configured.Available = test.available
			stub := &humanVerificationRuntimeStub{challenge: configured, verifyErr: test.verifyErr}
			server := &Server{humanVerification: stub}
			request := httptest.NewRequest(http.MethodPost, "/api/login", nil)
			request.RemoteAddr = "203.0.113.50:42310"
			recorder := httptest.NewRecorder()
			ok := server.requireHumanVerification(recorder, request, humanverification.ActionLogin, 4, test.proof)
			if ok != test.wantOK || recorder.Code != test.wantStatus {
				t.Fatalf("ok=%v status=%d body=%s", ok, recorder.Code, recorder.Body.String())
			}
			if test.wantOK && (stub.verified == nil || stub.verified.Token != "token" || stub.verified.Action != humanverification.ActionLogin || stub.attempt != 4) {
				t.Fatalf("forwarded verification = %#v attempt=%d", stub.verified, stub.attempt)
			}
		})
	}
}

func TestHumanVerificationMutationErrorsHaveStableStatuses(t *testing.T) {
	tests := []struct {
		err    error
		status int
	}{
		{humanverification.ErrStateConflict, http.StatusConflict},
		{humanverification.ErrCandidateTestRequired, http.StatusConflict},
		{humanverification.ErrNoActiveVersion, http.StatusConflict},
		{humanverification.ErrAlreadyEnabled, http.StatusConflict},
		{humanverification.ErrSecretInheritance, http.StatusBadRequest},
		{errors.Join(humanverification.ErrInvalidConfig, errors.New("invalid site key")), http.StatusBadRequest},
	}
	for _, test := range tests {
		recorder := httptest.NewRecorder()
		(&Server{}).writeHumanVerificationMutationError(recorder, test.err)
		if recorder.Code != test.status {
			t.Fatalf("error %v status=%d body=%s", test.err, recorder.Code, recorder.Body.String())
		}
	}
}
