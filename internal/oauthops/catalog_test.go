package oauthops

import (
	"slices"
	"testing"
)

func TestEventNormalizeBoundsDiagnosticData(t *testing.T) {
	t.Parallel()
	event := Event{
		ClientID: " client-1 ", Flow: FlowAuthorizationCode, Stage: StageAuthorization,
		Outcome: OutcomeFailure, Reason: ReasonRedirectURIMismatch,
		RequestID: " request-1 ", RedirectURI: "https://app.example/callback?code=secret#fragment",
		Scopes: []string{"profile", "openid", "profile", "not valid"},
	}
	if err := event.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if event.ClientID != "client-1" || event.RequestID != "request-1" {
		t.Fatalf("normalized identifiers = %q/%q", event.ClientID, event.RequestID)
	}
	if event.RedirectURI != "https://app.example/callback" {
		t.Fatalf("redirect URI = %q", event.RedirectURI)
	}
	if !slices.Equal(event.Scopes, []string{"openid", "profile"}) {
		t.Fatalf("scopes = %#v", event.Scopes)
	}
}

func TestEventNormalizeFailsClosedForUnknownVocabulary(t *testing.T) {
	t.Parallel()
	tests := []Event{
		{ClientID: "client", Flow: "invented", Stage: StageToken, Outcome: OutcomeFailure, Reason: ReasonServerError},
		{ClientID: "client", Flow: FlowRefreshToken, Stage: "invented", Outcome: OutcomeFailure, Reason: ReasonServerError},
		{ClientID: "client", Flow: FlowRefreshToken, Stage: StageToken, Outcome: OutcomeFailure, Reason: "raw database error"},
	}
	for _, event := range tests {
		if err := event.Normalize(); err == nil {
			t.Fatalf("Normalize accepted unknown vocabulary: %#v", event)
		}
	}
}

func TestReasonForGrantFailureDoesNotPersistRawErrors(t *testing.T) {
	t.Parallel()
	if got := ReasonForGrantFailure("temporarily_unavailable"); got != ReasonTemporarilyUnavailable {
		t.Fatalf("temporary reason = %q", got)
	}
	if got := ReasonForGrantFailure("SELECT password FROM users"); got != ReasonServerError {
		t.Fatalf("unknown reason = %q", got)
	}
}
