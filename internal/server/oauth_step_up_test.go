package server

import (
	"slices"
	"testing"

	"github.com/nyasharp/nyauth/internal/session"
)

func TestStepUpAuthenticationMethodsPreserveStandardPrimaryMethods(t *testing.T) {
	methods := mergeAuthenticationMethods([]string{"pwd", "unknown", "pwd"}, oauthAuthenticationMethods("session", "totp")...)
	if !slices.Equal(methods, []string{"pwd", "otp"}) {
		t.Fatalf("step-up authentication methods = %v", methods)
	}
	passkeyMethods := mergeAuthenticationMethods([]string{"federated"}, oauthAuthenticationMethods("session", "passkey")...)
	if !slices.Equal(passkeyMethods, []string{"federated", "hwk"}) {
		t.Fatalf("Passkey step-up authentication methods = %v", passkeyMethods)
	}
}

func TestConsentMaxAgeRequiresPersistedAuthorizationDecision(t *testing.T) {
	if !consentMaxAgeSatisfied(&session.ConsentData{}) {
		t.Fatal("consent without max_age should be satisfied")
	}
	zero := int64(0)
	if consentMaxAgeSatisfied(&session.ConsentData{MaxAgeSeconds: &zero}) {
		t.Fatal("max_age was satisfied without a persisted authentication decision")
	}
	if !consentMaxAgeSatisfied(&session.ConsentData{MaxAgeSeconds: &zero, MaxAgeSatisfied: true}) {
		t.Fatal("persisted max_age decision was ignored")
	}
}
