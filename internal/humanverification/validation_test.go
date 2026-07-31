package humanverification

import "testing"

func TestDefaultPolicyUsesBalancedProtectionBaseline(t *testing.T) {
	policy := DefaultPolicy()

	if !policy.Registration || policy.LoginMode != LoginAdaptive || policy.LoginTriggerAfter != 3 {
		t.Fatalf("unexpected registration/login defaults: %#v", policy)
	}
	if !policy.PasswordReset || !policy.EmailVerificationResend || !policy.ProviderLogin {
		t.Fatalf("unexpected public entry-point defaults: %#v", policy)
	}
}

func TestNormalizePolicyAndRequirements(t *testing.T) {
	policy, err := NormalizePolicy(Policy{
		Registration: true, LoginMode: " Adaptive ", LoginTriggerAfter: 3,
		PasswordReset: true, EmailVerificationResend: true, ProviderLogin: true,
	})
	if err != nil {
		t.Fatalf("NormalizePolicy: %v", err)
	}
	if !PolicyRequires(policy, ActionRegistration, 0) || PolicyRequires(policy, ActionLogin, 2) || !PolicyRequires(policy, ActionLogin, 3) {
		t.Fatalf("unexpected policy requirements: %#v", policy)
	}
	if _, err := NormalizePolicy(Policy{LoginMode: LoginAdaptive, LoginTriggerAfter: 0}); err == nil {
		t.Fatal("expected invalid trigger to fail")
	}
}

func TestNormalizeSettingsRejectsUnsafeValues(t *testing.T) {
	settings, err := NormalizeSettings(Settings{Provider: " TURNSTILE ", SiteKey: "site-key", WidgetMode: "managed"})
	if err != nil || settings.Provider != ProviderTurnstile {
		t.Fatalf("NormalizeSettings = %#v, %v", settings, err)
	}
	for _, siteKey := range []string{"", "site\nkey", "site\u202ekey"} {
		if _, err := NormalizeSettings(Settings{Provider: ProviderTurnstile, SiteKey: siteKey, WidgetMode: WidgetManaged}); err == nil {
			t.Fatalf("unsafe site key %q was accepted", siteKey)
		}
	}
	trimmed, err := NormalizeSettings(Settings{Provider: ProviderTurnstile, SiteKey: " site-key ", WidgetMode: WidgetManaged})
	if err != nil || trimmed.SiteKey != "site-key" {
		t.Fatalf("site key was not safely normalized: %#v, %v", trimmed, err)
	}
}
