package settings

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestLifecycleDefaultsUseDeploymentAuthenticationFallbacks(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	manager.SetAuthenticationFallbacks(45*time.Minute, 14*24*time.Hour, 90*time.Second)
	value := manager.Lifecycle()
	if value.AccessTokenDuration() != 45*time.Minute ||
		value.RefreshTokenDuration() != 14*24*time.Hour ||
		value.AuthorizationCodeDuration() != 90*time.Second {
		t.Fatalf("authentication fallback = %#v", value)
	}
	if value.SessionIdleTTL != value.SessionAbsoluteTTL || value.MaxConcurrentSessions != 0 {
		t.Fatalf("session compatibility defaults = %#v", value)
	}
}

func TestDecodeLegacyLifecyclePreservesSessionBehaviorAndUsesDeploymentTokenFallbacks(t *testing.T) {
	defaults := DefaultLifecycleWithAuthentication(365, 45*time.Minute, 14*24*time.Hour, 90*time.Second)
	raw, err := json.Marshal(map[string]any{
		"session_absolute_ttl": "48h", "recent_authentication_ttl": "10m", "audit_retention_days": 365,
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeLifecycle(raw, defaults)
	if err != nil {
		t.Fatal(err)
	}
	if value.SessionIdleTTL != "48h" || value.MaxConcurrentSessions != 0 {
		t.Fatalf("legacy session policy = %#v", value)
	}
	if value.AccessTokenDuration() != 45*time.Minute || value.RefreshTokenDuration() != 14*24*time.Hour || value.AuthorizationCodeDuration() != 90*time.Second {
		t.Fatalf("legacy token fallback = %#v", value)
	}
}

func TestValidateLifecycleAuthenticationAndSessionBounds(t *testing.T) {
	valid := DefaultLifecycle(365)
	valid.SessionIdleTTL = "12h"
	valid.MaxConcurrentSessions = 8
	if err := ValidateLifecycle(valid); err != nil {
		t.Fatalf("valid lifecycle: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Lifecycle)
	}{
		{name: "idle exceeds absolute", mutate: func(value *Lifecycle) { value.SessionIdleTTL = "25h" }},
		{name: "too many sessions", mutate: func(value *Lifecycle) { value.MaxConcurrentSessions = 101 }},
		{name: "long access token", mutate: func(value *Lifecycle) { value.AccessTokenTTL = "25h" }},
		{name: "short refresh token", mutate: func(value *Lifecycle) { value.RefreshTokenTTL = "59m" }},
		{name: "long authorization code", mutate: func(value *Lifecycle) { value.AuthorizationCodeTTL = "11m" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if err := ValidateLifecycle(value); err == nil {
				t.Fatalf("invalid lifecycle accepted: %#v", value)
			}
		})
	}
}

func TestBrandingFallsBackToDefaults(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya", LogoURL: "https://cdn.example.com/logo.png"})
	branding := manager.Branding()
	if branding.Title != "Nya" || branding.LogoURL != "https://cdn.example.com/logo.png" {
		t.Fatalf("branding = %#v", branding)
	}
}

func TestBrandingUsesStoredSnapshot(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	stored := Branding{Title: "Custom", LogoURL: ""}
	manager.branding.Store(&Versioned[Branding]{Revision: 2, Value: stored})
	if branding := manager.Branding(); branding.Title != "Custom" || branding.LogoURL != "" {
		t.Fatalf("branding = %#v", branding)
	}
	manager.branding.Store(nil)
	if branding := manager.Branding(); branding.Title != "Nya" {
		t.Fatalf("branding after reset = %#v", branding)
	}
}

func TestRegistrationFallsBackToSafeDefaults(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	registration := manager.Registration()
	if registration.Mode != RegistrationClosed || !registration.RequireEmailVerification {
		t.Fatalf("registration defaults must be closed with verification: %#v", registration)
	}
	if registration.InviteDefaultTTL != "168h" || registration.InviteDefaultMaxUses != 1 {
		t.Fatalf("invite defaults = %#v", registration)
	}

	stored := Registration{Mode: RegistrationOpen, RequireEmailVerification: true, InviteDefaultTTL: "24h", InviteDefaultMaxUses: 5}
	manager.registration.Store(&Versioned[Registration]{Revision: 3, Value: stored})
	if got := manager.Registration(); got.Mode != RegistrationOpen || got.InviteDefaultMaxUses != 5 {
		t.Fatalf("registration = %#v", got)
	}
}

func TestSecurityFallsBackToEnrollmentEnabledAndOptionalAdminMFA(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	security := manager.Security()
	if !security.TOTPEnabled || !security.PasskeysEnabled || security.RequireMFAForAdmins {
		t.Fatalf("security defaults = %#v", security)
	}
	stored := Security{TOTPEnabled: false, PasskeysEnabled: false, RequireMFAForAdmins: false}
	manager.security.Store(&Versioned[Security]{Revision: 4, Value: stored})
	if got := manager.Security(); got.TOTPEnabled || got.PasskeysEnabled || got.RequireMFAForAdmins {
		t.Fatalf("security snapshot = %#v", got)
	}
}

func TestValidRegistrationMode(t *testing.T) {
	for _, mode := range []string{RegistrationClosed, RegistrationInviteOnly, RegistrationOpen} {
		if !ValidRegistrationMode(mode) {
			t.Fatalf("%s must be valid", mode)
		}
	}
	if ValidRegistrationMode("vip") || ValidRegistrationMode("") {
		t.Fatal("unknown modes must be rejected")
	}
}

func TestLoadWithoutDatabaseKeepsDefaults(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	if err := manager.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if branding := manager.Branding(); branding.Title != "Nya" {
		t.Fatalf("branding = %#v", branding)
	}
	if registration := manager.Registration(); registration.Mode != RegistrationClosed {
		t.Fatalf("registration = %#v", registration)
	}
	if security := manager.Security(); !security.TOTPEnabled || !security.PasskeysEnabled || security.RequireMFAForAdmins {
		t.Fatalf("security = %#v", security)
	}
}

func TestSettingsLoadsAndWritesShareOnePublicationLock(t *testing.T) {
	manager := NewManager(nil, Branding{Title: "Nya"})
	manager.loadMu.Lock()
	loadDone := make(chan error, 1)
	writeDone := make(chan error, 1)
	go func() { loadDone <- manager.Load(t.Context()) }()
	go func() {
		_, err := manager.SetRegistration(
			t.Context(), DefaultRegistration(), 0, "test", false, testSettingsMutation("test"),
		)
		writeDone <- err
	}()
	for _, operation := range []struct {
		name   string
		result <-chan error
	}{
		{name: "load", result: loadDone},
		{name: "write", result: writeDone},
	} {
		select {
		case <-operation.result:
			manager.loadMu.Unlock()
			t.Fatalf("%s bypassed the settings publication lock", operation.name)
		case <-time.After(25 * time.Millisecond):
		}
	}
	manager.loadMu.Unlock()
	if err := <-loadDone; err != nil {
		t.Fatalf("Load without database: %v", err)
	}
	if err := <-writeDone; err == nil {
		t.Fatal("SetRegistration without database unexpectedly succeeded")
	}
}

func testSettingsMutation(actor string) audit.MutationAudit {
	return audit.MutationAudit{
		Event: models.AuditSettingsUpdated, ActorID: uuid.New(), ActorName: actor,
		Result: "success", RiskLevel: "high",
	}
}
