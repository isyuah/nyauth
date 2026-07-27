package settings

import (
	"testing"
	"time"
)

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
	manager.branding.Store(&stored)
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
	manager.registration.Store(&stored)
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
	manager.security.Store(&stored)
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
		writeDone <- manager.SetRegistration(t.Context(), DefaultRegistration(), "test", false)
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
