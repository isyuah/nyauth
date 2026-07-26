package settings

import "testing"

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
}
