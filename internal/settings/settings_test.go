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
	manager.snapshot.Store(&stored)
	if branding := manager.Branding(); branding.Title != "Custom" || branding.LogoURL != "" {
		t.Fatalf("branding = %#v", branding)
	}
	manager.snapshot.Store(nil)
	if branding := manager.Branding(); branding.Title != "Nya" {
		t.Fatalf("branding after reset = %#v", branding)
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
}
