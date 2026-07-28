package server

import (
	"strings"
	"testing"
)

func TestValidateBrandingAcceptsTrimmedValues(t *testing.T) {
	branding, err := validateBranding("  Nya  ", "  https://cdn.example.com/logo.png  ")
	if err != nil {
		t.Fatal(err)
	}
	if branding.Title != "Nya" || branding.LogoURL != "https://cdn.example.com/logo.png" {
		t.Fatalf("branding = %#v", branding)
	}
}

func TestValidateBrandingAllowsEmptyLogoURL(t *testing.T) {
	branding, err := validateBranding("Nya", "")
	if err != nil {
		t.Fatal(err)
	}
	if branding.LogoURL != "" {
		t.Fatalf("logo url = %q", branding.LogoURL)
	}
}

func TestValidateBrandingAllowsSameOriginLogoPath(t *testing.T) {
	branding, err := validateBranding("Nya", "/media/branding/logo.png?v=2")
	if err != nil {
		t.Fatal(err)
	}
	if branding.LogoURL != "/media/branding/logo.png?v=2" {
		t.Fatalf("logo url = %q", branding.LogoURL)
	}
}

func TestValidateBrandingRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		title   string
		logoURL string
	}{
		{"empty title", "   ", ""},
		{"overlong title", strings.Repeat("喵", 65), ""},
		{"relative logo url", "Nya", "logo.png"},
		{"scheme relative logo url", "Nya", "//tracker.example/logo.png"},
		{"backslash logo url", "Nya", `/\\tracker.example/logo.png`},
		{"insecure absolute logo url", "Nya", "http://cdn.example.com/logo.png"},
		{"non-http scheme", "Nya", "javascript:alert(1)"},
		{"credentials in url", "Nya", "https://user:pass@cdn.example.com/logo.png"},
		{"overlong logo url", "Nya", "https://cdn.example.com/" + strings.Repeat("a", 512)},
	}
	for _, c := range cases {
		if _, err := validateBranding(c.title, c.logoURL); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
	}
}
