package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nyasharp/nyauth/internal/settings"
)

func TestGetBrandingReturnsPublicNoStoreDTO(t *testing.T) {
	manager := settings.NewManager(nil, settings.Branding{
		Title: "Public Nya", PrimaryColor: "#123456", PrimaryTextColor: settings.PrimaryTextWhite,
		LightLogoURL: "/light.webp", DarkLogoURL: "/dark.webp", FaviconURL: "/favicon.ico",
	})
	server := &Server{settingsMgr: manager}
	recorder := httptest.NewRecorder()
	server.handleGetBranding(recorder, httptest.NewRequest(http.MethodGet, "/api/branding", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"title", "primary_color", "primary_text_color", "light_logo_url", "dark_logo_url", "favicon_url"} {
		if _, ok := response[field]; !ok {
			t.Fatalf("public branding response is missing %q: %#v", field, response)
		}
	}
	for _, private := range []string{"revision", "updated_by", "updated_at", "default_theme"} {
		if _, ok := response[private]; ok {
			t.Fatalf("public branding response leaked %q: %#v", private, response)
		}
	}
}

func TestGetBrandingStylesheetProvidesCurrentPaletteBeforeAppMount(t *testing.T) {
	manager := settings.NewManager(nil, settings.Branding{
		Title: "Public Nya", PrimaryColor: "#F6D365", PrimaryTextColor: settings.PrimaryTextWhite,
	})
	server := &Server{settingsMgr: manager}
	recorder := httptest.NewRecorder()
	server.handleGetBrandingStylesheet(recorder, httptest.NewRequest(http.MethodGet, "/branding.css", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/css; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	for _, expected := range []string{
		`:root,[data-theme="light"]{`, `[data-theme="dark"]{`,
		`--nya-primary:#F6D365`, `--nya-primary-rgb:246 211 101`, `--nya-primary-contrast:#FFFFFF`,
	} {
		if !strings.Contains(recorder.Body.String(), expected) {
			t.Fatalf("stylesheet does not contain %q: %s", expected, recorder.Body.String())
		}
	}
}

func TestValidateBrandingAcceptsTrimmedValues(t *testing.T) {
	branding, err := validateBranding(
		"  Nya  ", " #704de8 ", " WHITE ",
		"  https://cdn.example.com/light.png  ", "/dark.png", "/favicon.ico",
	)
	if err != nil {
		t.Fatal(err)
	}
	if branding.Title != "Nya" || branding.PrimaryColor != "#704DE8" || branding.PrimaryTextColor != settings.PrimaryTextWhite ||
		branding.LightLogoURL != "https://cdn.example.com/light.png" || branding.DarkLogoURL != "/dark.png" ||
		branding.FaviconURL != "/favicon.ico" {
		t.Fatalf("branding = %#v", branding)
	}
}

func TestValidateBrandingAllowsEmptyAssetURLs(t *testing.T) {
	branding, err := validateBranding("Nya", "#123456", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if branding.LightLogoURL != "" || branding.DarkLogoURL != "" || branding.FaviconURL != "" {
		t.Fatalf("branding assets = %#v", branding)
	}
}

func TestValidateBrandingAllowsSameOriginAssetPath(t *testing.T) {
	branding, err := validateBranding("Nya", "#ABCDEF", "auto", "/media/branding/logo.png?v=2", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if branding.LightLogoURL != "/media/branding/logo.png?v=2" {
		t.Fatalf("logo url = %q", branding.LightLogoURL)
	}
}

func TestValidateBrandingRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name         string
		title        string
		primaryColor string
		primaryText  string
		assetURL     string
	}{
		{"empty title", "   ", "#704DE8", "auto", ""},
		{"overlong title", strings.Repeat("喵", 65), "#704DE8", "auto", ""},
		{"mail header title", "Nya\r\nBcc: attacker@example.test", "#704DE8", "auto", ""},
		{"bidirectional title", "Nya\u202eAuth", "#704DE8", "auto", ""},
		{"short color", "Nya", "#704D", "auto", ""},
		{"color without hash", "Nya", "704DE8", "auto", ""},
		{"unknown text color", "Nya", "#704DE8", "purple", ""},
		{"relative asset url", "Nya", "#704DE8", "auto", "logo.png"},
		{"scheme relative asset url", "Nya", "#704DE8", "auto", "//tracker.example/logo.png"},
		{"backslash asset url", "Nya", "#704DE8", "auto", `/\\tracker.example/logo.png`},
		{"insecure absolute asset url", "Nya", "#704DE8", "auto", "http://cdn.example.com/logo.png"},
		{"non-http scheme", "Nya", "#704DE8", "auto", "javascript:alert(1)"},
		{"credentials in url", "Nya", "#704DE8", "auto", "https://user:pass@cdn.example.com/logo.png"},
		{"overlong asset url", "Nya", "#704DE8", "auto", "https://cdn.example.com/" + strings.Repeat("a", 512)},
	}
	for _, c := range cases {
		if _, err := validateBranding(c.title, c.primaryColor, c.primaryText, c.assetURL, "", ""); err == nil {
			t.Fatalf("%s: expected error", c.name)
		}
	}
}

func TestAbsoluteBrandingAssetURLBindsSameOriginPathToIssuer(t *testing.T) {
	if got := absoluteBrandingAssetURL("https://auth.example.test/base", "/media/logo.webp?v=2"); got != "https://auth.example.test/media/logo.webp?v=2" {
		t.Fatalf("absolute asset URL = %q", got)
	}
	if got := absoluteBrandingAssetURL("https://auth.example.test", "https://cdn.example.test/logo.webp"); got != "https://cdn.example.test/logo.webp" {
		t.Fatalf("external asset URL = %q", got)
	}
	if got := absoluteBrandingAssetURL("", "/media/logo.webp"); got != "" {
		t.Fatalf("asset URL without issuer = %q", got)
	}
}
