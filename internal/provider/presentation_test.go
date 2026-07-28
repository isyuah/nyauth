package provider

import (
	"errors"
	"testing"
)

func TestNormalizePresentationDefaultsAndTrims(t *testing.T) {
	displayName, iconKey, err := normalizePresentation("company-sso", "  Company SSO  ", "  GLOBE ")
	if err != nil {
		t.Fatalf("normalizePresentation() error = %v", err)
	}
	if displayName != "Company SSO" || iconKey != "globe" {
		t.Fatalf("presentation = %q/%q", displayName, iconKey)
	}
	displayName, iconKey, err = normalizePresentation("company-sso", "", "")
	if err != nil || displayName != "company-sso" || iconKey != "auto" {
		t.Fatalf("default presentation = %q/%q err=%v", displayName, iconKey, err)
	}
}

func TestNormalizePresentationRejectsUnsupportedIcon(t *testing.T) {
	_, _, err := normalizePresentation("company-sso", "Company SSO", "remote-url")
	if !errors.Is(err, ErrInvalidPresentation) {
		t.Fatalf("unsupported icon error = %v", err)
	}
}
