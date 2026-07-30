package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteAPIErrorIncludesStableCode(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeAPIError(recorder, http.StatusForbidden, "recent authentication is required")
	var payload map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["error"] != "recent authentication is required" || payload["code"] != "auth.recent_authentication_required" {
		t.Fatalf("error payload = %#v", payload)
	}
}

func TestUnknownAPIErrorUsesGenericStableCode(t *testing.T) {
	if got := apiErrorCodeForMessage("new internal wording"); got != apiErrorCodeRequestFailed {
		t.Fatalf("unknown error code = %q", got)
	}
}

func TestPasskeyCeremonyUnavailableHasSpecificStableCode(t *testing.T) {
	if got := apiErrorCodeForMessage("Passkey ceremony temporarily unavailable"); got != "passkey.ceremony_unavailable" {
		t.Fatalf("Passkey ceremony error code = %q", got)
	}
}

func TestMiddlewareErrorsHaveSpecificStableCodes(t *testing.T) {
	tests := map[string]string{
		"invalid CSRF token":                            "security.csrf_validation_failed",
		"password change required":                      "account.password_change_required",
		"self-service client creation is disabled":      "client.self_service_disabled",
		"OAuth client policy changed; reload and retry": "client.policy_changed",
	}
	for message, expected := range tests {
		if got := apiErrorCodeForMessage(message); got != expected {
			t.Fatalf("error code for %q = %q, want %q", message, got, expected)
		}
	}
}

func TestMediaSettingsErrorsHaveSpecificStableCodes(t *testing.T) {
	tests := map[string]string{
		"media settings are temporarily unavailable":                           "media.settings_unavailable",
		"media storage configuration is invalid":                               "media.configuration_invalid",
		"media settings changed; reload and try again":                         "media.revision_conflict",
		"a recent successful media storage test is required":                   "media.test_required",
		"active instances are still preparing the media storage candidate":     "media.instances_not_ready",
		"local media fallback is not configured":                               "media.fallback_not_configured",
		"local media fallback is already active":                               "media.fallback_already_active",
		"local media fallback migration requires a single active instance":     "media.fallback_requires_single_instance",
		"local media fallback is unavailable":                                  "media.fallback_unavailable",
		"clear the current maintenance expiry before starting media migration": "media.maintenance_expiry",
	}
	for message, expected := range tests {
		if got := apiErrorCodeForMessage(message); got != expected {
			t.Fatalf("error code for %q = %q, want %q", message, got, expected)
		}
	}
}

func TestMailTemplateErrorsHaveSpecificStableCodes(t *testing.T) {
	tests := map[string]string{
		"a verified administrator email is required for template tests": "mail.template_test_recipient_unverified",
		"test recipient must match the administrator's verified email":  "mail.template_test_recipient_mismatch",
		"mail delivery is unavailable":                                  "mail.delivery_unavailable",
		"test email could not be delivered":                             "mail.template_test_delivery_failed",
	}
	for message, expected := range tests {
		if got := apiErrorCodeForMessage(message); got != expected {
			t.Fatalf("error code for %q = %q, want %q", message, got, expected)
		}
	}
}

func TestAPIErrorMappingKeysAreNormalized(t *testing.T) {
	for message := range apiErrorCodesByMessage {
		if normalized := strings.ToLower(strings.TrimSpace(message)); message != normalized {
			t.Fatalf("API error mapping key %q is not normalized; use %q", message, normalized)
		}
	}
}
