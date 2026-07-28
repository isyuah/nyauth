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
		"invalid CSRF token":       "security.csrf_validation_failed",
		"password change required": "account.password_change_required",
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
