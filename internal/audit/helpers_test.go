package audit

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

func TestOutboxEventFromAuditLogUsesTargetAndSafeDetails(t *testing.T) {
	actorID := uuid.New()
	targetType, targetID := "provider", "github"
	actorName, ip := "alice", "203.0.113.5"
	createdAt := time.Date(2026, 7, 26, 3, 0, 0, 0, time.UTC)
	event, err := outboxEventFromAuditLog(&models.AuditLog{
		ID: uuid.New(), Event: "user.reauthenticated", ActorID: &actorID, ActorName: &actorName,
		TargetType: &targetType, TargetID: &targetID, IPAddress: &ip,
		Result: "success", RiskLevel: "medium", Details: map[string]any{"method": "provider"}, CreatedAt: createdAt,
	})
	if err != nil {
		t.Fatalf("convert audit log: %v", err)
	}
	if event.AggregateType != targetType || event.AggregateID != targetID || event.CreatedAt != createdAt {
		t.Fatalf("unexpected aggregate: %+v", event)
	}
	if event.Payload["actor_id"] != actorID.String() || event.Payload["ip_address"] != ip {
		t.Fatalf("unexpected payload: %#v", event.Payload)
	}
	details, ok := event.Payload["details"].(map[string]any)
	if !ok || details["method"] != "provider" {
		t.Fatalf("unexpected details: %#v", event.Payload["details"])
	}
}

func TestOutboxEventFromAuditLogRejectsSensitiveDetails(t *testing.T) {
	for _, key := range []string{
		"refresh_token", "authorization_code", "provider_secret", "csrf_value", "nonce",
		"passphrase", "credential", "credential_id", "recovery_code", "device_code", "user_code", "private_key", "api_key",
		"ciphertext", "totp_seed", "totp_secret",
	} {
		t.Run(key, func(t *testing.T) {
			_, err := outboxEventFromAuditLog(&models.AuditLog{
				ID: uuid.New(), Event: "token.issue_failed", Result: "failure", RiskLevel: "high",
				Details: map[string]any{key: "must-not-be-persisted"}, CreatedAt: time.Now(),
			})
			if err == nil {
				t.Fatalf("sensitive detail %q was accepted", key)
			}
		})
	}
}

func TestRedactDetailsProtectsLegacyAndNestedSensitiveKeys(t *testing.T) {
	input := map[string]interface{}{
		"method":        "provider",
		"access_token":  "legacy-token",
		"recovery_code": "legacy-recovery-code",
		"nested": map[string]interface{}{
			"client_secret": "legacy-secret",
			"credential_id": "legacy-credential-id",
			"totp_seed":     "legacy-totp-seed",
			"safe":          "visible",
		},
		"items": []interface{}{map[string]interface{}{"csrf_token": "legacy-csrf"}},
	}
	redacted := RedactDetails(input)
	if redacted["method"] != "provider" || redacted["access_token"] != "[REDACTED]" || redacted["recovery_code"] != "[REDACTED]" {
		t.Fatalf("top-level redaction = %#v", redacted)
	}
	nested := redacted["nested"].(map[string]interface{})
	if nested["client_secret"] != "[REDACTED]" || nested["credential_id"] != "[REDACTED]" || nested["totp_seed"] != "[REDACTED]" || nested["safe"] != "visible" {
		t.Fatalf("nested redaction = %#v", nested)
	}
	items := redacted["items"].([]interface{})
	if items[0].(map[string]interface{})["csrf_token"] != "[REDACTED]" {
		t.Fatalf("slice redaction = %#v", items)
	}
	if input["access_token"] != "legacy-token" {
		t.Fatalf("input map was mutated: %#v", input)
	}
	empty := map[string]interface{}{}
	redactedEmpty := RedactDetails(empty)
	redactedEmpty["safe"] = "detached"
	if len(empty) != 0 {
		t.Fatalf("empty input map was not detached: %#v", empty)
	}
}

func TestOutboxEventFromAuditLogAllowsSafeSecurityStateMetadata(t *testing.T) {
	_, err := outboxEventFromAuditLog(&models.AuditLog{
		ID: uuid.New(), Event: "settings.updated", Result: "success", RiskLevel: "high",
		Details: map[string]interface{}{
			"totp_enabled":          true,
			"recovery_codes":        10,
			"credential_configured": true,
		},
	})
	if err != nil {
		t.Fatalf("safe security state metadata was rejected: %v", err)
	}
}
