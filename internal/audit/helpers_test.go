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
	for _, key := range []string{"refresh_token", "authorization_code", "provider_secret", "csrf_value", "nonce"} {
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
