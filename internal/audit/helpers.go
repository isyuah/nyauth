package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

// EnqueueResult durably queues an untargeted authentication event. It returns
// producer failures to the caller so request handlers can emit both a metric
// and a structured error without changing the authentication response.
func EnqueueResult(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName, result, riskLevel, ip, userAgent string, details map[string]any) error {
	entry := newAuditEntry(event, actorID, actorName, result, riskLevel, ip, userAgent, details)
	return EnqueueLog(ctx, store, entry)
}

// EnqueueTargetResult durably queues a targeted authentication event.
func EnqueueTargetResult(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName, targetType, targetID, result, riskLevel, ip, userAgent string, details map[string]any) error {
	entry := newAuditEntry(event, actorID, actorName, result, riskLevel, ip, userAgent, details)
	if value := strings.TrimSpace(targetType); value != "" {
		entry.TargetType = &value
	}
	if value := strings.TrimSpace(targetID); value != "" {
		entry.TargetID = &value
	}
	return EnqueueLog(ctx, store, entry)
}

// EnqueueLog converts an audit log into the durable outbox representation.
func EnqueueLog(ctx context.Context, store *Store, entry *models.AuditLog) error {
	if store == nil {
		return fmt.Errorf("audit store is required")
	}
	event, err := outboxEventFromAuditLog(entry)
	if err != nil {
		return err
	}
	return store.Enqueue(ctx, event)
}

func newAuditEntry(event string, actorID *uuid.UUID, actorName, result, riskLevel, ip, userAgent string, details map[string]any) *models.AuditLog {
	entry := &models.AuditLog{
		ID: uuid.New(), Event: event, ActorID: actorID, Result: result,
		RiskLevel: riskLevel, Details: details, CreatedAt: time.Now().UTC(),
	}
	if value := strings.TrimSpace(actorName); value != "" {
		entry.ActorName = &value
	}
	if value := strings.TrimSpace(ip); value != "" {
		entry.IPAddress = &value
	}
	if value := strings.TrimSpace(userAgent); value != "" {
		entry.UserAgent = &value
	}
	return entry
}

func outboxEventFromAuditLog(entry *models.AuditLog) (OutboxEvent, error) {
	if entry == nil {
		return OutboxEvent{}, fmt.Errorf("audit log is required")
	}
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	if entry.CreatedAt.IsZero() {
		entry.CreatedAt = time.Now().UTC()
	}
	result := strings.TrimSpace(entry.Result)
	if result == "" {
		result = "success"
	}
	riskLevel := strings.TrimSpace(entry.RiskLevel)
	if riskLevel == "" {
		riskLevel = "low"
	}
	payload := map[string]any{"result": result, "risk_level": riskLevel}
	if entry.ActorID != nil {
		payload["actor_id"] = entry.ActorID.String()
	}
	if entry.ActorName != nil && strings.TrimSpace(*entry.ActorName) != "" {
		payload["actor_name"] = strings.TrimSpace(*entry.ActorName)
	}
	if entry.TargetType != nil && strings.TrimSpace(*entry.TargetType) != "" {
		payload["target_type"] = strings.TrimSpace(*entry.TargetType)
	}
	if entry.TargetID != nil && strings.TrimSpace(*entry.TargetID) != "" {
		payload["target_id"] = strings.TrimSpace(*entry.TargetID)
	}
	if entry.IPAddress != nil && strings.TrimSpace(*entry.IPAddress) != "" {
		payload["ip_address"] = strings.TrimSpace(*entry.IPAddress)
	}
	if entry.UserAgent != nil && strings.TrimSpace(*entry.UserAgent) != "" {
		payload["user_agent"] = strings.TrimSpace(*entry.UserAgent)
	}
	if len(entry.Details) > 0 {
		details := make(map[string]any, len(entry.Details))
		for key, value := range entry.Details {
			if sensitiveAuditDetailKey(key) {
				return OutboxEvent{}, fmt.Errorf("audit detail %q is sensitive", key)
			}
			details[key] = value
		}
		payload["details"] = details
	}

	aggregateType, aggregateID := "event", strings.TrimSpace(entry.Event)
	if entry.ActorID != nil {
		aggregateType, aggregateID = "user", entry.ActorID.String()
	}
	if entry.TargetType != nil && entry.TargetID != nil && strings.TrimSpace(*entry.TargetType) != "" && strings.TrimSpace(*entry.TargetID) != "" {
		aggregateType, aggregateID = strings.TrimSpace(*entry.TargetType), strings.TrimSpace(*entry.TargetID)
	}
	return OutboxEvent{
		ID: entry.ID, Event: entry.Event, AggregateType: aggregateType,
		AggregateID: aggregateID, Payload: payload, AvailableAt: entry.CreatedAt.UTC(), CreatedAt: entry.CreatedAt.UTC(),
	}, nil
}

func sensitiveAuditDetailKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	for _, fragment := range []string{"password", "secret", "token", "cookie", "csrf", "nonce", "authorization_code", "code_verifier"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
