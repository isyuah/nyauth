package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/nyasharp/nyauth/pkg/models"
)

// MutationAudit contains trusted request metadata for a successful management
// mutation. Failure events are recorded by the HTTP mutation audit middleware.
type MutationAudit struct {
	Event      string
	ActorID    uuid.UUID
	ActorName  string
	TargetType string
	TargetID   string
	Result     string
	RiskLevel  string
	IPAddress  string
	UserAgent  string
	Details    map[string]any
}

type mutationAuditContextKey struct{}

// WithMutationAudit attaches trusted audit metadata to a request context.
func WithMutationAudit(ctx context.Context, value MutationAudit) context.Context {
	value.Details = cloneAuditDetails(value.Details)
	return context.WithValue(ctx, mutationAuditContextKey{}, value)
}

// MutationAuditFromContext returns a copy of trusted mutation metadata.
func MutationAuditFromContext(ctx context.Context) (MutationAudit, bool) {
	value, ok := ctx.Value(mutationAuditContextKey{}).(MutationAudit)
	if !ok {
		return MutationAudit{}, false
	}
	value.Details = cloneAuditDetails(value.Details)
	return value, true
}

// WithTarget returns a copy bound to the resource mutated by the transaction.
func (value MutationAudit) WithTarget(targetType, targetID string) MutationAudit {
	value.TargetType = strings.TrimSpace(targetType)
	value.TargetID = strings.TrimSpace(targetID)
	value.Details = cloneAuditDetails(value.Details)
	return value
}

// WithDetails returns a copy with additional non-sensitive structured details.
func (value MutationAudit) WithDetails(details map[string]any) MutationAudit {
	value.Details = cloneAuditDetails(value.Details)
	for key, detail := range details {
		value.Details[key] = detail
	}
	return value
}

// ValidateEvent prevents a fixed management operation from being committed
// under a different route's audit event.
func (value MutationAudit) ValidateEvent(expected string) error {
	if strings.TrimSpace(value.Event) != strings.TrimSpace(expected) || strings.TrimSpace(expected) == "" {
		return fmt.Errorf("unexpected mutation audit event")
	}
	return nil
}

// EnqueueMutationTx writes the successful audit event in the same transaction
// as its state change. Invalid or sensitive metadata fails closed so callers
// roll the state mutation back.
func EnqueueMutationTx(ctx context.Context, tx pgx.Tx, value MutationAudit) error {
	value.Event = strings.TrimSpace(value.Event)
	value.ActorName = strings.TrimSpace(value.ActorName)
	value.TargetType = strings.TrimSpace(value.TargetType)
	value.TargetID = strings.TrimSpace(value.TargetID)
	value.IPAddress = strings.TrimSpace(value.IPAddress)
	value.UserAgent = strings.TrimSpace(value.UserAgent)
	value.Result = strings.TrimSpace(value.Result)
	value.RiskLevel = strings.TrimSpace(value.RiskLevel)
	if value.Event == "" {
		return fmt.Errorf("audit event is required")
	}
	if value.ActorID == uuid.Nil || value.ActorName == "" {
		return fmt.Errorf("audit actor is required")
	}
	if value.TargetType == "" || value.TargetID == "" {
		return fmt.Errorf("audit target is required")
	}
	if value.Result == "" {
		value.Result = "success"
	}
	if value.Result != "success" {
		return fmt.Errorf("transactional mutation audit result must be success")
	}
	if value.RiskLevel == "" {
		value.RiskLevel = "high"
	}
	if !validRiskLevel(value.RiskLevel) {
		return fmt.Errorf("audit risk level is invalid")
	}

	actorID := value.ActorID
	actorName := value.ActorName
	targetType := value.TargetType
	targetID := value.TargetID
	entry := &models.AuditLog{
		ID:         uuid.New(),
		Event:      value.Event,
		ActorID:    &actorID,
		ActorName:  &actorName,
		TargetType: &targetType,
		TargetID:   &targetID,
		Result:     value.Result,
		RiskLevel:  value.RiskLevel,
		Details:    cloneAuditDetails(value.Details),
		CreatedAt:  time.Now().UTC(),
	}
	if value.IPAddress != "" {
		entry.IPAddress = &value.IPAddress
	}
	if value.UserAgent != "" {
		entry.UserAgent = &value.UserAgent
	}
	outboxEvent, err := outboxEventFromAuditLog(entry)
	if err != nil {
		return fmt.Errorf("building mutation audit event: %w", err)
	}
	if err := EnqueueTx(ctx, tx, outboxEvent); err != nil {
		return fmt.Errorf("queueing mutation audit event: %w", err)
	}
	return nil
}

func cloneAuditDetails(details map[string]any) map[string]any {
	if len(details) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(details))
	for key, value := range details {
		cloned[key] = value
	}
	return cloned
}
