package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

type fakeAuditOutboxStore struct {
	items       []OutboxEvent
	delivered   []*models.AuditLog
	failed      []uuid.UUID
	deliverErr  error
	failureText string
	retryAt     time.Time
}

func (s *fakeAuditOutboxStore) ClaimAuditBatch(context.Context, string, int, time.Time, time.Duration) ([]OutboxEvent, error) {
	return s.items, nil
}

func (s *fakeAuditOutboxStore) DeliverAuditEvent(_ context.Context, _ OutboxEvent, entry *models.AuditLog, _ string, _ time.Time) error {
	if s.deliverErr != nil {
		return s.deliverErr
	}
	s.delivered = append(s.delivered, entry)
	return nil
}

func (s *fakeAuditOutboxStore) MarkAuditEventFailed(_ context.Context, id uuid.UUID, _ string, failure string, retryAt, _ time.Time) error {
	s.failed = append(s.failed, id)
	s.failureText = failure
	s.retryAt = retryAt
	return nil
}

func TestAuditLogFromOutboxPreservesStructuredDetails(t *testing.T) {
	id := uuid.New()
	actorID := uuid.New()
	createdAt := time.Date(2026, 7, 26, 1, 2, 3, 0, time.UTC)
	entry, err := auditLogFromOutbox(OutboxEvent{
		ID: id, Event: "user.password_reset", AggregateType: "user", AggregateID: "user-1", CreatedAt: createdAt,
		Payload: map[string]any{
			"actor_id": actorID.String(), "result": "success", "risk_level": "high",
			"auth_version": float64(4), "details": map[string]any{"source": "account_action"},
		},
	})
	if err != nil {
		t.Fatalf("convert audit event: %v", err)
	}
	if entry.ID != id || entry.ActorID == nil || *entry.ActorID != actorID || entry.TargetType == nil || *entry.TargetType != "user" || entry.TargetID == nil || *entry.TargetID != "user-1" {
		t.Fatalf("unexpected audit identity: %+v", entry)
	}
	if entry.RiskLevel != "high" || entry.CreatedAt != createdAt || entry.Details["source"] != "account_action" || entry.Details["auth_version"] != float64(4) {
		t.Fatalf("unexpected audit payload: %+v", entry)
	}
}

func TestDispatcherRetriesFailedDeliveryAndReportsIt(t *testing.T) {
	now := time.Date(2026, 7, 26, 2, 0, 0, 0, time.UTC)
	id := uuid.New()
	store := &fakeAuditOutboxStore{
		items: []OutboxEvent{{
			ID: id, Event: "user.email_changed", AggregateType: "user", AggregateID: "user-1",
			Payload: map[string]any{"result": "success", "risk_level": "high"}, AttemptCount: 3, CreatedAt: now,
		}},
		deliverErr: errors.New("database temporarily unavailable"),
	}
	var reportedEvent string
	dispatcher, err := newDispatcher(store, DispatcherOptions{
		WorkerID: "worker-1", Clock: func() time.Time { return now },
		OnError: func(_ context.Context, event string, _ error) { reportedEvent = event },
	})
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	processed, err := dispatcher.DispatchOnce(context.Background())
	if err == nil || processed != 0 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	if len(store.failed) != 1 || store.failed[0] != id || store.retryAt != now.Add(4*time.Minute) {
		t.Fatalf("unexpected retry state: failed=%v retryAt=%s", store.failed, store.retryAt)
	}
	if reportedEvent != "user.email_changed" || store.failureText == "" {
		t.Fatalf("event=%q failure=%q", reportedEvent, store.failureText)
	}
}

func TestAuditLogFromOutboxRejectsInvalidSecurityFields(t *testing.T) {
	_, err := auditLogFromOutbox(OutboxEvent{
		ID: uuid.New(), Event: "test", AggregateType: "user", AggregateID: "user-1",
		Payload: map[string]any{"result": "maybe"}, CreatedAt: time.Now(),
	})
	if err == nil {
		t.Fatal("expected invalid result to be rejected")
	}
}
