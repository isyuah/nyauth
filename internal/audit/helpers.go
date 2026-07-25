package audit

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Helper to create an audit log entry quickly.
func Record(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName string, ip string) {
	entry := &models.AuditLog{
		ID:        uuid.New(),
		Event:     event,
		ActorID:   actorID,
		ActorName: &actorName,
		Result:    "success",
		RiskLevel: "low",
		CreatedAt: time.Now(),
	}
	if ip != "" {
		entry.IPAddress = &ip
	}
	_ = store.Record(ctx, entry)
}

// RecordWithTarget records an audit event with target info.
func RecordWithTarget(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName, targetType, targetID, ip string) {
	entry := &models.AuditLog{
		ID:         uuid.New(),
		Event:      event,
		ActorID:    actorID,
		ActorName:  &actorName,
		TargetType: &targetType,
		TargetID:   &targetID,
		Result:     "success",
		RiskLevel:  "low",
		CreatedAt:  time.Now(),
	}
	if ip != "" {
		entry.IPAddress = &ip
	}
	_ = store.Record(ctx, entry)
}

// GetIP extracts the client IP from a request.
func GetIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
