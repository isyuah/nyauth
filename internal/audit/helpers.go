package audit

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/pkg/models"
)

// Helper to create an audit log entry quickly.
func Record(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName string, ip string) {
	RecordResult(ctx, store, event, actorID, actorName, "success", ip)
}

// RecordResult records an event with its actual outcome.
func RecordResult(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName, result, ip string) {
	entry := &models.AuditLog{
		ID:        uuid.New(),
		Event:     event,
		ActorID:   actorID,
		ActorName: &actorName,
		Result:    result,
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
	RecordTargetResult(ctx, store, event, actorID, actorName, targetType, targetID, "success", ip)
}

// RecordTargetResult records a targeted event with its actual outcome.
func RecordTargetResult(ctx context.Context, store *Store, event string, actorID *uuid.UUID, actorName, targetType, targetID, result, ip string) {
	entry := &models.AuditLog{
		ID:         uuid.New(),
		Event:      event,
		ActorID:    actorID,
		ActorName:  &actorName,
		TargetType: &targetType,
		TargetID:   &targetID,
		Result:     result,
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
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
