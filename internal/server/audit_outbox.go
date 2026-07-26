package server

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

func (s *Server) enqueueAuditResult(ctx context.Context, event string, actorID *uuid.UUID, actorName, result, riskLevel, ip, userAgent string, details map[string]any) {
	if s == nil || s.auditStore == nil {
		return
	}
	err := audit.EnqueueResult(ctx, s.auditStore, event, actorID, actorName, result, riskLevel, ip, userAgent, details)
	s.reportAuditProducerFailure(ctx, event, result, err)
}

func (s *Server) enqueueAuditTargetResult(ctx context.Context, event string, actorID *uuid.UUID, actorName, targetType, targetID, result, riskLevel, ip, userAgent string, details map[string]any) {
	if s == nil || s.auditStore == nil {
		return
	}
	err := audit.EnqueueTargetResult(ctx, s.auditStore, event, actorID, actorName, targetType, targetID, result, riskLevel, ip, userAgent, details)
	s.reportAuditProducerFailure(ctx, event, result, err)
}

func (s *Server) enqueueAuditLog(ctx context.Context, entry *models.AuditLog) {
	if s == nil || s.auditStore == nil || entry == nil {
		return
	}
	err := audit.EnqueueLog(ctx, s.auditStore, entry)
	s.reportAuditProducerFailure(ctx, entry.Event, entry.Result, err)
}

func (s *Server) reportAuditProducerFailure(ctx context.Context, event, result string, err error) {
	if err == nil {
		return
	}
	s.telemetry.RecordAuditFailure(ctx, event)
	slog.ErrorContext(ctx, "audit outbox enqueue failed", "event", event, "result", result, "error", err)
}
