package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/pkg/models"
)

type adminAuditLog struct {
	ID         uuid.UUID              `json:"id"`
	Event      string                 `json:"event"`
	ActorID    *uuid.UUID             `json:"actor_id,omitempty"`
	ActorName  *string                `json:"actor_name,omitempty"`
	TargetType *string                `json:"target_type,omitempty"`
	TargetID   *string                `json:"target_id,omitempty"`
	IPAddress  *string                `json:"ip_address,omitempty"`
	UserAgent  *string                `json:"user_agent,omitempty"`
	Result     string                 `json:"result"`
	RiskLevel  string                 `json:"risk_level"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	filter, err := auditLogFilterFromRequest(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	items, err := s.auditStore.List(r.Context(), page, pageSize, filter)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}
	writeJSON(w, http.StatusOK, adminAuditLogPage(items))
}

func (s *Server) handleAuditLogOptions(w http.ResponseWriter, _ *http.Request) {
	setSessionNoStoreHeaders(w)
	writeJSON(w, http.StatusOK, audit.KnownFilterOptions())
}

func auditLogFilterFromRequest(r *http.Request) (audit.ListFilter, error) {
	query := r.URL.Query()
	filter := audit.ListFilter{
		Event: query.Get("event"), Result: query.Get("result"), RiskLevel: query.Get("risk"),
		Actor: query.Get("actor"), Target: query.Get("target"), TargetType: query.Get("target_type"),
		TargetID: query.Get("target_id"), IPAddress: query.Get("ip"),
	}
	if raw := strings.TrimSpace(query.Get("subject_user_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return filter, fmt.Errorf("subject_user_id must be a UUID")
		}
		filter.SubjectUserID = &id
	}
	if raw := strings.TrimSpace(query.Get("from")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, fmt.Errorf("from must be RFC3339")
		}
		parsed = parsed.UTC()
		filter.CreatedFrom = &parsed
	}
	if raw := strings.TrimSpace(query.Get("to")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return filter, fmt.Errorf("to must be RFC3339")
		}
		parsed = parsed.UTC()
		filter.CreatedTo = &parsed
	}
	if filter.CreatedFrom != nil && filter.CreatedTo != nil && !filter.CreatedTo.After(*filter.CreatedFrom) {
		return filter, fmt.Errorf("to must be later than from")
	}
	return filter, nil
}

func adminAuditLogPage(items *models.PaginatedResponse[models.AuditLog]) *models.PaginatedResponse[adminAuditLog] {
	result := &models.PaginatedResponse[adminAuditLog]{
		Items: make([]adminAuditLog, 0, len(items.Items)), Total: items.Total,
		Page: items.Page, PageSize: items.PageSize, TotalPages: items.TotalPages,
	}
	for index := range items.Items {
		result.Items = append(result.Items, adminAuditLogFromModel(items.Items[index]))
	}
	return result
}

func adminAuditLogFromModel(item models.AuditLog) adminAuditLog {
	return adminAuditLog{
		ID: item.ID, Event: item.Event, ActorID: item.ActorID, ActorName: item.ActorName,
		TargetType: item.TargetType, TargetID: item.TargetID, IPAddress: item.IPAddress,
		UserAgent: item.UserAgent, Result: item.Result, RiskLevel: item.RiskLevel,
		Details: audit.RedactDetails(item.Details), CreatedAt: item.CreatedAt,
	}
}
