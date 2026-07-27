package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

type adminUserAuthorization struct {
	ID         uuid.UUID  `json:"id"`
	ClientID   string     `json:"client_id"`
	ClientName string     `json:"client_name"`
	Scopes     []string   `json:"scopes"`
	GrantedAt  time.Time  `json:"granted_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

type adminUserClientSummary struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	IsPublic         bool       `json:"is_public"`
	AccessPolicy     string     `json:"access_policy"`
	Grants           []string   `json:"grants"`
	Scopes           []string   `json:"scopes"`
	SecretHint       *string    `json:"secret_hint,omitempty"`
	SecretLastUsedAt *time.Time `json:"secret_last_used_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type adminUserActivity struct {
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

func adminUserInsightsID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return uuid.Nil, false
	}
	return id, true
}

func adminUserInsightsPagination(r *http.Request) (int, int) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	pagination := models.NewPagination(page, pageSize)
	return pagination.Page, pagination.PageSize
}

func (s *Server) requireAdminInsightsUser(w http.ResponseWriter, r *http.Request, id uuid.UUID) (*models.User, bool) {
	current, err := s.userService.GetByID(r.Context(), id)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusNotFound, "user not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to load user")
		}
		return nil, false
	}
	return current, true
}

func (s *Server) handleAdminUserOverview(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	id, ok := adminUserInsightsID(w, r)
	if !ok {
		return
	}
	overview, err := s.userService.GetAdminOverview(r.Context(), id)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusNotFound, "user not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to load user overview")
		}
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (s *Server) handleAdminUserSecurity(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	id, ok := adminUserInsightsID(w, r)
	if !ok {
		return
	}
	security, err := s.userService.GetAdminSecurity(r.Context(), id)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusNotFound, "user not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to load user security")
		}
		return
	}
	policy := s.settingsMgr.Security()
	security.TOTPAvailable = policy.TOTPEnabled
	security.PasskeysAvailable = policy.PasskeysEnabled
	security.MFARequiredForAdmin = policy.RequireMFAForAdmins &&
		security.UserRole == "admin" && security.UserStatus == models.UserStatusActive
	security.MFARequirementSatisfied = !security.MFARequiredForAdmin ||
		security.TOTPEnrolled || security.PasskeysEnrolled > 0
	writeJSON(w, http.StatusOK, security)
}

func (s *Server) handleAdminUserAuthorizations(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	id, ok := adminUserInsightsID(w, r)
	if !ok {
		return
	}
	if _, ok := s.requireAdminInsightsUser(w, r, id); !ok {
		return
	}
	items, err := s.authorizationStore.ListByUser(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load user authorizations")
		return
	}
	active := make([]adminUserAuthorization, 0, len(items))
	for index := range items {
		revoked, checkErr := s.sessionStore.IsUserClientAuthorizationRevoked(
			r.Context(), id.String(), items[index].ClientID, items[index].GrantedAt.UnixMicro(),
		)
		if checkErr != nil {
			writeAPIError(w, http.StatusServiceUnavailable, "user authorizations temporarily unavailable")
			return
		}
		if revoked {
			continue
		}
		active = append(active, adminUserAuthorization{
			ID: items[index].ID, ClientID: items[index].ClientID, ClientName: items[index].ClientName,
			Scopes: items[index].Scopes, GrantedAt: items[index].GrantedAt, LastUsedAt: items[index].LastUsedAt,
		})
	}
	writeJSON(w, http.StatusOK, active)
}

func (s *Server) handleAdminUserClients(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	id, ok := adminUserInsightsID(w, r)
	if !ok {
		return
	}
	if _, ok := s.requireAdminInsightsUser(w, r, id); !ok {
		return
	}
	page, pageSize := adminUserInsightsPagination(r)
	items, err := s.clientService.ListByOwner(r.Context(), id.String(), page, pageSize)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load user clients")
		return
	}
	result := &models.PaginatedResponse[adminUserClientSummary]{
		Items: make([]adminUserClientSummary, 0, len(items.Items)), Total: items.Total,
		Page: items.Page, PageSize: items.PageSize, TotalPages: items.TotalPages,
	}
	for index := range items.Items {
		item := items.Items[index]
		result.Items = append(result.Items, adminUserClientSummary{
			ID: item.ID, Name: item.Name, IsPublic: item.IsPublic, AccessPolicy: item.AccessPolicy,
			Grants: item.Grants, Scopes: item.Scopes, SecretHint: item.SecretHint,
			SecretLastUsedAt: item.SecretLastUsedAt, CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAdminUserActivity(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	id, ok := adminUserInsightsID(w, r)
	if !ok {
		return
	}
	if _, ok := s.requireAdminInsightsUser(w, r, id); !ok {
		return
	}
	page, pageSize := adminUserInsightsPagination(r)
	items, err := s.auditStore.List(r.Context(), page, pageSize, audit.ListFilter{SubjectUserID: &id})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to load user activity")
		return
	}
	result := &models.PaginatedResponse[adminUserActivity]{
		Items: make([]adminUserActivity, 0, len(items.Items)), Total: items.Total,
		Page: items.Page, PageSize: items.PageSize, TotalPages: items.TotalPages,
	}
	for index := range items.Items {
		item := items.Items[index]
		result.Items = append(result.Items, adminUserActivity{
			ID: item.ID, Event: item.Event, ActorID: item.ActorID, ActorName: item.ActorName,
			TargetType: item.TargetType, TargetID: item.TargetID, IPAddress: item.IPAddress,
			UserAgent: item.UserAgent, Result: item.Result, RiskLevel: item.RiskLevel,
			Details: audit.RedactDetails(item.Details), CreatedAt: item.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, result)
}
