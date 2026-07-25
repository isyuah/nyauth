package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const maxRequestBody = 1 << 20
const maxClientsPerUser = 10

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("request body must contain one JSON value")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeAPIError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func sessionResponse(current *models.User, dataCSRF string) *models.SessionResponse {
	return &models.SessionResponse{User: current, CSRFToken: dataCSRF, MustChangePassword: current.MustChangePassword}
}

func setSessionNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	if !s.validSameOriginRequest(r) {
		writeAPIError(w, http.StatusForbidden, "invalid request origin")
		return
	}
	var request models.LoginRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	ip := requestIP(r)
	allowed, retry, err := s.loginLimiter.Reserve(r.Context(), ip, strings.ToLower(request.Username))
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "login temporarily unavailable")
		return
	}
	if !allowed {
		seconds := int64((retry + time.Second - 1) / time.Second)
		w.Header().Set("Retry-After", strconv.FormatInt(seconds, 10))
		writeAPIError(w, http.StatusTooManyRequests, "too many login attempts")
		return
	}
	current, err := s.userService.Authenticate(r.Context(), request.Username, request.Password)
	if err != nil {
		audit.RecordResult(r.Context(), s.auditStore, models.AuditUserLoginFailed, nil, request.Username, "failure", ip)
		writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	authenticated, err := s.sessionMiddleware.CreateSession(w, r, current)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	_ = s.loginLimiter.ResetIdentity(r.Context(), ip, strings.ToLower(request.Username))
	audit.RecordResult(r.Context(), s.auditStore, models.AuditUserLogin, &current.ID, current.Username, "success", ip)
	_ = s.userService.RecordLogin(r.Context(), current.ID, ip)
	writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data.CSRFToken))
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if current == nil || authenticated == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(current, authenticated.Data.CSRFToken))
}
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionMiddleware.DestroySession(w, r)
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, current)
}
func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request models.UpdateUserRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.userService.Update(r.Context(), current.ID, request)
	if err != nil {
		if user.IsInvalidInput(err) {
			writeAPIError(w, http.StatusBadRequest, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update profile")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request models.ChangePasswordRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	updated, err := s.userService.ChangePassword(r.Context(), current.ID, request.CurrentPassword, request.NewPassword)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrInvalidCredentials):
			writeAPIError(w, http.StatusUnauthorized, "current password is incorrect")
		case errors.Is(err, user.ErrPasswordUnavailable):
			writeAPIError(w, http.StatusConflict, err.Error())
		case user.IsInvalidInput(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to change password")
		}
		return
	}
	authenticated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "password changed; please sign in again")
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, "user.password_changed", &updated.ID, updated.Username, "user", updated.ID.String(), requestIP(r))
	writeJSON(w, http.StatusOK, sessionResponse(updated, authenticated.Data.CSRFToken))
}

func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.providerMgr.List())
}
func (s *Server) handleMyIdentities(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	items, err := s.identityStore.ListByUser(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleUserIdentities(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	items, err := s.identityStore.ListByUser(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}
	writeJSON(w, http.StatusOK, items)
}
func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatus(w, r, models.UserStatusSuspended, models.AuditUserSuspended)
}
func (s *Server) handleActivateUser(w http.ResponseWriter, r *http.Request) {
	s.handleUserStatus(w, r, models.UserStatusActive, models.AuditUserActivated)
}
func (s *Server) handleUserStatus(w http.ResponseWriter, r *http.Request, status models.UserStatus, event string) {
	actor := currentUserFromContext(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	updated, err := s.userService.AdminUpdate(r.Context(), id, models.AdminUpdateUserRequest{Status: &status})
	if err != nil {
		if errors.Is(err, user.ErrLastActiveAdmin) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update user status")
		}
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, event, &actor.ID, actor.Username, "user", id.String(), requestIP(r))
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	var request struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &request); err != nil || (request.Role != "admin" && request.Role != "user") {
		writeAPIError(w, http.StatusBadRequest, "role must be admin or user")
		return
	}
	updated, err := s.userService.AdminUpdate(r.Context(), id, models.AdminUpdateUserRequest{Role: &request.Role})
	if err != nil {
		if errors.Is(err, user.ErrLastActiveAdmin) {
			writeAPIError(w, http.StatusConflict, err.Error())
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to update role")
		}
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, "user.role_changed", &actor.ID, actor.Username, "user", id.String(), requestIP(r))
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	result, err := s.auditStore.List(r.Context(), page, pageSize, r.URL.Query().Get("event"))
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list audit logs")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleListMyClients(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	result, err := s.clientService.ListByOwner(r.Context(), current.ID.String(), 1, 50)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list applications")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
func (s *Server) handleCreateMyClient(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	var request models.CreateClientRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	result, err := s.clientService.CreateForOwner(r.Context(), current.ID.String(), maxClientsPerUser, request)
	if err != nil {
		switch {
		case errors.Is(err, client.ErrClientQuotaExceeded):
			writeAPIError(w, http.StatusForbidden, fmt.Sprintf("application limit reached (%d)", maxClientsPerUser))
		case client.IsInvalidClient(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to create application")
		}
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditClientCreated, &current.ID, current.Username, "client", result.ID, requestIP(r))
	writeJSON(w, http.StatusCreated, result)
}
func (s *Server) handleDeleteMyClient(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	id := chi.URLParam(r, "id")
	registered, err := s.clientService.GetByID(r.Context(), id)
	if err != nil {
		writeAPIError(w, http.StatusNotFound, "application not found")
		return
	}
	if registered.OwnerID == nil || *registered.OwnerID != current.ID.String() {
		writeAPIError(w, http.StatusForbidden, "application is not owned by current user")
		return
	}
	if err := s.clientService.Delete(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to delete application")
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditClientDeleted, &current.ID, current.Username, "client", id, requestIP(r))
	w.WriteHeader(http.StatusNoContent)
}
