package server

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

type browserSessionResponse struct {
	ID              string    `json:"id"`
	Current         bool      `json:"current"`
	IPAddress       string    `json:"ip_address,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}

func mapBrowserSessions(items []session.SessionData, currentPublicID string) []browserSessionResponse {
	result := make([]browserSessionResponse, 0, len(items))
	for _, item := range items {
		result = append(result, browserSessionResponse{
			ID: item.PublicID, Current: item.PublicID == currentPublicID,
			IPAddress: item.IPAddress, UserAgent: item.UserAgent,
			CreatedAt: item.CreatedAt, LastSeenAt: item.LastSeenAt, AuthenticatedAt: item.AuthenticatedAt,
		})
	}
	return result
}

func (s *Server) handleListMySessions(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	items, err := s.sessionStore.ListUserSessions(r.Context(), current.ID.String())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to list sessions")
		return
	}
	writeJSON(w, http.StatusOK, mapBrowserSessions(items, authenticated.Data.PublicID))
}

func (s *Server) handleDeleteMySession(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	publicID := chi.URLParam(r, "id")
	if err := s.sessionStore.DeleteUserSessionByPublicID(r.Context(), current.ID.String(), publicID); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "session not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "failed to revoke session")
		}
		return
	}
	if publicID == authenticated.Data.PublicID {
		s.sessionMiddleware.clearCookie(w)
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditSessionRevoked, &current.ID, current.Username, "session", publicID, "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	count, err := s.sessionStore.DeleteOtherUserSessions(r.Context(), current.ID.String(), authenticated.ID)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to revoke sessions")
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditSessionOthersRevoked, &current.ID, current.Username, "user", current.ID.String(), "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"revoked_count": count})
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": count})
}

func (s *Server) handleAdminListUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	if _, err := s.userService.GetByID(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	items, err := s.sessionStore.ListUserSessions(r.Context(), id.String())
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to list sessions")
		return
	}
	currentPublicID := ""
	if actor != nil && actor.ID == id && authenticated != nil {
		currentPublicID = authenticated.Data.PublicID
	}
	writeJSON(w, http.StatusOK, mapBrowserSessions(items, currentPublicID))
}

func (s *Server) handleAdminDeleteUserSession(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	if _, err := s.userService.GetByID(r.Context(), id); err != nil {
		writeAPIError(w, http.StatusNotFound, "user not found")
		return
	}
	publicID := chi.URLParam(r, "session_id")
	if err := s.sessionStore.DeleteUserSessionByPublicID(r.Context(), id.String(), publicID); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "session not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "failed to revoke session")
		}
		return
	}
	if actor != nil && actor.ID == id && authenticated != nil && publicID == authenticated.Data.PublicID {
		s.sessionMiddleware.clearCookie(w)
	}
	if actor != nil {
		s.enqueueAuditTargetResult(r.Context(), models.AuditSessionRevoked, &actor.ID, actor.Username, "user", id.String(), "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"session_id": publicID})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAdminRevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	sessionVersion, err := s.userService.RevokeSessions(r.Context(), id, mutation)
	if err != nil {
		if user.IsNotFound(err) {
			writeAPIError(w, http.StatusNotFound, "user not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to revoke sessions")
		}
		return
	}
	count, cleanupErr := s.sessionStore.DeleteUserSessionsBeforeVersion(r.Context(), id.String(), sessionVersion)
	if cleanupErr != nil {
		slog.WarnContext(r.Context(), "stale user session cleanup failed", "operation", "admin_session_revoke", "error_class", "redis_error")
	}
	if actor != nil && actor.ID == id {
		s.sessionMiddleware.DestroySession(w, r)
	}
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": count})
}
