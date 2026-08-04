package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/notification"
)

func (s *Server) handleDeleteMyIdentity(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if current == nil || authenticated == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if !isRecentAuthentication(authenticated.Data.AuthenticatedAt, time.Now().UTC(), s.recentAuthenticationTTL()) {
		writeAPIError(w, http.StatusForbidden, "recent authentication is required")
		return
	}
	identityID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid identity ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := s.identityStore.DeleteOwned(r.Context(), current.ID, identityID, mutation); err != nil {
		switch {
		case errors.Is(err, identity.ErrLastAuthenticationMethod):
			writeAPIError(w, http.StatusConflict, "cannot remove the last authentication method")
		case identity.IsNotFound(err):
			writeAPIError(w, http.StatusNotFound, "identity not found")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to remove identity")
		}
		return
	}
	s.notifySecurityChange(r.Context(), current.ID, notification.TypeIdentityChanged, "外部身份已解绑", "您的账户已解绑一个外部身份提供商。", "/profile/identities")
	updated, err := s.userService.GetByID(r.Context(), current.ID)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "identity removed; please sign in again")
		return
	}
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "identity removed; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, rotated.Data))
}
