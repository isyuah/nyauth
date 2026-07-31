package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

func isRecentAuthentication(authenticatedAt, now time.Time, configuredTTL ...time.Duration) bool {
	ttl := account.DefaultReauthenticationTTL
	if len(configuredTTL) > 0 && configuredTTL[0] > 0 {
		ttl = configuredTTL[0]
	}
	if authenticatedAt.IsZero() || authenticatedAt.After(now.Add(time.Minute)) {
		return false
	}
	return now.Sub(authenticatedAt) <= ttl
}

func (s *Server) recentAuthenticationTTL() time.Duration {
	if s.settingsMgr == nil {
		return account.DefaultReauthenticationTTL
	}
	return s.settingsMgr.Lifecycle().RecentAuthenticationDuration()
}

func (s *Server) requireRecentAuthentication(w http.ResponseWriter, r *http.Request) bool {
	authenticated := sessionFromContext(r.Context())
	if authenticated == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return false
	}
	if !isRecentAuthentication(authenticated.Data.AuthenticatedAt, time.Now().UTC(), s.recentAuthenticationTTL()) {
		writeAPIError(w, http.StatusForbidden, "recent authentication is required")
		return false
	}
	return true
}

func (s *Server) recentAuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireRecentAuthentication(w, r) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handlePasswordReauthentication(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	verified, err := s.userService.VerifyPasswordForReauthentication(r.Context(), current.ID, request.Password)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrPasswordUnavailable):
			writeAPIError(w, http.StatusConflict, "password reauthentication is unavailable")
		case errors.Is(err, user.ErrInvalidCredentials):
			writeAPIError(w, http.StatusUnauthorized, "invalid credentials")
		default:
			writeAPIError(w, http.StatusInternalServerError, "reauthentication failed")
		}
		return
	}
	mfaResponse, mfaRequired, err := s.beginReauthenticationMFAPending(w, r, verified, "password", "", "/profile")
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "MFA verification temporarily unavailable")
		return
	}
	if mfaRequired {
		writeJSON(w, http.StatusAccepted, mfaResponse)
		return
	}
	updated, err := s.userService.RecordAuthentication(
		r.Context(), current.ID, verified.AuthVersion, verified.SessionVersion,
	)
	if err != nil {
		if errors.Is(err, user.ErrAuthStateChanged) {
			writeAPIError(w, http.StatusUnauthorized, "account changed; sign in again")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "reauthentication failed")
		}
		return
	}
	authenticated, err := s.sessionMiddleware.MarkReauthenticated(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "reauthentication session could not be updated")
		return
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditUserReauthenticated, &current.ID, current.Username, "user", current.ID.String(), "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "password"})
	s.telemetry.RecordAuthEvent(r.Context(), "reauthentication", "success")
	writeJSON(w, http.StatusOK, sessionResponse(updated, authenticated.Data))
}

func (s *Server) handleSetPassword(w http.ResponseWriter, r *http.Request) {
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
	var request struct {
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.userService.SetPassword(r.Context(), current.ID, request.NewPassword, mutation)
	if err != nil {
		switch {
		case errors.Is(err, user.ErrPasswordConfigured):
			writeAPIError(w, http.StatusConflict, "a local password is already configured")
		case user.IsInvalidInput(err):
			writeAPIError(w, http.StatusBadRequest, err.Error())
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to set password")
		}
		return
	}
	s.revokeUserSecurityState(r.Context(), current.ID, "password_set")
	rotated, err := s.sessionMiddleware.RotateSession(w, r, updated)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "password set; please sign in again")
		return
	}
	writeJSON(w, http.StatusOK, sessionResponse(updated, rotated.Data))
}
