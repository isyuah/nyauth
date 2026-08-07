package server

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/nyasharp/nyauth/internal/oauthstepup"
	"github.com/nyasharp/nyauth/internal/session"
)

func (s *Server) handleConsentStepUp(w http.ResponseWriter, r *http.Request) {
	setSessionNoStoreHeaders(w)
	current := currentUserFromContext(r)
	authenticated := sessionFromContext(r.Context())
	if current == nil || authenticated == nil || authenticated.Data == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request struct {
		Challenge string `json:"challenge"`
	}
	if err := decodeJSON(w, r, &request); err != nil || request.Challenge == "" {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	data, err := s.sessionStore.GetConsent(r.Context(), request.Challenge)
	if err != nil || data.UserID != current.ID.String() || data.AuthVersion != current.AuthVersion {
		writeAPIError(w, http.StatusBadRequest, "invalid or expired authorization request")
		return
	}
	returnTo := "/consent?challenge=" + url.QueryEscape(request.Challenge)
	context := oauthstepup.NormalizeContext(authenticated.Data.AuthenticationContext)
	if context.Satisfies(data.RequiredAuthContext) && consentMaxAgeSatisfied(data) {
		writeJSON(w, http.StatusOK, map[string]string{"redirect_url": returnTo})
		return
	}
	if !consentMaxAgeSatisfied(data) {
		writeAPIError(w, http.StatusConflict, "invalid or expired authorization request")
		return
	}
	response, err := s.beginOAuthStepUpMFAPending(w, r, current, data.RequiredAuthContext, returnTo)
	if err != nil {
		switch {
		case errors.Is(err, errMFAEnrollmentRequired):
			writeAPIError(w, http.StatusConflict, "unmet authentication requirements")
		case errors.Is(err, session.ErrNotFound), errors.Is(err, session.ErrValueMismatch):
			writeAPIError(w, http.StatusUnauthorized, "authentication required")
		default:
			writeAPIError(w, http.StatusServiceUnavailable, "MFA verification temporarily unavailable")
		}
		return
	}
	writeJSON(w, http.StatusAccepted, response)
}

func consentMaxAgeSatisfied(data *session.ConsentData) bool {
	if data == nil {
		return false
	}
	if data.MaxAgeSeconds == nil {
		return true
	}
	return data.MaxAgeSatisfied
}
