package server

import (
	"errors"
	"net/http"

	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
)

type protectionSettingsResponse struct {
	Revision int64 `json:"revision"`
	settings.Protection
}

type updateProtectionSettingsRequest struct {
	ExpectedRevision    int64  `json:"expected_revision"`
	DisableConfirmation string `json:"disable_confirmation,omitempty"`
	settings.Protection
}

type lifecycleSettingsResponse struct {
	Revision int64 `json:"revision"`
	settings.Lifecycle
}

type updateLifecycleSettingsRequest struct {
	ExpectedRevision      int64  `json:"expected_revision"`
	RetentionConfirmation string `json:"retention_confirmation,omitempty"`
	settings.Lifecycle
}

type oauthSettingsResponse struct {
	Revision int64 `json:"revision"`
	settings.OAuthPolicy
}

type updateOAuthSettingsRequest struct {
	ExpectedRevision int64 `json:"expected_revision"`
	settings.OAuthPolicy
}

func (s *Server) handleGetProtectionSettings(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.settingsMgr.ProtectionSnapshot()
	writeJSON(w, http.StatusOK, protectionSettingsResponse{Revision: snapshot.Revision, Protection: snapshot.Value})
}

func (s *Server) handleUpdateProtectionSettings(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateProtectionSettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := settings.ValidateProtection(request.Protection); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, err := s.settingsMgr.SetProtection(
		r.Context(), request.Protection, request.ExpectedRevision, current.Username,
		request.DisableConfirmation, mutation,
	)
	if err != nil {
		switch {
		case errors.Is(err, settings.ErrRevisionConflict):
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
		case errors.Is(err, settings.ErrProtectionDisableConfirmation):
			writeAPIError(w, http.StatusBadRequest, "rate limit disable confirmation is required")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to store protection settings")
		}
		return
	}
	writeJSON(w, http.StatusOK, protectionSettingsResponse{Revision: revision, Protection: request.Protection})
}

func (s *Server) handleGetLifecycleSettings(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.settingsMgr.LifecycleSnapshot()
	writeJSON(w, http.StatusOK, lifecycleSettingsResponse{Revision: snapshot.Revision, Lifecycle: snapshot.Value})
}

func (s *Server) handleUpdateLifecycleSettings(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateLifecycleSettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := settings.ValidateLifecycle(request.Lifecycle); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, err := s.settingsMgr.SetLifecycle(
		r.Context(), request.Lifecycle, request.ExpectedRevision, current.Username,
		request.RetentionConfirmation, mutation,
	)
	if err != nil {
		switch {
		case errors.Is(err, settings.ErrRevisionConflict):
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
		case errors.Is(err, settings.ErrRetentionConfirmation):
			writeAPIError(w, http.StatusBadRequest, "audit retention confirmation is required")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to store lifecycle settings")
		}
		return
	}
	writeJSON(w, http.StatusOK, lifecycleSettingsResponse{Revision: revision, Lifecycle: request.Lifecycle})
}

func (s *Server) handleGetOAuthSettings(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.settingsMgr.OAuthPolicySnapshot()
	writeJSON(w, http.StatusOK, oauthSettingsResponse{Revision: snapshot.Revision, OAuthPolicy: snapshot.Value})
}

func (s *Server) handleUpdateOAuthSettings(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
		return
	}
	var request updateOAuthSettingsRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	value, err := settings.NormalizeOAuthPolicyUpdate(request.OAuthPolicy)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	revision, err := s.settingsMgr.SetOAuthPolicy(
		r.Context(), value, request.ExpectedRevision, current.Username, mutation,
	)
	if err != nil {
		switch {
		case errors.Is(err, settings.ErrRevisionConflict):
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
		default:
			writeAPIError(w, http.StatusInternalServerError, "failed to store OAuth settings")
		}
		return
	}
	writeJSON(w, http.StatusOK, oauthSettingsResponse{Revision: revision, OAuthPolicy: s.settingsMgr.OAuthPolicySnapshot().Value})
}

func (s *Server) authorizePolicySettingsMutation(
	w http.ResponseWriter,
	r *http.Request,
) (*models.User, audit.MutationAudit, bool) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return nil, audit.MutationAudit{}, false
	}
	if !s.requireRecentAuthentication(w, r) {
		return nil, audit.MutationAudit{}, false
	}
	if s.policySettingsLimiter == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "settings are temporarily unavailable")
		return nil, audit.MutationAudit{}, false
	}
	allowed, retry, err := s.policySettingsLimiter.Reserve(r.Context(), requestIP(r), current.ID.String())
	if err != nil {
		s.telemetry.RecordRateLimit(r.Context(), "settings", "update", "error")
		writeAPIError(w, http.StatusServiceUnavailable, "settings are temporarily unavailable")
		return nil, audit.MutationAudit{}, false
	}
	if !allowed {
		s.telemetry.RecordRateLimit(r.Context(), "settings", "update", "rejected")
		w.Header().Set("Retry-After", retryAfterSeconds(retry))
		writeAPIError(w, http.StatusTooManyRequests, "too many settings operations")
		return nil, audit.MutationAudit{}, false
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return nil, audit.MutationAudit{}, false
	}
	return current, mutation, true
}
