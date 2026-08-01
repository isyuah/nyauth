package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/trusteddevice"
	"github.com/nyasharp/nyauth/pkg/models"
)

const trustedDeviceCookieName = "nyauth_trusted_device"

func (s *Server) currentTrustedDeviceToken(r *http.Request) (trusteddevice.Token, error) {
	cookie, err := r.Cookie(trustedDeviceCookieName)
	if err != nil {
		return trusteddevice.Token{}, err
	}
	return trusteddevice.ParseToken(cookie.Value)
}

func (s *Server) setTrustedDeviceCookie(w http.ResponseWriter, token trusteddevice.Token, expiresAt time.Time) {
	now := time.Now().UTC()
	maxAge := int((expiresAt.Sub(now) + time.Second - 1) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: trustedDeviceCookieName, Value: token.String(), Path: "/", HttpOnly: true,
		Secure: s.cfg.Server.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: maxAge, Expires: expiresAt,
	})
}

func (s *Server) clearTrustedDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: trustedDeviceCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.Server.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func (s *Server) useTrustedDevice(w http.ResponseWriter, r *http.Request, current *models.User) bool {
	policy := s.settingsMgr.Security()
	if !policy.TrustedDevicesEnabled {
		if _, err := r.Cookie(trustedDeviceCookieName); err == nil {
			s.clearTrustedDeviceCookie(w)
		}
		return false
	}
	token, err := s.currentTrustedDeviceToken(r)
	if errors.Is(err, http.ErrNoCookie) {
		return false
	}
	if err != nil {
		s.clearTrustedDeviceCookie(w)
		return false
	}
	valid, err := s.trustedDeviceStore.ValidateAndTouch(
		r.Context(), token, current, policy.TrustedDeviceDuration(),
		requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), time.Now().UTC(),
	)
	if err != nil {
		slog.WarnContext(r.Context(), "trusted device validation failed", "error_class", "database_error")
		return false
	}
	if !valid {
		s.clearTrustedDeviceCookie(w)
	}
	return valid
}

func (s *Server) issueTrustedDevice(w http.ResponseWriter, r *http.Request, current *models.User) bool {
	policy := s.settingsMgr.Security()
	if !policy.TrustedDevicesEnabled || policy.TrustedDeviceDuration() <= 0 {
		return false
	}
	replaceID := uuid.Nil
	if token, err := s.currentTrustedDeviceToken(r); err == nil {
		replaceID = token.ID
	}
	mutation := audit.MutationAudit{
		Event: models.AuditTrustedDeviceCreated, ActorID: current.ID, ActorName: current.Username,
		Result: "success", RiskLevel: "medium", IPAddress: requestIP(r),
		UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
	}
	device, token, err := s.trustedDeviceStore.Issue(
		r.Context(), current, requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
		policy.TrustedDeviceDuration(), replaceID, mutation,
	)
	if err != nil {
		slog.WarnContext(r.Context(), "trusted device issuance failed", "error_class", "database_error")
		return false
	}
	s.setTrustedDeviceCookie(w, token, device.ExpiresAt)
	return true
}

func (s *Server) handleListMyLoginHistory(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	items, err := s.auditStore.ListLoginHistory(r.Context(), current.ID, page, pageSize)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to list login history")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) handleListMyTrustedDevices(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	policy := s.settingsMgr.Security()
	currentID := s.validCurrentTrustedDeviceID(w, r, current)
	items, err := s.trustedDeviceStore.List(r.Context(), current, policy.TrustedDeviceDuration(), currentID)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to list trusted devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": policy.TrustedDevicesEnabled, "items": items,
	})
}

func (s *Server) handleDeleteMyTrustedDevice(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid trusted device ID")
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := s.trustedDeviceStore.Revoke(r.Context(), current.ID, id, mutation); err != nil {
		if errors.Is(err, trusteddevice.ErrNotFound) {
			writeAPIError(w, http.StatusNotFound, "trusted device not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "failed to revoke trusted device")
		}
		return
	}
	if token, err := s.currentTrustedDeviceToken(r); err == nil && token.ID == id {
		s.clearTrustedDeviceCookie(w)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleRevokeOtherTrustedDevices(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	keepID := s.validCurrentTrustedDeviceID(w, r, current)
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	count, err := s.trustedDeviceStore.RevokeOthers(r.Context(), current.ID, keepID, mutation)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to revoke trusted devices")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"revoked": count})
}

func (s *Server) validCurrentTrustedDeviceID(w http.ResponseWriter, r *http.Request, current *models.User) uuid.UUID {
	if !s.useTrustedDevice(w, r, current) {
		return uuid.Nil
	}
	token, err := s.currentTrustedDeviceToken(r)
	if err != nil {
		return uuid.Nil
	}
	return token.ID
}
