package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/deviceauthorization"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
)

const deviceConsentTTL = 10 * time.Minute

func (h *Handler) DeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	if h.deviceStore == nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "device authorization is temporarily unavailable")
		return
	}
	if err := parseOAuthForm(w, r); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	cl, clientID, ok := h.authenticateTokenClient(r, "", true)
	if !ok {
		writeInvalidClient(w)
		return
	}
	if !cl.HasGrant(models.GrantDeviceCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "device authorization grant is not allowed")
		return
	}
	scopes, err := parseAndValidateScopes(r.Form.Get("scope"), cl.Scopes)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed")
		return
	}
	if r.Form.Get("scope") == "" {
		scopes = append([]string(nil), cl.Scopes...)
	}
	if containsScope(scopes, "offline_access") && !cl.HasGrant(models.GrantRefreshToken) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "offline_access requires refresh_token")
		return
	}
	optionalScopes := intersectScopes(scopes, cl.OptionalScopes)
	if len(scopes) > 0 && len(optionalScopes) == len(scopes) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "at least one requested scope must be required")
		return
	}
	if retry, err := h.deviceStore.ReserveInitiation(r.Context(), clientID, h.requestClientAddress(r)); err != nil {
		if errors.Is(err, deviceauthorization.ErrRateLimited) {
			writeRetryAfter(w, retry)
			writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "too many device authorization requests")
		} else {
			writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "device authorization is temporarily unavailable")
		}
		return
	}
	created, err := h.deviceStore.Create(r.Context(), deviceauthorization.CreateInput{
		ClientID: clientID, Scopes: scopes, OptionalScopes: optionalScopes,
		ScopeClaims:            scopeClaimsForClient(scopes, cl, h.oauthPolicy()),
		ClientIdentityRevision: cl.IdentityRevision, ClientAuthorizationRevision: cl.AuthorizationRevision,
	})
	if err != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "device authorization is temporarily unavailable")
		return
	}
	issuer := strings.TrimRight(h.config.Auth.Issuer, "/")
	verificationURI := issuer + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               created.DeviceCode,
		"user_code":                 created.UserCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(created.UserCode),
		"expires_in":                int(deviceauthorization.DefaultTTL / time.Second),
		"interval":                  int(deviceauthorization.DefaultInterval / time.Second),
	})
}

func (h *Handler) PrepareDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	if h.deviceStore == nil {
		writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
		return
	}
	var request struct {
		UserCode string `json:"user_code"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || deviceauthorization.NormalizeUserCode(request.UserCode) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	sess, currentUser := h.currentSessionUser(w, r)
	if sess == nil || currentUser == nil {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	if retry, err := h.deviceStore.ReserveVerification(r.Context(), currentUser.ID.String(), h.requestClientAddress(r)); err != nil {
		if errors.Is(err, deviceauthorization.ErrRateLimited) {
			writeRetryAfter(w, retry)
			writeError(w, http.StatusTooManyRequests, "too_many_device_verification_attempts")
		} else {
			writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
		}
		return
	}
	pending, err := h.deviceStore.FindPendingByUserCode(r.Context(), request.UserCode)
	if err != nil {
		if errors.Is(err, deviceauthorization.ErrNotFound) {
			writeError(w, http.StatusBadRequest, "invalid_or_expired_user_code")
		} else {
			writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
		}
		return
	}
	cl, err := h.clientStore.GetByID(r.Context(), pending.ClientID)
	if err != nil || !cl.HasGrant(models.GrantDeviceCode) ||
		normalizedClientRevision(pending.ClientIdentityRevision) != cl.IdentityRevision ||
		normalizedClientRevision(pending.ClientAuthorizationRevision) != cl.AuthorizationRevision {
		writeError(w, http.StatusConflict, "client_changed_restart_authorization")
		return
	}
	if _, err := parseAndValidateScopes(joinScopes(pending.Scopes), cl.Scopes); err != nil {
		writeError(w, http.StatusConflict, "client_changed_restart_authorization")
		return
	}
	allowed, err := h.clientStore.UserMayAccess(r.Context(), cl.ID, currentUser.ID.String())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "client_access_denied")
		return
	}
	challenge, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	data := &session.ConsentData{
		Flow: models.GrantDeviceCode, ClientID: cl.ID, UserID: currentUser.ID.String(),
		Scopes: pending.Scopes, OptionalScopes: pending.OptionalScopes, ScopeClaims: pending.ScopeClaims,
		ScopeDetails: scopeDetailsForScopes(pending.Scopes, h.oauthPolicy()), AuthVersion: currentUser.AuthVersion,
		ClientIdentityRevision: cl.IdentityRevision, ClientAuthorizationRevision: cl.AuthorizationRevision,
		DeviceID: pending.DeviceID, DeviceRecordVersion: pending.RecordVersion,
	}
	if err := h.sessionStore.SaveConsent(r.Context(), challenge, data, deviceConsentTTL); err != nil {
		writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"consent_url": "/consent?challenge=" + url.QueryEscape(challenge)})
}

func (h *Handler) handleDeviceCodeGrant(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" || r.Form.Get("scope") != "" {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantDeviceCode, "", "failure", "medium", "invalid_request")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "device_code is required and scope changes are not supported")
		return
	}
	if h.deviceStore == nil {
		writeTokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "device authorization is temporarily unavailable")
		return
	}
	cl, clientID, ok := h.authenticateTokenClient(r, "", true)
	if !ok {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantDeviceCode, clientID, "failure", "medium", "invalid_client")
		writeInvalidClient(w)
		return
	}
	if !cl.HasGrant(models.GrantDeviceCode) {
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "device authorization grant is not allowed")
		return
	}
	approved, retry, err := h.deviceStore.Poll(r.Context(), deviceCode, clientID)
	if err != nil {
		switch {
		case errors.Is(err, deviceauthorization.ErrAuthorizationPending):
			writeRetryAfter(w, retry)
			writeTokenError(w, http.StatusBadRequest, "authorization_pending", "the user has not completed authorization")
		case errors.Is(err, deviceauthorization.ErrSlowDown):
			writeRetryAfter(w, retry)
			writeTokenError(w, http.StatusBadRequest, "slow_down", "polling is too frequent")
		case errors.Is(err, deviceauthorization.ErrAccessDenied):
			writeTokenError(w, http.StatusBadRequest, "access_denied", "the user denied the authorization request")
		case errors.Is(err, deviceauthorization.ErrNotFound):
			writeTokenError(w, http.StatusBadRequest, "expired_token", "device code is invalid or expired")
		default:
			writeTokenError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "device authorization is temporarily unavailable")
		}
		return
	}
	if normalizedClientRevision(approved.ClientIdentityRevision) != cl.IdentityRevision ||
		normalizedClientRevision(approved.ClientAuthorizationRevision) != cl.AuthorizationRevision {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization is no longer valid")
		return
	}
	if _, err := parseAndValidateScopes(joinScopes(approved.GrantedScopes), cl.Scopes); err != nil {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization scope is no longer allowed")
		return
	}
	currentClaims := claimsForGrantedScopes(approved.GrantedScopes, scopeClaimsForClient(approved.GrantedScopes, cl, h.oauthPolicy()))
	if !scopesAreSubset(approved.AllowedClaims, currentClaims) {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization claims are no longer allowed")
		return
	}
	userID, err := uuid.Parse(approved.UserID)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization subject is invalid")
		return
	}
	currentUser, err := h.userService.GetByID(r.Context(), userID)
	if err != nil || currentUser.Status != models.UserStatusActive || currentUser.AuthVersion != approved.AuthVersion {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization subject is no longer active")
		return
	}
	if err := h.deviceStore.ConsumeApproved(r.Context(), approved); err != nil {
		writeTokenError(w, http.StatusBadRequest, "expired_token", "device authorization is invalid or expired")
		return
	}
	issueRefresh := containsScope(approved.GrantedScopes, "offline_access") && cl.HasGrant(models.GrantRefreshToken)
	pair, err := h.tokenService.GenerateAuthorizationCodeTokenPairAtRevisionWithClaims(
		r.Context(), cl.ID, approved.UserID, approved.GrantedScopes, approved.AllowedClaims,
		approved.AuthVersion, approved.AuthorizationIssuedAt, approved.ClientAuthorizationRevision, issueRefresh,
	)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			writeTokenError(w, http.StatusBadRequest, "expired_token", "authorization is no longer active")
		} else {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		}
		return
	}
	if containsScope(approved.GrantedScopes, "openid") {
		pair.IDToken, err = h.tokenService.GenerateIDTokenWithClaims(
			r.Context(), cl.ID, approved.UserID, approved.GrantedScopes, approved.AllowedClaims, "",
			h.userClaimsForAllowed(currentUser, approved.AllowedClaims),
		)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue ID token")
			return
		}
	}
	h.recordGrantAudit(r.Context(), models.AuditTokenIssued, models.GrantDeviceCode, cl.ID, "success", "low", "")
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) requestClientAddress(r *http.Request) string {
	if h.clientAddress != nil {
		if value := strings.TrimSpace(h.clientAddress(r)); value != "" {
			return value
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func writeRetryAfter(w http.ResponseWriter, retry time.Duration) {
	seconds := int(retry.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
}
