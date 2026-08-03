package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/deviceauthorization"
	"github.com/nyasharp/nyauth/internal/oauthops"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/pkg/models"
)

type ConsentHandler struct {
	sessionStore       *session.Store
	tokenService       *TokenService
	clientStore        *client.Store
	authorizationStore *authorization.Store
	config             *config.Config
	sessionResolver    BrowserSessionResolver
	deviceStore        *deviceauthorization.Store
	operationSink      OAuthOperationSink
}

type consentPermission struct {
	Scope             string   `json:"scope"`
	DisplayName       string   `json:"display_name"`
	Description       string   `json:"description"`
	RiskLevel         string   `json:"risk_level"`
	Required          bool     `json:"required"`
	Claims            []string `json:"claims"`
	PreviouslyGranted bool     `json:"previously_granted"`
	NewlyRequested    bool     `json:"newly_requested"`
}

type consentDecisionRequest struct {
	Challenge             string    `json:"challenge"`
	GrantedOptionalScopes *[]string `json:"granted_optional_scopes"`
}

var errInvalidConsentScopes = errors.New("invalid consent scope selection")

func (h *ConsentHandler) SetBrowserSessionResolver(resolver BrowserSessionResolver) {
	h.sessionResolver = resolver
}

func (h *ConsentHandler) SetDeviceAuthorizationStore(store *deviceauthorization.Store) {
	h.deviceStore = store
}

func (h *ConsentHandler) SetOAuthOperationSink(sink OAuthOperationSink) {
	h.operationSink = sink
}

func (h *ConsentHandler) recordConsentOperation(ctx context.Context, data *session.ConsentData, outcome oauthops.Outcome, reason oauthops.Reason, scopes []string) {
	if h.operationSink == nil || data == nil || data.ClientID == "" {
		return
	}
	flow, stage := oauthops.FlowAuthorizationCode, oauthops.StageConsent
	if data.Flow == models.GrantDeviceCode {
		flow, stage = oauthops.FlowDeviceAuthorization, oauthops.StageDeviceVerification
	}
	if err := h.operationSink(ctx, oauthops.Event{
		ClientID: data.ClientID, Flow: flow, Stage: stage, Outcome: outcome, Reason: reason,
		RedirectURI: data.RedirectURI, Scopes: scopes,
	}); err != nil {
		slog.ErrorContext(ctx, "OAuth consent operation recording failed",
			"client_id", data.ClientID, "flow", flow, "outcome", outcome, "error", err)
	}
}

func NewConsentHandler(sessionStore *session.Store, tokenService *TokenService, clientStore *client.Store, authorizationStore *authorization.Store, cfg *config.Config) *ConsentHandler {
	return &ConsentHandler{sessionStore: sessionStore, tokenService: tokenService, clientStore: clientStore, authorizationStore: authorizationStore, config: cfg}
}

func (h *ConsentHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	challenge := r.URL.Query().Get("challenge")
	sess, ok := h.authenticatedSession(w, r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication_required")
		return
	}
	data, err := h.sessionStore.GetConsent(r.Context(), challenge)
	if err != nil || data.UserID != sess.UserID {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	if data.Flow == models.GrantDeviceCode {
		if h.deviceStore == nil {
			writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
			return
		}
		if _, err := h.deviceStore.GetPending(r.Context(), data.DeviceID, data.DeviceRecordVersion); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
			return
		}
	}
	cl, err := h.clientStore.GetByID(r.Context(), data.ClientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	if normalizedClientRevision(data.ClientAuthorizationRevision) != cl.AuthorizationRevision || normalizedClientRevision(data.ClientIdentityRevision) != cl.IdentityRevision {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonClientChanged, data.Scopes)
		writeError(w, http.StatusConflict, "client_changed_restart_authorization")
		return
	}
	previousScopes := []string(nil)
	previousClaims := []string(nil)
	previouslyAuthorized := false
	applicationChanged := false
	reauthorizationRequired := false
	newScopes := []string{}
	newClaims := []string{}
	if userID, parseErr := uuid.Parse(data.UserID); parseErr == nil {
		if existing, getErr := h.authorizationStore.GetActive(r.Context(), userID, data.ClientID); getErr == nil {
			previousScopes = existing.Scopes
			previousClaims = existing.AllowedClaims
			previouslyAuthorized = true
			applicationChanged = existing.ClientIdentityRevision != cl.IdentityRevision
			reauthorizationRequired = existing.ClientAuthorizationRevision != cl.AuthorizationRevision
			newScopes = difference(data.Scopes, previousScopes)
			newClaims = difference(claimsForGrantedScopes(data.Scopes, data.ScopeClaims), previousClaims)
		}
	}
	redirectOrigin := ""
	if parsed, parseErr := url.Parse(data.RedirectURI); parseErr == nil && parsed.Scheme != "" && parsed.Host != "" {
		redirectOrigin = parsed.Scheme + "://" + parsed.Host
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge": challenge, "flow": consentFlow(data), "client_name": cl.Name, "client_id": cl.ID,
		"scopes": data.Scopes, "redirect_uri": data.RedirectURI,
		"permissions":     consentPermissionsWithHistory(data.Scopes, data.OptionalScopes, data.ScopeClaims, data.ScopeDetails, previousScopes),
		"redirect_origin": redirectOrigin, "publisher_type": cl.PublisherType,
		"verification_status": cl.PublisherVerification,
		"logo_url":            cl.LogoURL, "homepage_uri": cl.HomepageURI,
		"privacy_policy_uri": cl.PrivacyPolicyURI, "terms_of_service_uri": cl.TermsOfServiceURI,
		"previously_authorized": previouslyAuthorized, "application_changed": applicationChanged,
		"reauthorization_required": reauthorizationRequired,
		"new_scopes":               newScopes, "new_claims": newClaims,
	})
}

func (h *ConsentHandler) AcceptConsent(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	sess, ok := h.authorizeMutation(w, r)
	if !ok {
		writeError(w, http.StatusForbidden, "csrf_validation_failed")
		return
	}
	decision, ok := decodeConsentDecisionRequest(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	data, err := h.sessionStore.ConsumeConsentForUser(r.Context(), decision.Challenge, sess.UserID)
	if err != nil || data.AuthVersion != sess.AuthVersion {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	var pendingDevice *deviceauthorization.Record
	if data.Flow == models.GrantDeviceCode {
		if h.deviceStore == nil {
			writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
			return
		}
		pendingDevice, err = h.deviceStore.GetPending(r.Context(), data.DeviceID, data.DeviceRecordVersion)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
			return
		}
	}
	cl, err := h.clientStore.GetByID(r.Context(), data.ClientID)
	if err != nil || normalizedClientRevision(data.ClientAuthorizationRevision) != cl.AuthorizationRevision || normalizedClientRevision(data.ClientIdentityRevision) != cl.IdentityRevision {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonClientChanged, data.Scopes)
		writeError(w, http.StatusConflict, "client_changed_restart_authorization")
		return
	}
	grantedOptionalScopes := data.OptionalScopes
	if decision.GrantedOptionalScopes != nil {
		grantedOptionalScopes = *decision.GrantedOptionalScopes
	}
	grantedScopes, err := resolveGrantedScopes(data.Scopes, data.OptionalScopes, grantedOptionalScopes)
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonInvalidScopeSelection, data.Scopes)
		writeError(w, http.StatusBadRequest, "invalid_scope_selection")
		return
	}
	grantedClaims := claimsForGrantedScopes(grantedScopes, data.ScopeClaims)
	userID, err := uuid.Parse(data.UserID)
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonInvalidSubject, grantedScopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	authorizationIssuedAt, err := h.sessionStore.AuthorizationIssueTime(r.Context(), data.UserID, data.ClientID, h.authorizationStateTTL())
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := h.authorizationStore.UpsertExpected(r.Context(), userID, data.ClientID, grantedScopes, grantedClaims, time.UnixMicro(authorizationIssuedAt).UTC(), cl.IdentityRevision, cl.AuthorizationRevision); err != nil {
		if errors.Is(err, authorization.ErrClientChanged) {
			h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonClientChanged, grantedScopes)
			writeError(w, http.StatusConflict, "client_changed_restart_authorization")
		} else {
			h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
			writeError(w, http.StatusInternalServerError, "server_error")
		}
		return
	}
	if pendingDevice != nil {
		if err := h.deviceStore.Approve(r.Context(), pendingDevice, data.UserID, data.AuthVersion, grantedScopes, grantedClaims, authorizationIssuedAt); err != nil {
			if errors.Is(err, deviceauthorization.ErrNotFound) || errors.Is(err, deviceauthorization.ErrValueMismatch) {
				h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonExpiredToken, grantedScopes)
				writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
			} else {
				h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
				writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
			}
			return
		}
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeSuccess, oauthops.ReasonNone, grantedScopes)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_url": "/device?status=approved"})
		return
	}
	code, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	authorization := &session.AuthorizationData{
		ClientID: data.ClientID, UserID: data.UserID, RedirectURI: data.RedirectURI, Scopes: grantedScopes,
		AllowedClaims: grantedClaims, ClaimNamesSet: true,
		CodeChallenge: data.CodeChallenge, ChallengeMethod: "S256", Nonce: data.Nonce, AuthVersion: data.AuthVersion,
		AuthorizationIssuedAt:       authorizationIssuedAt,
		ClientAuthorizationRevision: cl.AuthorizationRevision,
	}
	if err := h.sessionStore.SaveAuthorizationCode(r.Context(), code, authorization, h.authorizationCodeTTL()); err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	redirectValues := map[string]string{"code": code, "state": data.State}
	if !slices.Equal(grantedScopes, data.Scopes) {
		redirectValues["scope"] = joinScopes(grantedScopes)
	}
	target, err := addQuery(data.RedirectURI, redirectValues)
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, grantedScopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	h.recordConsentOperation(r.Context(), data, oauthops.OutcomeSuccess, oauthops.ReasonNone, grantedScopes)
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": target})
}

func consentPermissionsWithHistory(scopes, optionalScopes []string, scopeClaims map[string][]string, details map[string]session.ConsentScopeDetails, previousScopes []string) []consentPermission {
	permissions := consentPermissions(scopes, optionalScopes, scopeClaims, details)
	for index := range permissions {
		permissions[index].PreviouslyGranted = slices.Contains(previousScopes, permissions[index].Scope)
		permissions[index].NewlyRequested = len(previousScopes) > 0 && !permissions[index].PreviouslyGranted
	}
	return permissions
}

func difference(values, previous []string) []string {
	result := make([]string, 0)
	for _, value := range values {
		if !slices.Contains(previous, value) {
			result = append(result, value)
		}
	}
	return result
}

func (h *ConsentHandler) authorizationStateTTL() time.Duration {
	if h.tokenService != nil {
		return h.tokenService.RevocationTTL() + 5*time.Minute
	}
	if h.config == nil {
		return 5 * time.Minute
	}
	return maxDuration(h.config.Auth.AccessTokenTTL, h.config.Auth.RefreshTokenTTL) + 5*time.Minute
}

func (h *ConsentHandler) authorizationCodeTTL() time.Duration {
	if h.tokenService != nil {
		return h.tokenService.Lifetimes().AuthorizationCode
	}
	if h.config != nil && h.config.Auth.AuthorizationCodeTTL > 0 {
		return h.config.Auth.AuthorizationCodeTTL
	}
	return 5 * time.Minute
}

func (h *ConsentHandler) DenyConsent(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	sess, ok := h.authorizeMutation(w, r)
	if !ok {
		writeError(w, http.StatusForbidden, "csrf_validation_failed")
		return
	}
	challenge, ok := decodeConsentRequest(r)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	data, err := h.sessionStore.ConsumeConsentForUser(r.Context(), challenge, sess.UserID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	if data.Flow == models.GrantDeviceCode {
		if h.deviceStore == nil {
			writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
			return
		}
		pending, getErr := h.deviceStore.GetPending(r.Context(), data.DeviceID, data.DeviceRecordVersion)
		if getErr != nil {
			writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
			return
		}
		if err := h.deviceStore.Deny(r.Context(), pending); err != nil {
			if errors.Is(err, deviceauthorization.ErrNotFound) || errors.Is(err, deviceauthorization.ErrValueMismatch) {
				writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
			} else {
				writeError(w, http.StatusServiceUnavailable, "device_authorization_unavailable")
			}
			return
		}
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonUserDenied, data.Scopes)
		writeJSON(w, http.StatusOK, map[string]string{"redirect_url": "/device?status=denied"})
		return
	}
	target, err := addQuery(data.RedirectURI, map[string]string{"error": "access_denied", "state": data.State})
	if err != nil {
		h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonServerError, data.Scopes)
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	h.recordConsentOperation(r.Context(), data, oauthops.OutcomeFailure, oauthops.ReasonUserDenied, data.Scopes)
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": target})
}

func consentFlow(data *session.ConsentData) string {
	if data != nil && data.Flow == models.GrantDeviceCode {
		return "device_authorization"
	}
	return "authorization_code"
}

func (h *ConsentHandler) authenticatedSession(w http.ResponseWriter, r *http.Request) (*session.SessionData, bool) {
	if h.sessionResolver != nil {
		sess, err := h.sessionResolver(w, r)
		return sess, err == nil && sess != nil && sess.UserID != ""
	}
	cookie, err := r.Cookie(oauthSessionCookie)
	if err != nil {
		return nil, false
	}
	sess, err := h.sessionStore.GetSession(r.Context(), cookie.Value)
	return sess, err == nil && sess.UserID != ""
}

func (h *ConsentHandler) authorizeMutation(w http.ResponseWriter, r *http.Request) (*session.SessionData, bool) {
	sess, ok := h.authenticatedSession(w, r)
	if !ok || sess.CSRFToken == "" {
		return nil, false
	}
	provided := r.Header.Get("X-CSRF-Token")
	if len(provided) != len(sess.CSRFToken) || subtle.ConstantTimeCompare([]byte(provided), []byte(sess.CSRFToken)) != 1 {
		return nil, false
	}
	return sess, true
}

func decodeConsentRequest(r *http.Request) (string, bool) {
	var request struct {
		Challenge string `json:"challenge"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 4096))
	if err := decoder.Decode(&request); err != nil || request.Challenge == "" {
		return "", false
	}
	return request.Challenge, true
}

func decodeConsentDecisionRequest(r *http.Request) (consentDecisionRequest, bool) {
	var payload struct {
		Challenge             string          `json:"challenge"`
		GrantedOptionalScopes json.RawMessage `json:"granted_optional_scopes"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, int64(maxAuthorizationQueryBytes*2)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.Challenge == "" {
		return consentDecisionRequest{}, false
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return consentDecisionRequest{}, false
	}
	request := consentDecisionRequest{Challenge: payload.Challenge}
	if len(payload.GrantedOptionalScopes) > 0 {
		if bytes.Equal(bytes.TrimSpace(payload.GrantedOptionalScopes), []byte("null")) {
			return consentDecisionRequest{}, false
		}
		var scopes []string
		if err := json.Unmarshal(payload.GrantedOptionalScopes, &scopes); err != nil || scopes == nil {
			return consentDecisionRequest{}, false
		}
		request.GrantedOptionalScopes = &scopes
	}
	return request, true
}

func consentPermissions(scopes, optionalScopes []string, scopeClaims map[string][]string, scopeDetails map[string]session.ConsentScopeDetails) []consentPermission {
	optional := make(map[string]struct{}, len(optionalScopes))
	for _, scope := range optionalScopes {
		optional[scope] = struct{}{}
	}
	permissions := make([]consentPermission, 0, len(scopes))
	for _, scope := range scopes {
		_, isOptional := optional[scope]
		claims := scopeClaims[scope]
		if scopeClaims == nil {
			claims = claimsForScope(scope)
		}
		if claims == nil {
			claims = []string{}
		}
		details := scopeDetails[scope]
		if details.DisplayName == "" {
			details = legacyScopeDetails(scope)
		}
		permissions = append(permissions, consentPermission{
			Scope: scope, DisplayName: details.DisplayName, Description: details.Description,
			RiskLevel: details.RiskLevel, Required: !isOptional, Claims: slices.Clone(claims),
		})
	}
	return permissions
}

func legacyScopeDetails(scope string) session.ConsentScopeDetails {
	switch scope {
	case "openid":
		return session.ConsentScopeDetails{DisplayName: "确认身份", Description: "使用稳定的账户标识完成 OpenID Connect 登录。", RiskLevel: "low"}
	case "profile":
		return session.ConsentScopeDetails{DisplayName: "基本资料", Description: "读取用户名、显示名称和头像。", RiskLevel: "personal_data"}
	case "email":
		return session.ConsentScopeDetails{DisplayName: "邮箱信息", Description: "读取邮箱地址及邮箱验证状态。", RiskLevel: "personal_data"}
	case "offline_access":
		return session.ConsentScopeDetails{DisplayName: "离线访问", Description: "允许应用在用户离开后继续访问。", RiskLevel: "sensitive"}
	default:
		return session.ConsentScopeDetails{DisplayName: scope, Description: "使用该应用为此集成定义的权限。", RiskLevel: "sensitive"}
	}
}

func claimsForGrantedScopes(scopes []string, scopeClaims map[string][]string) []string {
	selected := make(map[string]bool)
	for _, scope := range scopes {
		claims := scopeClaims[scope]
		if scopeClaims == nil {
			claims = claimsForScope(scope)
		}
		for _, claim := range claims {
			selected[claim] = true
		}
	}
	ordered := []string{"sub", "preferred_username", "name", "picture", "email", "email_verified", "role"}
	result := make([]string, 0, len(selected))
	for _, claim := range ordered {
		if selected[claim] {
			result = append(result, claim)
		}
	}
	return result
}

func claimsForScope(scope string) []string {
	switch scope {
	case "openid":
		return []string{"sub"}
	case "profile":
		return []string{"preferred_username", "name", "picture"}
	case "email":
		return []string{"email", "email_verified"}
	default:
		return []string{}
	}
}

func resolveGrantedScopes(requested, optional, selected []string) ([]string, error) {
	requestedSet := make(map[string]struct{}, len(requested))
	for _, scope := range requested {
		if _, exists := requestedSet[scope]; exists {
			return nil, errInvalidConsentScopes
		}
		requestedSet[scope] = struct{}{}
	}
	optionalSet := make(map[string]struct{}, len(optional))
	for _, scope := range optional {
		if _, exists := requestedSet[scope]; !exists || scope == "openid" {
			return nil, errInvalidConsentScopes
		}
		if _, exists := optionalSet[scope]; exists {
			return nil, errInvalidConsentScopes
		}
		optionalSet[scope] = struct{}{}
	}
	selectedSet := make(map[string]struct{}, len(selected))
	for _, scope := range selected {
		if _, exists := optionalSet[scope]; !exists {
			return nil, errInvalidConsentScopes
		}
		if _, exists := selectedSet[scope]; exists {
			return nil, errInvalidConsentScopes
		}
		selectedSet[scope] = struct{}{}
	}
	granted := make([]string, 0, len(requested))
	for _, scope := range requested {
		_, isOptional := optionalSet[scope]
		_, isSelected := selectedSet[scope]
		if !isOptional || isSelected {
			granted = append(granted, scope)
		}
	}
	return granted, nil
}
