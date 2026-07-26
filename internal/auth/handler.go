package auth

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
	"github.com/nyasharp/nyauth/pkg/models"
)

const oauthSessionCookie = "nyauth_session"

const (
	maxOAuthFormBodyBytes      int64 = 1 << 20
	maxAuthorizationQueryBytes       = 16 << 10
	maxOAuthStateBytes               = 512
	maxOIDCNonceBytes                = 512
)

var errEndSessionSubjectMismatch = errors.New("ID token subject does not match session subject")

type SecurityAuditEvent struct {
	Event         string
	ActorID       *uuid.UUID
	ActorName     string
	AggregateType string
	AggregateID   string
	Result        string
	RiskLevel     string
	Details       map[string]any
}

type SecurityAuditSink func(context.Context, SecurityAuditEvent) error
type GrantMetricSink func(context.Context, string, string, string)

type Handler struct {
	tokenService *TokenService
	jwkManager   *JWKManager
	userService  *user.Service
	clientStore  *client.Store
	sessionStore *session.Store
	config       *config.Config
	auditSink    SecurityAuditSink
	metricSink   GrantMetricSink
}

func NewHandler(tokenService *TokenService, jwkManager *JWKManager, userService *user.Service, clientStore *client.Store, sessionStore *session.Store, cfg *config.Config) *Handler {
	tokenService.SetUserService(userService)
	tokenService.SetAccessPolicyChecker(clientStore)
	if err := jwkManager.Configure(cfg.Auth.MasterKey, cfg.Auth.AccessTokenTTL); err != nil {
		panic("invalid validated JWK configuration: " + err.Error())
	}
	return &Handler{tokenService: tokenService, jwkManager: jwkManager, userService: userService, clientStore: clientStore, sessionStore: sessionStore, config: cfg}
}

func (h *Handler) SetSecurityAuditSink(sink SecurityAuditSink) { h.auditSink = sink }
func (h *Handler) SetGrantMetricSink(sink GrantMetricSink)     { h.metricSink = sink }

func (h *Handler) recordSecurityAudit(ctx context.Context, event SecurityAuditEvent) {
	if h.auditSink == nil {
		return
	}
	if err := h.auditSink(ctx, event); err != nil {
		slog.ErrorContext(ctx, "OAuth security audit enqueue failed",
			"event", event.Event,
			"result", event.Result,
			"target_type", event.AggregateType,
			"error", err,
		)
	}
}

func (h *Handler) recordGrantAudit(ctx context.Context, event, grantType, clientID, result, riskLevel, reason string) {
	grantType = normalizedGrantType(grantType)
	reason = strings.TrimSpace(reason)
	metricReason := reason
	if metricReason == "" {
		metricReason = "none"
	}
	if h.metricSink != nil {
		h.metricSink(ctx, grantType, result, metricReason)
	}
	aggregateType, aggregateID := "oauth_grant", grantType
	if clientID = strings.TrimSpace(clientID); clientID != "" {
		aggregateType, aggregateID = "client", clientID
	}
	details := map[string]any{"grant_type": grantType}
	if reason != "" {
		details["failure_reason"] = reason
	}
	securityEvent := SecurityAuditEvent{
		Event: event, AggregateType: aggregateType, AggregateID: aggregateID,
		Result: result, RiskLevel: riskLevel, Details: details,
	}
	h.recordSecurityAudit(ctx, securityEvent)
}

func (h *Handler) recordTokenRevocationAudit(ctx context.Context, clientID string, authenticated bool, result, riskLevel, reason string) {
	targetType, targetID := oauthAuditTarget(clientID, "revoke")
	details := map[string]any{"operation": "token_revocation"}
	if reason = strings.TrimSpace(reason); reason != "" {
		details["failure_reason"] = reason
	}
	event := SecurityAuditEvent{
		Event: models.AuditTokenRevoked, AggregateType: targetType, AggregateID: targetID,
		Result: result, RiskLevel: riskLevel, Details: details,
	}
	if authenticated && targetType == "client" {
		event.ActorName = targetID
	}
	h.recordSecurityAudit(ctx, event)
}

func (h *Handler) recordEndSessionAudit(ctx context.Context, actorID *uuid.UUID, actorName, clientID, result, riskLevel, reason string) {
	targetType, targetID := oauthAuditTarget(clientID, "end_session")
	details := map[string]any{"operation": "oidc_end_session"}
	if reason = strings.TrimSpace(reason); reason != "" {
		details["failure_reason"] = reason
	}
	h.recordSecurityAudit(ctx, SecurityAuditEvent{
		Event: models.AuditUserLogout, ActorID: actorID, ActorName: strings.TrimSpace(actorName),
		AggregateType: targetType, AggregateID: targetID,
		Result: result, RiskLevel: riskLevel, Details: details,
	})
}

func oauthAuditTarget(clientID, endpoint string) (string, string) {
	clientID = strings.TrimSpace(clientID)
	if validOAuthAuditIdentifier(clientID) {
		return "client", clientID
	}
	return "oauth_endpoint", endpoint
}

func validOAuthAuditIdentifier(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func endSessionActor(subject string, sess *session.SessionData) (*uuid.UUID, string) {
	if sess != nil && sess.UserID != "" {
		subject = sess.UserID
	}
	actorID, err := uuid.Parse(subject)
	if err != nil {
		return nil, ""
	}
	actorName := ""
	if sess != nil {
		actorName = strings.TrimSpace(sess.Username)
	}
	return &actorID, actorName
}

func normalizedGrantType(value string) string {
	switch strings.TrimSpace(value) {
	case models.GrantAuthorizationCode:
		return models.GrantAuthorizationCode
	case models.GrantClientCredentials:
		return models.GrantClientCredentials
	case models.GrantRefreshToken:
		return models.GrantRefreshToken
	default:
		return "unsupported"
	}
}

func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Get("/authorize", h.Authorize)
	r.Post("/token", h.Token)
	r.Post("/revoke", h.Revoke)
	r.Post("/introspect", h.Introspect)
	r.Get("/userinfo", h.UserInfo)
	r.Post("/userinfo", h.UserInfo)
	r.Get("/end_session", h.EndSession)
	return r
}

func (h *Handler) Discovery(w http.ResponseWriter, _ *http.Request) {
	issuer := strings.TrimRight(h.config.Auth.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
		"userinfo_endpoint": issuer + "/userinfo", "jwks_uri": issuer + "/.well-known/jwks.json",
		"revocation_endpoint": issuer + "/revoke", "introspection_endpoint": issuer + "/introspect", "end_session_endpoint": issuer + "/end_session",
		"response_types_supported": []string{"code"},
		"grant_types_supported":    []string{"authorization_code", "client_credentials", "refresh_token"},
		"subject_types_supported":  []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "jti", "nonce", "name", "email", "preferred_username", "picture"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.jwkManager.ListActivePublicKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	type publicJWK struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	result := make([]publicJWK, 0, len(keys))
	for _, key := range keys {
		block, _ := pem.Decode([]byte(key.PublicKey))
		if block == nil {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		publicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			continue
		}
		result = append(result, publicJWK{Kty: "RSA", Kid: key.Kid, Use: "sig", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()), E: intToBase64URL(publicKey.E)})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"keys": result})
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.RawQuery) > maxAuthorizationQueryBytes {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "authorization request is too large")
		return
	}
	q := r.URL.Query()
	clientID, redirectURI := q.Get("client_id"), q.Get("redirect_uri")
	if clientID == "" || redirectURI == "" || q.Get("response_type") != "code" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id, redirect_uri, and response_type=code are required")
		return
	}
	cl, err := h.clientStore.GetByID(r.Context(), clientID)
	if err != nil || !cl.HasRedirectURI(redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid client or redirect_uri")
		return
	}
	state := q.Get("state")
	if !validOAuthOpaqueParameter(state, maxOAuthStateBytes, true) {
		h.redirectAuthorizeError(w, r, redirectURI, "", "invalid_request")
		return
	}
	if !cl.HasGrant(models.GrantAuthorizationCode) {
		h.redirectAuthorizeError(w, r, redirectURI, state, "unauthorized_client")
		return
	}
	scopes, err := parseAndValidateScopes(q.Get("scope"), cl.Scopes)
	if err != nil {
		h.redirectAuthorizeError(w, r, redirectURI, state, "invalid_scope")
		return
	}
	if containsScope(scopes, "offline_access") && !cl.HasGrant(models.GrantRefreshToken) {
		h.redirectAuthorizeError(w, r, redirectURI, state, "invalid_scope")
		return
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	if method != "S256" || !validPKCEChallenge(challenge) {
		h.redirectAuthorizeError(w, r, redirectURI, state, "invalid_request")
		return
	}
	nonce := q.Get("nonce")
	if !validOAuthOpaqueParameter(nonce, maxOIDCNonceBytes, !containsScope(scopes, "openid")) {
		h.redirectAuthorizeError(w, r, redirectURI, state, "invalid_request")
		return
	}

	sess, currentUser := h.currentSessionUser(r)
	if sess == nil || currentUser == nil {
		loginURL := "/login?return_to=" + url.QueryEscape(r.URL.RequestURI())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}
	if currentUser.MustChangePassword {
		http.Redirect(w, r, "/change-password", http.StatusFound)
		return
	}
	allowed, err := h.clientStore.UserMayAccess(r.Context(), cl.ID, currentUser.ID.String())
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to evaluate client access policy")
		return
	}
	if !allowed {
		h.recordSecurityAudit(r.Context(), SecurityAuditEvent{
			Event: models.AuditAuthorizeDenied, ActorID: &currentUser.ID, ActorName: currentUser.Username,
			AggregateType: "client", AggregateID: cl.ID, Result: "failure", RiskLevel: "medium",
			Details: map[string]any{"access_policy": cl.AccessPolicy},
		})
		h.redirectAuthorizeError(w, r, redirectURI, state, "access_denied")
		return
	}
	consentChallenge, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create consent challenge")
		return
	}
	data := &session.ConsentData{ClientID: clientID, UserID: currentUser.ID.String(), RedirectURI: redirectURI, Scopes: scopes,
		State: state, CodeChallenge: challenge, ChallengeMethod: "S256", Nonce: nonce, AuthVersion: currentUser.AuthVersion}
	if err := h.sessionStore.SaveConsent(r.Context(), consentChallenge, data, 10*time.Minute); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to persist consent challenge")
		return
	}
	http.Redirect(w, r, "/consent?challenge="+url.QueryEscape(consentChallenge), http.StatusFound)
}

func validOAuthOpaqueParameter(value string, maxBytes int, allowEmpty bool) bool {
	if value == "" {
		return allowEmpty
	}
	return len(value) <= maxBytes && utf8.ValidString(value)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	if err := parseOAuthForm(w, r); err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, "", "", "failure", "medium", "invalid_form")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	switch r.Form.Get("grant_type") {
	case models.GrantAuthorizationCode:
		h.handleAuthorizationCodeGrant(w, r)
	case models.GrantClientCredentials:
		h.handleClientCredentialsGrant(w, r)
	case models.GrantRefreshToken:
		h.handleRefreshTokenGrant(w, r)
	default:
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, r.Form.Get("grant_type"), "", "failure", "medium", "unsupported_grant_type")
		writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type is not supported")
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code, redirectURI, verifier := r.Form.Get("code"), r.Form.Get("redirect_uri"), r.Form.Get("code_verifier")
	if code == "" || redirectURI == "" || !validPKCEVerifier(verifier) {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, "", "failure", "medium", "invalid_request")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri, and valid code_verifier are required")
		return
	}
	stored, err := h.sessionStore.GetAuthorizationCode(r.Context(), code)
	if err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, "", "failure", "high", "invalid_or_expired_code")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired authorization code")
		return
	}
	cl, clientID, authOK := h.authenticateTokenClient(r, stored.ClientID, true)
	if !authOK {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, stored.ClientID, "failure", "high", "invalid_client")
		writeInvalidClient(w)
		return
	}
	if clientID != stored.ClientID || !cl.HasGrant(models.GrantAuthorizationCode) || redirectURI != stored.RedirectURI ||
		stored.ChallengeMethod != "S256" || !validatePKCE(verifier, stored.CodeChallenge, stored.ChallengeMethod) {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, stored.ClientID, "failure", "high", "code_binding_validation")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code binding validation failed")
		return
	}
	if _, err := parseAndValidateScopes(joinScopes(stored.Scopes), cl.Scopes); err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "scope_no_longer_allowed")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization scope is no longer allowed")
		return
	}
	uid, err := uuid.Parse(stored.UserID)
	if err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "invalid_subject")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid authorization subject")
		return
	}
	u, err := h.userService.GetByID(r.Context(), uid)
	if err != nil || u.Status != models.UserStatusActive || u.AuthVersion != stored.AuthVersion {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "inactive_subject")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization subject is no longer active")
		return
	}
	if _, err := h.sessionStore.ConsumeAuthorizationCodeIfMatch(r.Context(), code, stored); err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "code_reuse")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization code was already consumed")
		return
	}
	issueRefresh := containsScope(stored.Scopes, "offline_access") && cl.HasGrant(models.GrantRefreshToken)
	pair, err := h.tokenService.GenerateAuthorizationCodeTokenPair(r.Context(), cl.ID, stored.UserID, stored.Scopes, stored.AuthVersion, stored.AuthorizationIssuedAt, issueRefresh)
	if err != nil {
		if errors.Is(err, ErrInvalidToken) {
			h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "authorization_inactive")
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "authorization is no longer active")
			return
		}
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "token_issuance_failed")
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}
	if containsScope(stored.Scopes, "openid") {
		info := make(map[string]interface{})
		if containsScope(stored.Scopes, "profile") {
			info["preferred_username"] = u.Username
			if u.DisplayName != nil {
				info["name"] = *u.DisplayName
			}
			if u.AvatarURL != nil {
				info["picture"] = *u.AvatarURL
			}
		}
		if containsScope(stored.Scopes, "email") && u.Email != nil {
			info["email"] = *u.Email
		}
		pair.IDToken, err = h.tokenService.GenerateIDToken(r.Context(), cl.ID, stored.UserID, stored.Scopes, stored.Nonce, info)
		if err != nil {
			h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantAuthorizationCode, cl.ID, "failure", "high", "id_token_issuance_failed")
			writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue ID token")
			return
		}
	}
	h.recordGrantAudit(r.Context(), models.AuditTokenIssued, models.GrantAuthorizationCode, cl.ID, "success", "low", "")
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	cl, _, ok := h.authenticateTokenClient(r, "", false)
	if !ok || cl.IsPublic {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantClientCredentials, "", "failure", "medium", "invalid_client")
		writeInvalidClient(w)
		return
	}
	if !cl.HasGrant(models.GrantClientCredentials) {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantClientCredentials, cl.ID, "failure", "medium", "grant_not_allowed")
		writeTokenError(w, http.StatusBadRequest, "unauthorized_client", "client_credentials grant is not allowed")
		return
	}
	scopes, err := parseAndValidateScopes(r.Form.Get("scope"), cl.Scopes)
	if err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantClientCredentials, cl.ID, "failure", "medium", "invalid_scope")
		writeTokenError(w, http.StatusBadRequest, "invalid_scope", "requested scope is not allowed")
		return
	}
	if r.Form.Get("scope") == "" {
		scopes = append([]string(nil), cl.Scopes...)
	}
	scopes = withoutScope(scopes, "offline_access")
	pair, err := h.tokenService.GenerateClientTokenPair(r.Context(), cl.ID, scopes)
	if err != nil {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantClientCredentials, cl.ID, "failure", "high", "token_issuance_failed")
		writeTokenError(w, http.StatusInternalServerError, "server_error", "failed to issue token")
		return
	}
	h.recordGrantAudit(r.Context(), models.AuditTokenIssued, models.GrantClientCredentials, cl.ID, "success", "low", "")
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refresh := r.Form.Get("refresh_token")
	if refresh == "" || r.Form.Get("scope") != "" {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantRefreshToken, "", "failure", "medium", "invalid_request")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required and scope changes are not supported")
		return
	}
	cl, clientID, ok := h.authenticateTokenClient(r, "", true)
	if !ok {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantRefreshToken, "", "failure", "medium", "invalid_client")
		writeInvalidClient(w)
		return
	}
	if !cl.HasGrant(models.GrantRefreshToken) {
		h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantRefreshToken, cl.ID, "failure", "high", "grant_not_allowed")
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "refresh token is not valid for this client")
		return
	}
	pair, err := h.tokenService.RefreshToken(r.Context(), refresh, clientID, cl.Scopes)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenReuse) {
			h.recordGrantAudit(r.Context(), models.AuditRefreshTokenReuse, models.GrantRefreshToken, cl.ID, "failure", "critical", "refresh_reuse")
		} else {
			h.recordGrantAudit(r.Context(), models.AuditTokenGrantFailed, models.GrantRefreshToken, cl.ID, "failure", "high", "invalid_refresh")
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "invalid refresh token")
		return
	}
	h.recordGrantAudit(r.Context(), models.AuditTokenIssued, models.GrantRefreshToken, cl.ID, "success", "low", "")
	writeJSON(w, http.StatusOK, pair)
}

func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := parseOAuthForm(w, r); err != nil {
		h.recordTokenRevocationAudit(r.Context(), "", false, "failure", "medium", "invalid_form")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	token := r.Form.Get("token")
	if token == "" {
		h.recordTokenRevocationAudit(r.Context(), "", false, "failure", "medium", "missing_token")
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	cl, clientID, ok := h.authenticateTokenClient(r, "", true)
	if !ok {
		h.recordTokenRevocationAudit(r.Context(), clientID, false, "failure", "high", "invalid_client")
		writeInvalidClient(w)
		return
	}
	if err := h.tokenService.RevokeTokenForClient(r.Context(), token, cl.ID); err != nil {
		if errors.Is(err, ErrClientMismatch) {
			h.recordTokenRevocationAudit(r.Context(), cl.ID, true, "failure", "high", "client_binding_mismatch")
			// RFC 7009 requires an idempotent response and must not expose token ownership.
			w.WriteHeader(http.StatusOK)
			return
		}
		h.recordTokenRevocationAudit(r.Context(), cl.ID, true, "failure", "high", "revocation_store_error")
		writeTokenError(w, http.StatusServiceUnavailable, "server_error", "token revocation is temporarily unavailable")
		return
	}
	h.recordTokenRevocationAudit(r.Context(), cl.ID, true, "success", "medium", "")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	if err := parseOAuthForm(w, r); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}
	cl, _, ok := h.authenticateTokenClient(r, "", false)
	if !ok || cl.IsPublic {
		writeInvalidClient(w)
		return
	}
	result, _ := h.tokenService.IntrospectTokenForClient(r.Context(), r.Form.Get("token"), cl.ID, cl.Scopes)
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	claims, err := h.tokenService.ValidateAccessToken(r.Context(), extractBearerToken(r))
	if err != nil || claims.AuthVersion <= 0 {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	u, err := h.userService.GetByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	result := map[string]interface{}{"sub": claims.Subject}
	scopes := strings.Fields(claims.Scope)
	if containsScope(scopes, "profile") {
		result["preferred_username"] = u.Username
		if u.DisplayName != nil {
			result["name"] = *u.DisplayName
		}
		if u.AvatarURL != nil {
			result["picture"] = *u.AvatarURL
		}
	}
	if containsScope(scopes, "email") && u.Email != nil {
		result["email"] = *u.Email
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	setOAuthNoStoreHeaders(w)
	w.Header().Set("Referrer-Policy", "no-referrer")
	postLogoutURI, state, hint := r.URL.Query().Get("post_logout_redirect_uri"), r.URL.Query().Get("state"), r.URL.Query().Get("id_token_hint")
	if hint == "" {
		if postLogoutURI != "" {
			h.recordEndSessionAudit(r.Context(), nil, "", "", "failure", "medium", "missing_id_token_hint")
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id_token_hint is required for redirect")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "no session ended; use the CSRF-protected logout endpoint"})
		return
	}
	claims, err := h.tokenService.ValidateIDToken(r.Context(), hint)
	if errors.Is(err, ErrTokenValidationUnavailable) {
		h.recordEndSessionAudit(r.Context(), nil, "", "", "failure", "high", "token_validation_unavailable")
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "logout validation is temporarily unavailable")
		return
	}
	if err != nil || len(claims.Audience) != 1 {
		h.recordEndSessionAudit(r.Context(), nil, "", "", "failure", "high", "invalid_id_token_hint")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "valid id_token_hint is required for redirect")
		return
	}
	var actorID *uuid.UUID
	actorName := ""
	cl, err := h.clientStore.GetByID(r.Context(), claims.Audience[0])
	if err != nil {
		h.recordEndSessionAudit(r.Context(), actorID, actorName, claims.Audience[0], "failure", "high", "unknown_client")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id_token_hint refers to an unknown client")
		return
	}
	if postLogoutURI != "" && !cl.HasPostLogoutRedirectURI(postLogoutURI) {
		h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "failure", "high", "unregistered_post_logout_redirect_uri")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri is not registered")
		return
	}
	redirectTarget := ""
	if postLogoutURI != "" {
		redirectTarget, err = addQuery(postLogoutURI, map[string]string{"state": state})
		if err != nil {
			h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "failure", "medium", "invalid_post_logout_redirect_uri")
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid post_logout_redirect_uri")
			return
		}
	}
	var sessionCookie *http.Cookie
	var activeSession *session.SessionData
	if cookie, cookieErr := r.Cookie(oauthSessionCookie); cookieErr == nil {
		sessionCookie = cookie
		sess, sessionErr := h.sessionStore.GetSession(r.Context(), cookie.Value)
		if err := validateEndSessionSession(sess, sessionErr, claims.Subject); errors.Is(err, errEndSessionSubjectMismatch) {
			actorID, actorName = endSessionActor(claims.Subject, sess)
			h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "failure", "high", "session_subject_mismatch")
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "id_token_hint does not belong to the current session")
			return
		} else if err != nil {
			h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "failure", "high", "session_store_error")
			writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "session service is temporarily unavailable")
			return
		}
		if sess != nil {
			actorID, actorName = endSessionActor(claims.Subject, sess)
			activeSession = sess
		}
	}
	sessionEnded := false
	if sessionCookie != nil && activeSession != nil {
		if err := h.sessionStore.DeleteSession(r.Context(), sessionCookie.Value); err != nil && !errors.Is(err, session.ErrNotFound) {
			h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "failure", "high", "session_store_error")
			writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "session service is temporarily unavailable")
			return
		} else if err == nil {
			sessionEnded = true
		}
	}
	if sessionEnded {
		h.recordEndSessionAudit(r.Context(), actorID, actorName, cl.ID, "success", "medium", "")
	} else {
		h.recordEndSessionAudit(r.Context(), nil, "", cl.ID, "failure", "low", "no_active_session")
	}
	http.SetCookie(w, &http.Cookie{Name: oauthSessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: h.config.Server.SecureCookie, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if postLogoutURI == "" {
		message := "no active session"
		if sessionEnded {
			message = "logged out"
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": message})
		return
	}
	http.Redirect(w, r, redirectTarget, http.StatusFound)
}

func validateEndSessionSession(sess *session.SessionData, err error, subject string) error {
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return nil
		}
		return err
	}
	if sess == nil || sess.UserID != subject {
		return errEndSessionSubjectMismatch
	}
	return nil
}

func (h *Handler) authenticateTokenClient(r *http.Request, expectedID string, allowPublic bool) (*models.OAuthClient, string, bool) {
	formID, formSecret := r.Form.Get("client_id"), r.Form.Get("client_secret")
	basicID, basicSecret, hasBasic := r.BasicAuth()
	if hasBasic && (formID != "" || formSecret != "") {
		return nil, "", false
	}
	if !hasBasic && formID == "" {
		return nil, "", false
	}
	clientID, secret := formID, formSecret
	if hasBasic {
		clientID, secret = basicID, basicSecret
	}
	if clientID == "" {
		clientID = expectedID
	}
	if clientID == "" || (expectedID != "" && clientID != expectedID) {
		return nil, clientID, false
	}
	cl, err := h.clientStore.GetByID(r.Context(), clientID)
	if err != nil {
		return nil, clientID, false
	}
	if cl.IsPublic {
		return cl, clientID, allowPublic && !hasBasic && secret == ""
	}
	if secret == "" {
		return nil, clientID, false
	}
	authed, err := h.clientStore.AuthenticateClient(r.Context(), clientID, secret)
	return authed, clientID, err == nil
}

func (h *Handler) currentSessionUser(r *http.Request) (*session.SessionData, *models.User) {
	cookie, err := r.Cookie(oauthSessionCookie)
	if err != nil {
		return nil, nil
	}
	sess, err := h.sessionStore.GetSession(r.Context(), cookie.Value)
	if err != nil {
		return nil, nil
	}
	id, err := uuid.Parse(sess.UserID)
	if err != nil {
		return nil, nil
	}
	u, err := h.userService.GetByID(r.Context(), id)
	if err != nil || u.Status != models.UserStatusActive ||
		u.AuthVersion != sess.AuthVersion || u.SessionVersion != sess.SessionVersion {
		return nil, nil
	}
	return sess, u
}

func (h *Handler) redirectAuthorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, code string) {
	target, err := addQuery(redirectURI, map[string]string{"error": code, "state": state})
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect URI")
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func parseAndValidateScopes(raw string, allowed []string) ([]string, error) {
	requested := strings.Fields(raw)
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	seen := make(map[string]struct{}, len(requested))
	result := make([]string, 0, len(requested))
	for _, scope := range requested {
		if _, ok := allowedSet[scope]; !ok {
			return nil, errors.New("scope not allowed")
		}
		if _, duplicate := seen[scope]; duplicate {
			return nil, errors.New("duplicate scope")
		}
		seen[scope] = struct{}{}
		result = append(result, scope)
	}
	sort.Strings(result)
	return result, nil
}

func withoutScope(scopes []string, excluded string) []string {
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope != excluded {
			result = append(result, scope)
		}
	}
	return result
}
func addQuery(raw string, values map[string]string) (string, error) {
	target, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	query := target.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}
func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}
func writeTokenError(w http.ResponseWriter, status int, code, description string) {
	writeOAuthError(w, status, code, description)
}
func writeInvalidClient(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="token"`)
	writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
}
func parseOAuthForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxOAuthFormBodyBytes)
	return r.ParseForm()
}
func setOAuthNoStoreHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
func extractBearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(strings.ToLower(parts[0])), []byte("bearer")) == 1 {
		return parts[1]
	}
	return ""
}
func intToBase64URL(value int) string {
	return base64.RawURLEncoding.EncodeToString(big.NewInt(int64(value)).Bytes())
}
