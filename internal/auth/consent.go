package auth

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/authorization"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	internalcrypto "github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/session"
)

type ConsentHandler struct {
	sessionStore       *session.Store
	tokenService       *TokenService
	clientStore        *client.Store
	authorizationStore *authorization.Store
	config             *config.Config
	sessionResolver    BrowserSessionResolver
}

func (h *ConsentHandler) SetBrowserSessionResolver(resolver BrowserSessionResolver) {
	h.sessionResolver = resolver
}

func NewConsentHandler(sessionStore *session.Store, tokenService *TokenService, clientStore *client.Store, authorizationStore *authorization.Store, cfg *config.Config) *ConsentHandler {
	return &ConsentHandler{sessionStore: sessionStore, tokenService: tokenService, clientStore: clientStore, authorizationStore: authorizationStore, config: cfg}
}

func (h *ConsentHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
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
	cl, err := h.clientStore.GetByID(r.Context(), data.ClientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	publisherType := "user_registered"
	if cl.OwnerID == nil {
		publisherType = "system_managed"
	}
	redirectOrigin := ""
	if parsed, parseErr := url.Parse(data.RedirectURI); parseErr == nil && parsed.Scheme != "" && parsed.Host != "" {
		redirectOrigin = parsed.Scheme + "://" + parsed.Host
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge": challenge, "client_name": cl.Name, "client_id": cl.ID,
		"scopes": data.Scopes, "redirect_uri": data.RedirectURI,
		"redirect_origin": redirectOrigin, "publisher_type": publisherType,
		"verification_status": "unverified",
	})
}

func (h *ConsentHandler) AcceptConsent(w http.ResponseWriter, r *http.Request) {
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
	if err != nil || data.AuthVersion != sess.AuthVersion {
		writeError(w, http.StatusBadRequest, "invalid_or_expired_challenge")
		return
	}
	userID, err := uuid.Parse(data.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	authorizationIssuedAt, err := h.sessionStore.AuthorizationIssueTime(r.Context(), data.UserID, data.ClientID, h.authorizationStateTTL())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	if err := h.authorizationStore.Upsert(r.Context(), userID, data.ClientID, data.Scopes, time.UnixMicro(authorizationIssuedAt).UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	code, err := internalcrypto.GenerateRandomString(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	authorization := &session.AuthorizationData{
		ClientID: data.ClientID, UserID: data.UserID, RedirectURI: data.RedirectURI, Scopes: data.Scopes,
		CodeChallenge: data.CodeChallenge, ChallengeMethod: "S256", Nonce: data.Nonce, AuthVersion: data.AuthVersion,
		AuthorizationIssuedAt: authorizationIssuedAt,
	}
	if err := h.sessionStore.SaveAuthorizationCode(r.Context(), code, authorization, h.authorizationCodeTTL()); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	target, err := addQuery(data.RedirectURI, map[string]string{"code": code, "state": data.State})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": target})
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
	target, err := addQuery(data.RedirectURI, map[string]string{"error": "access_denied", "state": data.State})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect_url": target})
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
