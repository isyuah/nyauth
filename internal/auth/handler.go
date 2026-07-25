package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/user"
)

// Handler handles OAuth 2.0 and OIDC HTTP endpoints.
type Handler struct {
	tokenService *TokenService
	jwkManager   *JWKManager
	userService  *user.Service
	clientStore  *client.Store
	sessionStore *session.Store
	config       *config.Config
}

// NewHandler creates a new auth handler.
func NewHandler(
	tokenService *TokenService,
	jwkManager *JWKManager,
	userService *user.Service,
	clientStore *client.Store,
	sessionStore *session.Store,
	config *config.Config,
) *Handler {
	return &Handler{
		tokenService: tokenService,
		jwkManager:   jwkManager,
		userService:  userService,
		clientStore:  clientStore,
		sessionStore: sessionStore,
		config:       config,
	}
}

// Routes returns a chi router with auth routes mounted.
func (h *Handler) Routes() chi.Router {
	r := chi.NewRouter()

	// OIDC Discovery
	r.Get("/.well-known/openid-configuration", h.Discovery)
	r.Get("/.well-known/jwks.json", h.JWKS)

	// OAuth 2.0 endpoints
	r.Get("/authorize", h.Authorize)
	r.Post("/token", h.Token)
	r.Post("/revoke", h.Revoke)
	r.Post("/introspect", h.Introspect)
	r.Get("/userinfo", h.UserInfo)
	r.Post("/userinfo", h.UserInfo)
	r.Get("/end_session", h.EndSession)

	return r
}

// Discovery handles the OIDC discovery endpoint.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.config.Auth.Issuer

	discovery := map[string]interface{}{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"userinfo_endpoint":      issuer + "/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"revocation_endpoint":    issuer + "/revoke",
		"introspection_endpoint": issuer + "/introspect",
		"end_session_endpoint":   issuer + "/end_session",

		"response_types_supported": []string{"code", "token", "id_token", "code id_token"},
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"refresh_token",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported":  []string{"client_secret_basic", "client_secret_post", "none"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "jti",
			"name", "email", "preferred_username", "picture",
		},
		"code_challenge_methods_supported": []string{"S256", "plain"},
	}

	writeJSON(w, http.StatusOK, discovery)
}

// JWKS handles the JSON Web Key Set endpoint.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	keys, err := h.jwkManager.ListActivePublicKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load keys")
		return
	}

	type jwkKey struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	}

	var jwks []jwkKey
	for _, k := range keys {
		block, _ := pem.Decode([]byte(k.PublicKey))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			continue
		}

		jwks = append(jwks, jwkKey{
			Kty: "RSA",
			Kid: k.Kid,
			Use: k.Usage,
			Alg: k.Algorithm,
			N:   bigIntToBase64URL(rsaPub.N),
			E:   intToBase64URL(rsaPub.E),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"keys": jwks,
	})
}

// Authorize handles the OAuth 2.0 authorization endpoint.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType != "code" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	// Validate client
	cl, err := h.clientStore.GetByID(r.Context(), clientID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client")
		return
	}

	if !cl.HasRedirectURI(redirectURI) {
		writeError(w, http.StatusBadRequest, "invalid_redirect_uri")
		return
	}

	if !cl.HasGrant("authorization_code") {
		writeError(w, http.StatusBadRequest, "unauthorized_client")
		return
	}

	// For now, return a JSON response indicating the authorization request is valid.
	// In production, this would redirect to a consent/login page.
	// The actual user authentication happens via the login endpoint.
	scopes := strings.Split(scope, " ")

	// Check for user session (set during login)
	var userID string
	if cookie, err := r.Cookie("nyauth_session"); err == nil {
		if sess, err := h.sessionStore.GetSession(r.Context(), cookie.Value); err == nil {
			userID = sess.UserID
		}
	}

	// If no session, redirect to frontend login page with return URL
	if userID == "" {
		returnTo := r.URL.String()
		loginURL := "/login?return_to=" + url.QueryEscape(returnTo)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Create consent challenge
	challenge := uuid.New().String()
	consentData := &session.ConsentData{
		ClientID:        clientID,
		UserID:          userID,
		RedirectURI:     redirectURI,
		Scopes:          scopes,
		State:           state,
		CodeChallenge:   codeChallenge,
		ChallengeMethod: codeChallengeMethod,
	}

	if err := h.sessionStore.SaveConsent(r.Context(), challenge, consentData, 10*time.Minute); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error")
		return
	}

	// Redirect to consent page
	http.Redirect(w, r, "/consent?challenge="+challenge, http.StatusFound)
}

// Token handles the OAuth 2.0 token endpoint.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "failed to parse form")
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		h.handleClientCredentialsGrant(w, r)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r)
	default:
		writeTokenError(w, "unsupported_grant_type", "grant type not supported")
	}
}

func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")
	codeVerifier := r.Form.Get("code_verifier")

	// Try Basic auth first
	if clientID == "" || clientSecret == "" {
		cID, cSecret, ok := r.BasicAuth()
		if ok {
			clientID = cID
			clientSecret = cSecret
		}
	}

	if code == "" {
		writeTokenError(w, "invalid_request", "code is required")
		return
	}

	// Consume the authorization code
	authData, err := h.sessionStore.ConsumeAuthorizationCode(r.Context(), code)
	if err != nil {
		writeTokenError(w, "invalid_grant", "invalid or expired authorization code")
		return
	}

	// Validate redirect_uri matches
	if authData.RedirectURI != redirectURI {
		writeTokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Validate client
	cl, err := h.clientStore.GetByID(r.Context(), authData.ClientID)
	if err != nil {
		writeTokenError(w, "invalid_client", "client not found")
		return
	}

	// For public clients, only PKCE is allowed (no secret)
	if !cl.IsPublic {
		if clientSecret == "" {
			writeTokenError(w, "invalid_client", "client authentication required")
			return
		}
		if _, err := h.clientStore.AuthenticateClient(r.Context(), clientID, clientSecret); err != nil {
			writeTokenError(w, "invalid_client", "invalid client credentials")
			return
		}
	}

	// Validate PKCE if challenge was provided
	if authData.CodeChallenge != "" {
		if codeVerifier == "" {
			writeTokenError(w, "invalid_grant", "code_verifier required")
			return
		}
		if !validatePKCE(codeVerifier, authData.CodeChallenge, authData.ChallengeMethod) {
			writeTokenError(w, "invalid_grant", "code_verifier mismatch")
			return
		}
	}

	// Issue tokens
	if authData.UserID == "" {
		authData.UserID = "anonymous" // Should be set during consent
	}

	tokenPair, err := h.tokenService.GenerateTokenPair(r.Context(), authData.ClientID, authData.UserID, authData.Scopes)
	if err != nil {
		writeTokenError(w, "server_error", "failed to issue token")
		return
	}

	// If openid scope, include ID token
	if containsScope(authData.Scopes, "openid") {
		userInfo := map[string]interface{}{
			"preferred_username": authData.UserID,
		}
		idToken, err := h.tokenService.GenerateIDToken(r.Context(), authData.ClientID, authData.UserID, authData.Scopes, "", userInfo)
		if err == nil {
			tokenPair.IDToken = idToken
		}
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

func (h *Handler) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		clientID = r.Form.Get("client_id")
		clientSecret = r.Form.Get("client_secret")
	}

	if clientID == "" || clientSecret == "" {
		writeTokenError(w, "invalid_client", "client authentication required")
		return
	}

	cl, err := h.clientStore.AuthenticateClient(r.Context(), clientID, clientSecret)
	if err != nil {
		writeTokenError(w, "invalid_client", "invalid client credentials")
		return
	}

	if !cl.HasGrant("client_credentials") {
		writeTokenError(w, "unauthorized_client", "client_credentials grant not allowed")
		return
	}

	scope := r.Form.Get("scope")
	scopes := strings.Split(scope, " ")
	if scope == "" {
		scopes = cl.Scopes
	}

	tokenPair, err := h.tokenService.GenerateTokenPair(r.Context(), cl.ID, cl.ID, scopes)
	if err != nil {
		writeTokenError(w, "server_error", "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	// Try Basic auth
	if clientID == "" || clientSecret == "" {
		cID, cSecret, ok := r.BasicAuth()
		if ok {
			clientID = cID
			clientSecret = cSecret
		}
	}

	if refreshToken == "" {
		writeTokenError(w, "invalid_request", "refresh_token is required")
		return
	}

	// Authenticate client for confidential clients
	cl, err := h.clientStore.GetByID(r.Context(), clientID)
	if err != nil {
		writeTokenError(w, "invalid_client", "client not found")
		return
	}

	if !cl.IsPublic {
		if _, err := h.clientStore.AuthenticateClient(r.Context(), clientID, clientSecret); err != nil {
			writeTokenError(w, "invalid_client", "invalid client credentials")
			return
		}
	}

	tokenPair, err := h.tokenService.RefreshToken(r.Context(), refreshToken, clientID)
	if err != nil {
		writeTokenError(w, "invalid_grant", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

// Revoke handles token revocation (RFC 7009).
func (h *Handler) Revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeTokenError(w, "invalid_request", "failed to parse form")
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		writeTokenError(w, "invalid_request", "token is required")
		return
	}

	// Always return 200 per RFC 7009
	_ = h.tokenService.RevokeToken(r.Context(), token)
	w.WriteHeader(http.StatusOK)
}

// Introspect handles token introspection (RFC 7662).
func (h *Handler) Introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	result, err := h.tokenService.IntrospectToken(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// UserInfo handles the OIDC userinfo endpoint.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "missing or invalid access token")
		return
	}

	claims, err := h.tokenService.ValidateAccessToken(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	userInfo := map[string]interface{}{
		"sub": claims.Subject,
	}

	// Try to load user details
	if u, err := h.userService.GetByUsername(r.Context(), claims.Subject); err == nil {
		userInfo["preferred_username"] = u.Username
		if u.Email != nil {
			userInfo["email"] = *u.Email
		}
		if u.DisplayName != nil {
			userInfo["name"] = *u.DisplayName
		}
		if u.AvatarURL != nil {
			userInfo["picture"] = *u.AvatarURL
		}
	}

	// Filter by scope
	scopes := strings.Split(claims.Scope, " ")
	result := map[string]interface{}{"sub": userInfo["sub"]}
	if containsScope(scopes, "profile") {
		if v, ok := userInfo["preferred_username"]; ok {
			result["preferred_username"] = v
		}
		if v, ok := userInfo["name"]; ok {
			result["name"] = v
		}
		if v, ok := userInfo["picture"]; ok {
			result["picture"] = v
		}
	}
	if containsScope(scopes, "email") {
		if v, ok := userInfo["email"]; ok {
			result["email"] = v
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// EndSession handles the OIDC end session endpoint.
func (h *Handler) EndSession(w http.ResponseWriter, r *http.Request) {
	// For now, just redirect to post_logout_redirect_uri if provided
	postLogoutURI := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogoutURI != "" {
		http.Redirect(w, r, postLogoutURI, http.StatusFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// --- Helper functions ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeTokenError(w http.ResponseWriter, code, description string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func validatePKCE(verifier, challenge, method string) bool {
	// For plain
	if method == "" || method == "plain" {
		return verifier == challenge
	}
	// For S256
	if method == "S256" {
		return computeS256(verifier) == challenge
	}
	return false
}

func computeS256(verifier string) string {
	// This would use SHA-256 and base64url encoding
	// Placeholder - actual implementation needs crypto/sha256
	h := sha256Sum(verifier)
	return base64URLEncode(h)
}

func bigIntToBase64URL(n *big.Int) string {
	return base64URLEncode(n.Bytes())
}

func intToBase64URL(e int) string {
	b := big.NewInt(int64(e)).Bytes()
	return base64URLEncode(b)
}
