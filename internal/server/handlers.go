package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/pkg/models"
)

// handleLogin handles username/password login.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := s.userService.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		audit.Record(r.Context(), s.auditStore, models.AuditUserLoginFailed, nil, req.Username, audit.GetIP(r))
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}

	// Record login audit + update last_login
	ip := audit.GetIP(r)
	audit.Record(r.Context(), s.auditStore, models.AuditUserLogin, &user.ID, user.Username, ip)
	_ = s.userService.RecordLogin(r.Context(), user.ID, ip)

	// Create session cookie for consent flow
	_ = s.sessionMiddleware.CreateSession(w, r, user.ID.String(), user.Username)

	tokenPair, err := s.tokenService.GenerateTokenPair(r.Context(), "nyauth-web", user.ID.String(), []string{"openid", "profile", "email"})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue token"})
		return
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

// handleLogout handles logout (revoke the current token).
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token != "" {
		claims, err := s.tokenService.ValidateAccessToken(r.Context(), token)
		if err == nil {
			_ = s.tokenService.RevokeToken(r.Context(), claims.ID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// handleMe returns the current user's information.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}

	claims, err := s.tokenService.ValidateAccessToken(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	user, err := s.userService.GetByUsername(r.Context(), claims.Subject)
	if err != nil {
		// Try by ID
		id, parseErr := uuid.Parse(claims.Subject)
		if parseErr != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		user, err = s.userService.GetByID(r.Context(), id)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
	}

	writeJSON(w, http.StatusOK, user)
}

// handleUpdateMe updates the current user's information.
func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	token := extractBearerToken(r)
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing token"})
		return
	}

	claims, err := s.tokenService.ValidateAccessToken(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid token"})
		return
	}

	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}

	var req models.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	user, err := s.userService.Update(r.Context(), id, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// handleListProviders returns the list of available external OAuth providers.
func (s *Server) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers := s.providerMgr.List()
	writeJSON(w, http.StatusOK, providers)
}

// handleProviderAuthorize initiates an external OAuth flow.
func (s *Server) handleProviderAuthorize(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	p, ok := s.providerMgr.Get(providerName)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}

	state, _ := crypto.GenerateRandomString(32)

	// Store CSRF state
	stateData := map[string]string{
		"provider":    providerName,
		"redirect_to": r.URL.Query().Get("redirect_to"),
	}
	_ = s.sessionStore.SaveCSRFState(r.Context(), state, stateData, 10*60) // 10 min

	redirectURI := s.cfg.Auth.Issuer + "/auth/" + providerName + "/callback"
	authURL := p.GetAuthorizationURL(state, redirectURI)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleProviderCallback handles the callback from an external OAuth provider.
func (s *Server) handleProviderCallback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing code or state"})
		return
	}

	// Validate CSRF state
	stateData, err := s.sessionStore.ConsumeCSRFState(r.Context(), state)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired state"})
		return
	}
	_ = stateData

	p, ok := s.providerMgr.Get(providerName)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "provider not found"})
		return
	}

	redirectURI := s.cfg.Auth.Issuer + "/auth/" + providerName + "/callback"
	token, err := p.ExchangeCode(r.Context(), code, redirectURI)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to exchange code"})
		return
	}

	extUser, err := p.GetUserInfo(r.Context(), token)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get user info"})
		return
	}

	// Look up existing identity
	identity, err := s.identityStore.FindByExternal(r.Context(), providerName, extUser.ID)
	if err == nil {
		// Existing identity - issue token
		tokenPair, err := s.tokenService.GenerateTokenPair(r.Context(), "nyauth-external", identity.UserID.String(), []string{"openid", "profile", "email"})
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue token"})
			return
		}
		writeJSON(w, http.StatusOK, tokenPair)
		return
	}

	// New identity - create user and binding
	newUser, err := s.userService.Create(r.Context(), models.CreateUserRequest{
		Username:    providerName + "_" + extUser.Username,
		Email:       extUser.Email,
		Password:    string(mustGenerateRandom(32)), // random password for OAuth users
		DisplayName: extUser.Username,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create user"})
		return
	}

	newIdentity := &models.Identity{
		ID:               uuid.New(),
		UserID:           newUser.ID,
		Provider:         providerName,
		ExternalID:       extUser.ID,
		ExternalUsername: &extUser.Username,
		ExternalEmail:    &extUser.Email,
	}
	if token.AccessToken != "" {
		newIdentity.AccessToken = &token.AccessToken
	}
	if token.RefreshToken != "" {
		newIdentity.RefreshToken = &token.RefreshToken
	}

	if err := s.identityStore.Create(r.Context(), newIdentity); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create identity binding"})
		return
	}

	tokenPair, err := s.tokenService.GenerateTokenPair(r.Context(), "nyauth-external", newUser.ID.String(), []string{"openid", "profile", "email"})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to issue token"})
		return
	}

	writeJSON(w, http.StatusOK, tokenPair)
}

// --- Admin handlers ---

func (s *Server) handleAdminListProviders(w http.ResponseWriter, r *http.Request) {
	providers := s.providerMgr.List()
	writeJSON(w, http.StatusOK, providers)
}

func (s *Server) handleAdminCreateProvider(w http.ResponseWriter, r *http.Request) {
	var req models.CreateProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	p, err := s.providerMgr.CreateProvider(r.Context(), req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleAdminUpdateProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "id")
	var body struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Scopes       []string `json:"scopes"`
		Enabled      *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	// Build dynamic update
	sets := []string{}
	args := []interface{}{}
	argIdx := 1

	if body.ClientID != "" {
		sets = append(sets, fmt.Sprintf("client_id=$%d", argIdx))
		args = append(args, body.ClientID)
		argIdx++
	}
	if body.ClientSecret != "" {
		// Encrypt the secret
		encSecret, err := crypto.Encrypt([]byte(body.ClientSecret), s.encryptionKey())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encrypt secret"})
			return
		}
		sets = append(sets, fmt.Sprintf("client_secret=$%d", argIdx))
		args = append(args, string(encSecret))
		argIdx++
	}
	if body.Enabled != nil {
		sets = append(sets, fmt.Sprintf("enabled=$%d", argIdx))
		args = append(args, *body.Enabled)
		argIdx++
	}

	if len(sets) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "nothing to update"})
		return
	}

	sets = append(sets, "updated_at=NOW()")
	args = append(args, name)

	query := fmt.Sprintf("UPDATE oauth_providers SET %s WHERE name=$%d", strings.Join(sets, ", "), argIdx)
	_, err := s.db.Exec(r.Context(), query, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	// Reload providers
	s.providerMgr.LoadDynamic(r.Context())

	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) encryptionKey() []byte {
	key := []byte(s.cfg.Auth.EncryptionKey)
	if len(key) < 32 {
		padded := make([]byte, 32)
		copy(padded, key)
		key = padded
	}
	return key
}

func (s *Server) handleAdminDeleteProvider(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func (s *Server) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	providerID := chi.URLParam(r, "id")

	// Try to get from the live provider manager first
	p, ok := s.providerMgr.Get(providerID)
	if !ok {
		// Try to find in the database
		ctx := r.Context()
		var discoveryURL, authURL string
		err := s.db.QueryRow(ctx, `SELECT COALESCE(discovery_url, ''), COALESCE(authorization_url, '') FROM oauth_providers WHERE name = $1`, providerID).Scan(&discoveryURL, &authURL)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]interface{}{"success": false, "error": "provider not found"})
			return
		}
		// Test by fetching the discovery URL or auth URL
		testURL := discoveryURL
		if testURL == "" {
			testURL = authURL
		}
		if testURL == "" {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": false, "latency_ms": 0, "error": "no URL configured to test"})
			return
		}
		start := time.Now()
		client := &http.Client{Timeout: 10 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "GET", testURL, nil)
		resp, err := client.Do(req)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]interface{}{"success": false, "latency_ms": latency, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": resp.StatusCode >= 200 && resp.StatusCode < 400,
			"latency_ms": latency,
			"status_code": resp.StatusCode,
			"provider": providerID,
		})
		return
	}

	// Provider exists in manager — test by fetching its authorization URL
	ctx := r.Context()
	start := time.Now()
	redirectURI := s.cfg.Auth.Issuer + "/auth/" + providerID + "/callback"
	authURL := p.GetAuthorizationURL("test", redirectURI)
	// We can't really test auth URL (it redirects), so just check the provider base
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(ctx, "GET", authURL, nil)
	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"success": false, "latency_ms": latency, "error": err.Error(), "provider": p.Name(), "type": p.Type()})
		return
	}
	defer resp.Body.Close()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    resp.StatusCode >= 200 && resp.StatusCode < 500,
		"latency_ms": latency,
		"status_code": resp.StatusCode,
		"provider":   p.Name(),
		"type":       p.Type(),
	})
}

// --- User management ---

func (s *Server) handleUserIdentities(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}
	identities, err := s.identityStore.ListByUser(r.Context(), id)
	if err != nil || identities == nil {
		writeJSON(w, http.StatusOK, []interface{}{})
		return
	}
	writeJSON(w, http.StatusOK, identities)
}

func (s *Server) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}
	status := models.UserStatusSuspended
	user, err := s.userService.Update(r.Context(), id, models.UpdateUserRequest{Status: &status})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditUserSuspended, nil, "admin", "user", id.String(), audit.GetIP(r))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleActivateUser(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}
	status := models.UserStatusActive
	user, err := s.userService.Update(r.Context(), id, models.UpdateUserRequest{Status: &status})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditUserActivated, nil, "admin", "user", id.String(), audit.GetIP(r))
	writeJSON(w, http.StatusOK, user)
}

func (s *Server) handleUpdateUserRole(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user ID"})
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Role != "admin" && body.Role != "user") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be 'admin' or 'user'"})
		return
	}
	role := body.Role
	user, err := s.userService.Update(r.Context(), id, models.UpdateUserRequest{Metadata: map[string]string{"_role": role}})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// --- Audit logs ---

func (s *Server) handleListAuditLogs(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	event := r.URL.Query().Get("event")

	result, err := s.auditStore.List(r.Context(), page, pageSize, event)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// --- Utilities ---

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

func mustGenerateRandom(n int) []byte {
	b, _ := crypto.GenerateRandomString(n)
	return []byte(b)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
