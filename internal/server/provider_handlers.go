package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/crypto"
	"github.com/nyasharp/nyauth/internal/identity"
	"github.com/nyasharp/nyauth/internal/provider"
	"github.com/nyasharp/nyauth/pkg/models"
)

const (
	providerStateTTL      = 10 * time.Minute
	providerFlowCookie    = "nyauth_provider_flow"
	providerFlowCookieAge = 10 * time.Minute
)

func safeReturnPath(value, fallback string) string {
	if value == "" || len(value) > 2048 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.Contains(value, "\\") {
		return fallback
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fallback
		}
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return fallback
	}
	return parsed.String()
}
func (s *Server) providerCallbackURI(name string) string {
	return strings.TrimRight(s.cfg.Auth.Issuer, "/") + "/auth/" + url.PathEscape(name) + "/callback"
}

func (s *Server) setProviderFlowCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: providerFlowCookie, Value: value, Path: "/auth/", HttpOnly: true,
		Secure: s.cfg.Server.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: int(providerFlowCookieAge.Seconds()), Expires: time.Now().Add(providerFlowCookieAge),
	})
}

func (s *Server) clearProviderFlowCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: providerFlowCookie, Value: "", Path: "/auth/", HttpOnly: true,
		Secure: s.cfg.Server.SecureCookie, SameSite: http.SameSiteLaxMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func validProviderFlowCookie(value, expectedDigest string) bool {
	if value == "" || expectedDigest == "" {
		return false
	}
	actualDigest := providerSessionDigest(value)
	return len(actualDigest) == len(expectedDigest) &&
		subtle.ConstantTimeCompare([]byte(actualDigest), []byte(expectedDigest)) == 1
}

func (s *Server) beginProviderFlow(w http.ResponseWriter, r *http.Request, providerName, intent, userID, returnTo string, jsonResponse bool) {
	configured, ok := s.providerMgr.Get(providerName)
	if !ok {
		writeAPIError(w, http.StatusNotFound, "provider not found")
		return
	}
	state, err := crypto.GenerateRandomString(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start provider login")
		return
	}
	nonce, err := crypto.GenerateRandomString(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start provider login")
		return
	}
	flowSecret, err := crypto.GenerateRandomString(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to start provider login")
		return
	}
	stateData := map[string]string{
		"provider": providerName, "intent": intent, "user_id": userID,
		"return_to": safeReturnPath(returnTo, "/"), "nonce": nonce,
		"flow_digest": providerSessionDigest(flowSecret),
	}
	if intent == "bind" {
		authenticated := sessionFromContext(r.Context())
		if authenticated == nil {
			writeAPIError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		stateData["session_digest"] = providerSessionDigest(authenticated.ID)
	}
	if err := s.sessionStore.SaveCSRFState(r.Context(), state, stateData, providerStateTTL); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, "failed to start provider login")
		return
	}
	s.setProviderFlowCookie(w, flowSecret)
	redirect := configured.AuthorizationURL(state, nonce, s.providerCallbackURI(providerName))
	if jsonResponse {
		writeJSON(w, http.StatusOK, map[string]string{"redirect_url": redirect})
		return
	}
	http.Redirect(w, r, redirect, http.StatusFound)
}
func (s *Server) handleProviderAuthorize(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "provider")
	s.beginProviderFlow(w, r, name, "login", "", safeReturnPath(r.URL.Query().Get("return_to"), "/dashboard"), false)
}
func (s *Server) handleProviderBind(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	var request struct {
		ReturnTo string `json:"return_to"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}
	s.beginProviderFlow(w, r, chi.URLParam(r, "provider"), "bind", current.ID.String(), safeReturnPath(request.ReturnTo, "/profile"), true)
}

func (s *Server) providerCallbackFailure(w http.ResponseWriter, r *http.Request, intent, returnTo, code string, status int) {
	fallback := "/login"
	if intent == "bind" {
		fallback = "/profile"
	}
	target := safeReturnPath(returnTo, fallback)
	parsed, _ := url.Parse(target)
	query := parsed.Query()
	query.Set("auth_error", code)
	parsed.RawQuery = query.Encode()
	http.Redirect(w, r, parsed.String(), http.StatusFound)
}

func (s *Server) handleProviderCallback(w http.ResponseWriter, r *http.Request) {
	flowCookie, flowCookieErr := r.Cookie(providerFlowCookie)
	s.clearProviderFlowCookie(w)
	providerName := chi.URLParam(r, "provider")
	state := r.URL.Query().Get("state")
	if state == "" {
		s.providerCallbackFailure(w, r, "", "", "invalid_state", http.StatusBadRequest)
		return
	}
	stateData, err := s.sessionStore.ConsumeCSRFState(r.Context(), state)
	if err != nil || stateData["provider"] != providerName {
		s.providerCallbackFailure(w, r, "", "", "invalid_state", http.StatusBadRequest)
		return
	}
	intent := stateData["intent"]
	returnTo := stateData["return_to"]
	if flowCookieErr != nil || !validProviderFlowCookie(flowCookie.Value, stateData["flow_digest"]) {
		s.providerCallbackFailure(w, r, intent, returnTo, "invalid_state", http.StatusBadRequest)
		return
	}
	if upstreamError := r.URL.Query().Get("error"); upstreamError != "" {
		s.providerCallbackFailure(w, r, intent, returnTo, "provider_denied", http.StatusBadRequest)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		s.providerCallbackFailure(w, r, intent, returnTo, "missing_code", http.StatusBadRequest)
		return
	}
	configured, ok := s.providerMgr.Get(providerName)
	if !ok {
		s.providerCallbackFailure(w, r, intent, returnTo, "provider_unavailable", http.StatusBadRequest)
		return
	}
	external, err := configured.Authenticate(r.Context(), code, s.providerCallbackURI(providerName), stateData["nonce"])
	if err != nil {
		s.providerCallbackFailure(w, r, intent, returnTo, "provider_authentication_failed", http.StatusBadGateway)
		return
	}
	if intent == "bind" {
		s.finishIdentityBind(w, r, providerName, stateData["user_id"], stateData["session_digest"], returnTo, external)
		return
	}
	s.finishExternalLogin(w, r, providerName, returnTo, external)
}

func providerSessionDigest(sessionID string) string {
	digest := sha256.Sum256([]byte(sessionID))
	return hex.EncodeToString(digest[:])
}

func (s *Server) finishIdentityBind(w http.ResponseWriter, r *http.Request, providerName, expectedUserID, expectedSessionDigest, returnTo string, external *models.ExternalUser) {
	authenticated, err := s.sessionMiddleware.GetSession(r)
	actualSessionDigest := ""
	if err == nil {
		actualSessionDigest = providerSessionDigest(authenticated.ID)
	}
	if err != nil || authenticated.Data.UserID != expectedUserID || expectedSessionDigest == "" ||
		len(actualSessionDigest) != len(expectedSessionDigest) ||
		subtle.ConstantTimeCompare([]byte(actualSessionDigest), []byte(expectedSessionDigest)) != 1 {
		s.providerCallbackFailure(w, r, "bind", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(expectedUserID)
	if err != nil {
		s.providerCallbackFailure(w, r, "bind", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	current, err := s.userService.GetByID(r.Context(), id)
	if err != nil || current.Status != models.UserStatusActive || current.AuthVersion != authenticated.Data.AuthVersion {
		s.providerCallbackFailure(w, r, "bind", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	existing, err := s.identityStore.FindByExternal(r.Context(), providerName, external.ID)
	if err == nil {
		if existing.UserID == current.ID {
			http.Redirect(w, r, safeReturnPath(returnTo, "/profile"), http.StatusFound)
			return
		}
		s.providerCallbackFailure(w, r, "bind", returnTo, "identity_already_bound", http.StatusConflict)
		return
	}
	if !identity.IsNotFound(err) {
		s.providerCallbackFailure(w, r, "bind", returnTo, "binding_failed", http.StatusInternalServerError)
		return
	}
	binding := identityFromExternal(providerName, current.ID, external)
	if err := s.identityStore.Create(r.Context(), binding); err != nil {
		s.providerCallbackFailure(w, r, "bind", returnTo, "binding_failed", http.StatusConflict)
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, "identity.bound", &current.ID, current.Username, "identity", binding.ID.String(), requestIP(r))
	http.Redirect(w, r, safeReturnPath(returnTo, "/profile"), http.StatusFound)
}

func identityFromExternal(providerName string, userID uuid.UUID, external *models.ExternalUser) *models.Identity {
	binding := &models.Identity{ID: uuid.New(), UserID: userID, Provider: providerName, ExternalID: external.ID, Metadata: map[string]string{}}
	if external.Username != "" {
		binding.ExternalUsername = &external.Username
	}
	if external.EmailVerified && external.Email != "" {
		binding.ExternalEmail = &external.Email
	}
	return binding
}
func externalUsername(providerName string, external *models.ExternalUser) string {
	base := strings.ToLower(providerName + "_" + external.Username)
	var cleaned strings.Builder
	for _, r := range base {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.' {
			cleaned.WriteRune(r)
		} else {
			cleaned.WriteByte('_')
		}
	}
	digest := sha256.Sum256([]byte(providerName + "\x00" + external.ID))
	suffix := "_" + hex.EncodeToString(digest[:4])
	value := strings.Trim(cleaned.String(), "_.-")
	if value == "" {
		value = "external"
	}
	if len(value) > 64-len(suffix) {
		value = value[:64-len(suffix)]
	}
	return value + suffix
}
func (s *Server) finishExternalLogin(w http.ResponseWriter, r *http.Request, providerName, returnTo string, external *models.ExternalUser) {
	binding, err := s.identityStore.FindByExternal(r.Context(), providerName, external.ID)
	var current *models.User
	if err == nil {
		current, err = s.userService.GetByID(r.Context(), binding.UserID)
	} else if identity.IsNotFound(err) {
		display := external.Username
		if display == "" {
			display = providerName + " user"
		}
		current = &models.User{ID: uuid.New(), Username: externalUsername(providerName, external), DisplayName: &display, Status: models.UserStatusActive, Role: "user", AuthVersion: 1, Metadata: map[string]string{}}
		if external.AvatarURL != "" {
			current.AvatarURL = &external.AvatarURL
		}
		if external.EmailVerified && external.Email != "" {
			current.Email = &external.Email
		}
		binding = identityFromExternal(providerName, current.ID, external)
		err = s.identityStore.CreateUserAndIdentity(r.Context(), current, binding)
		if identity.IsUserEmailConflict(err) {
			// A verified upstream email is identity evidence, not authority to
			// merge with an existing local account. Keep it on the identity and
			// retry the independent local account with no users.email value.
			current.Email = nil
			err = s.identityStore.CreateUserAndIdentity(r.Context(), current, binding)
		}
		if err != nil {
			binding, err = s.identityStore.FindByExternal(r.Context(), providerName, external.ID)
			if err == nil {
				current, err = s.userService.GetByID(r.Context(), binding.UserID)
			}
		}
	}
	if err != nil || current == nil || current.Status != models.UserStatusActive {
		s.providerCallbackFailure(w, r, "login", returnTo, "account_unavailable", http.StatusForbidden)
		return
	}
	if _, err := s.sessionMiddleware.CreateSession(w, r, current); err != nil {
		s.providerCallbackFailure(w, r, "login", returnTo, "session_failed", http.StatusInternalServerError)
		return
	}
	audit.RecordResult(r.Context(), s.auditStore, models.AuditUserLogin, &current.ID, current.Username, "success", requestIP(r))
	_ = s.userService.RecordLogin(r.Context(), current.ID, requestIP(r))
	http.Redirect(w, r, safeReturnPath(returnTo, "/dashboard"), http.StatusFound)
}

func (s *Server) handleAdminListProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT id,name,type,client_id,scopes,discovery_url,authorization_url,token_url,userinfo_url,enabled,metadata,created_at,updated_at FROM oauth_providers ORDER BY name`)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	defer rows.Close()
	items := make([]models.ExternalProvider, 0)
	for rows.Next() {
		var item models.ExternalProvider
		if err := rows.Scan(&item.ID, &item.Name, &item.Type, &item.ClientID, &item.Scopes, &item.DiscoveryURL, &item.AuthorizationURL, &item.TokenURL, &item.UserinfoURL, &item.Enabled, &item.Metadata, &item.CreatedAt, &item.UpdatedAt); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "failed to list providers")
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	writeJSON(w, http.StatusOK, items)
}
func validateProviderRequest(request models.CreateProviderRequest) error {
	if err := provider.ValidateName(request.Name); err != nil {
		return err
	}
	if strings.TrimSpace(request.ClientID) == "" || request.ClientSecret == "" {
		return errors.New("client_id and client_secret are required")
	}
	switch request.Type {
	case "github", "google":
	case "generic":
		parsed, err := url.Parse(request.DiscoveryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return errors.New("generic providers require an HTTPS discovery URL")
		}
	default:
		return errors.New("unsupported provider type")
	}
	return nil
}

func emptyProviderUpdate(request models.UpdateProviderRequest) bool {
	return request.ClientID == nil && request.ClientSecret == nil && request.Scopes == nil &&
		request.DiscoveryURL == nil && request.AuthorizationURL == nil && request.TokenURL == nil &&
		request.UserinfoURL == nil && request.Enabled == nil
}

func (s *Server) handleAdminCreateProvider(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	var request models.CreateProviderRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateProviderRequest(request); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	created, err := s.providerMgr.CreateProvider(r.Context(), request)
	if err != nil {
		writeAPIError(w, http.StatusConflict, "failed to create provider")
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditProviderCreated, &actor.ID, actor.Username, "provider", created.Name, requestIP(r))
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleAdminUpdateProvider(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	name := chi.URLParam(r, "id")
	var request models.UpdateProviderRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if emptyProviderUpdate(request) {
		writeAPIError(w, http.StatusBadRequest, "nothing to update")
		return
	}
	if request.ClientID != nil {
		if strings.TrimSpace(*request.ClientID) == "" {
			writeAPIError(w, http.StatusBadRequest, "client_id cannot be empty")
			return
		}
		trimmed := strings.TrimSpace(*request.ClientID)
		request.ClientID = &trimmed
	}
	if request.ClientSecret != nil {
		if *request.ClientSecret == "" {
			writeAPIError(w, http.StatusBadRequest, "client_secret cannot be empty")
			return
		}
	}
	if request.DiscoveryURL != nil {
		parsed, err := url.Parse(*request.DiscoveryURL)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
			writeAPIError(w, http.StatusBadRequest, "discovery_url must use HTTPS")
			return
		}
	}
	updated, err := s.providerMgr.UpdateProvider(r.Context(), name, request)
	if err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			writeAPIError(w, http.StatusNotFound, "provider not found")
		} else {
			writeAPIError(w, http.StatusConflict, "provider configuration could not be updated")
		}
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, "provider.updated", &actor.ID, actor.Username, "provider", name, requestIP(r))
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleAdminDeleteProvider(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	name := chi.URLParam(r, "id")
	if err := s.providerMgr.DeleteProvider(r.Context(), name); err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			writeAPIError(w, http.StatusNotFound, "provider not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to delete provider")
		}
		return
	}
	audit.RecordWithTarget(r.Context(), s.auditStore, models.AuditProviderDeleted, &actor.ID, actor.Username, "provider", name, requestIP(r))
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	name := chi.URLParam(r, "id")
	configured, ok := s.providerMgr.Get(name)
	if !ok {
		audit.RecordTargetResult(r.Context(), s.auditStore, models.AuditProviderTested, &actor.ID, actor.Username, "provider", name, "failure", requestIP(r))
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error": "provider is disabled or unavailable"})
		return
	}
	state, err := crypto.GenerateRandomString(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to test provider")
		return
	}
	nonce, err := crypto.GenerateRandomString(32)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to test provider")
		return
	}
	authorizationURL := configured.AuthorizationURL(state, nonce, s.providerCallbackURI(name))
	parsed, err := url.Parse(authorizationURL)
	success := err == nil && parsed.Scheme == "https" && parsed.Host != ""
	result := "failure"
	if success {
		result = "success"
	}
	audit.RecordTargetResult(r.Context(), s.auditStore, models.AuditProviderTested, &actor.ID, actor.Username, "provider", name, result, requestIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"success": success, "provider": name, "type": configured.Type()})
}
