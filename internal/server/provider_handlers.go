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
	"github.com/nyasharp/nyauth/internal/user"
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
	if intent == "bind" || intent == "reauth" {
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

func (s *Server) handleProviderReauthentication(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request struct {
		ReturnTo string `json:"return_to"`
	}
	if r.ContentLength != 0 {
		if err := decodeJSON(w, r, &request); err != nil {
			writeAPIError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}
	s.beginProviderFlow(w, r, chi.URLParam(r, "provider"), "reauth", current.ID.String(), safeReturnPath(request.ReturnTo, "/profile"), true)
}

func (s *Server) providerCallbackFailure(w http.ResponseWriter, r *http.Request, intent, returnTo, code string, status int) {
	s.telemetry.RecordProviderEvent(r.Context(), "callback", intent, "failure", code, -1)
	event := "provider.callback_failed"
	switch intent {
	case "login":
		event = models.AuditUserLoginFailed
	case "bind":
		event = "identity.bind_failed"
	case "reauth":
		event = "user.reauthentication_failed"
	}
	s.enqueueAuditTargetResult(r.Context(), event, nil, "", "provider", chi.URLParam(r, "provider"), "failure", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{
		"intent": intent, "failure_reason": code, "http_status": status,
	})
	fallback := "/login"
	if intent == "bind" || intent == "reauth" {
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
	authStarted := time.Now()
	external, err := configured.Authenticate(r.Context(), code, s.providerCallbackURI(providerName), stateData["nonce"])
	if err != nil {
		s.telemetry.RecordProviderEvent(r.Context(), "authentication", intent, "failure", "provider_authentication_failed", time.Since(authStarted))
		s.providerCallbackFailure(w, r, intent, returnTo, "provider_authentication_failed", http.StatusBadGateway)
		return
	}
	s.telemetry.RecordProviderEvent(r.Context(), "authentication", intent, "success", "none", time.Since(authStarted))
	if intent == "bind" {
		s.finishIdentityBind(w, r, providerName, stateData["user_id"], stateData["session_digest"], returnTo, external)
		return
	}
	if intent == "reauth" {
		s.finishExternalReauthentication(w, r, providerName, stateData["user_id"], stateData["session_digest"], returnTo, external)
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
	if err != nil || current.Status != models.UserStatusActive ||
		current.AuthVersion != authenticated.Data.AuthVersion ||
		current.SessionVersion != authenticated.Data.SessionVersion {
		s.providerCallbackFailure(w, r, "bind", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	existing, err := s.identityStore.FindByExternal(r.Context(), providerName, external.ID)
	if err == nil {
		if existing.UserID == current.ID {
			s.telemetry.RecordProviderEvent(r.Context(), "callback", "bind", "success", "none", -1)
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
	if err := s.identityStore.Create(r.Context(), binding, audit.MutationAudit{
		Event: models.AuditIdentityBound, ActorID: current.ID, ActorName: current.Username,
		TargetType: "identity", TargetID: binding.ID.String(), Result: "success", RiskLevel: "high",
		IPAddress: requestIP(r), UserAgent: truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength),
	}); err != nil {
		s.providerCallbackFailure(w, r, "bind", returnTo, "binding_failed", http.StatusConflict)
		return
	}
	s.telemetry.RecordProviderEvent(r.Context(), "callback", "bind", "success", "none", -1)
	http.Redirect(w, r, safeReturnPath(returnTo, "/profile"), http.StatusFound)
}

func (s *Server) finishExternalReauthentication(w http.ResponseWriter, r *http.Request, providerName, expectedUserID, expectedSessionDigest, returnTo string, external *models.ExternalUser) {
	authenticated, err := s.sessionMiddleware.GetSession(r)
	actualSessionDigest := ""
	if err == nil {
		actualSessionDigest = providerSessionDigest(authenticated.ID)
	}
	if err != nil || authenticated.Data.UserID != expectedUserID || expectedSessionDigest == "" ||
		len(actualSessionDigest) != len(expectedSessionDigest) ||
		subtle.ConstantTimeCompare([]byte(actualSessionDigest), []byte(expectedSessionDigest)) != 1 {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	id, err := uuid.Parse(expectedUserID)
	if err != nil {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	current, err := s.userService.GetByID(r.Context(), id)
	if err != nil || current.Status != models.UserStatusActive ||
		current.AuthVersion != authenticated.Data.AuthVersion ||
		current.SessionVersion != authenticated.Data.SessionVersion {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "session_changed", http.StatusUnauthorized)
		return
	}
	binding, err := s.identityStore.FindByExternal(r.Context(), providerName, external.ID)
	if err != nil || binding.UserID != current.ID {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "identity_mismatch", http.StatusForbidden)
		return
	}
	ctx := withAuthenticatedSession(r.Context(), authenticated)
	requestWithSession := r.WithContext(ctx)
	_, mfaRequired, mfaErr := s.beginReauthenticationMFAPending(w, requestWithSession, current, "provider", providerName, returnTo)
	if mfaErr != nil {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "mfa_unavailable", http.StatusServiceUnavailable)
		return
	}
	if mfaRequired {
		s.telemetry.RecordProviderEvent(r.Context(), "callback", "reauth", "success", "mfa_required", -1)
		target := "/login/mfa?purpose=reauthentication&return_to=" + url.QueryEscape(safeReturnPath(returnTo, "/profile"))
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	updated, err := s.userService.RecordAuthentication(
		r.Context(), current.ID, current.AuthVersion, current.SessionVersion,
	)
	if err != nil {
		status := http.StatusInternalServerError
		code := "reauthentication_failed"
		if errors.Is(err, user.ErrAuthStateChanged) {
			status = http.StatusUnauthorized
			code = "account_changed"
		}
		s.providerCallbackFailure(w, r, "reauth", returnTo, code, status)
		return
	}
	if _, err := s.sessionMiddleware.MarkReauthenticated(requestWithSession, updated); err != nil {
		s.providerCallbackFailure(w, r, "reauth", returnTo, "session_failed", http.StatusServiceUnavailable)
		return
	}
	s.enqueueAuditTargetResult(r.Context(), "user.reauthenticated", &current.ID, current.Username, "provider", providerName, "success", "medium", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "provider"})
	s.telemetry.RecordAuthEvent(r.Context(), "reauthentication", "success")
	s.telemetry.RecordProviderEvent(r.Context(), "callback", "reauth", "success", "none", -1)
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
		current = &models.User{ID: uuid.New(), Username: externalUsername(providerName, external), DisplayName: &display, Status: models.UserStatusActive, Role: "user", AuthVersion: 1, SessionVersion: 1, Metadata: map[string]string{}}
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
	_, mfaRequired, mfaErr := s.beginMFAPending(w, r, current, "provider", providerName, returnTo)
	if mfaErr != nil {
		code := "mfa_unavailable"
		status := http.StatusServiceUnavailable
		if errors.Is(mfaErr, errMFAEnrollmentRequired) {
			code = "mfa_enrollment_required"
			status = http.StatusForbidden
		}
		s.providerCallbackFailure(w, r, "login", returnTo, code, status)
		return
	}
	if mfaRequired {
		s.telemetry.RecordProviderEvent(r.Context(), "callback", "login", "success", "mfa_required", -1)
		target := "/login/mfa?return_to=" + url.QueryEscape(safeReturnPath(returnTo, "/dashboard"))
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	if _, err := s.sessionMiddleware.CreateSession(w, r, current); err != nil {
		s.providerCallbackFailure(w, r, "login", returnTo, "session_failed", http.StatusInternalServerError)
		return
	}
	s.enqueueAuditResult(r.Context(), models.AuditUserLogin, &current.ID, current.Username, "success", "low", requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), map[string]any{"authentication_method": "provider", "provider": providerName})
	_ = s.userService.RecordLogin(r.Context(), current.ID, requestIP(r))
	s.telemetry.RecordProviderEvent(r.Context(), "callback", "login", "success", "none", -1)
	http.Redirect(w, r, safeReturnPath(returnTo, "/dashboard"), http.StatusFound)
}

func (s *Server) handleAdminListProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT id,name,type,client_id,scopes,discovery_url,authorization_url,token_url,userinfo_url,enabled,revision,metadata,created_at,updated_at FROM oauth_providers ORDER BY name`)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	defer rows.Close()
	items := make([]models.ExternalProvider, 0)
	for rows.Next() {
		var item models.ExternalProvider
		if err := rows.Scan(&item.ID, &item.Name, &item.Type, &item.ClientID, &item.Scopes, &item.DiscoveryURL, &item.AuthorizationURL, &item.TokenURL, &item.UserinfoURL, &item.Enabled, &item.Revision, &item.Metadata, &item.CreatedAt, &item.UpdatedAt); err != nil {
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
	if request.Enabled == nil {
		return errors.New("enabled must be explicitly set")
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
	var request models.CreateProviderRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateProviderRequest(request); err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	created, err := s.providerMgr.CreateProvider(r.Context(), request, mutation)
	if err != nil {
		writeAPIError(w, http.StatusConflict, "failed to create provider")
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) handleAdminUpdateProvider(w http.ResponseWriter, r *http.Request) {
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
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	updated, err := s.providerMgr.UpdateProvider(r.Context(), name, request, mutation)
	if err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			writeAPIError(w, http.StatusNotFound, "provider not found")
		} else {
			writeAPIError(w, http.StatusConflict, "provider configuration could not be updated")
		}
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
func (s *Server) handleAdminDeleteProvider(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "id")
	mutation, ok := audit.MutationAuditFromContext(r.Context())
	if !ok {
		writeAPIError(w, http.StatusInternalServerError, "audit context unavailable")
		return
	}
	if err := s.providerMgr.DeleteProvider(r.Context(), name, mutation); err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			writeAPIError(w, http.StatusNotFound, "provider not found")
		} else {
			writeAPIError(w, http.StatusInternalServerError, "failed to delete provider")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (s *Server) handleTestProvider(w http.ResponseWriter, r *http.Request) {
	actor := currentUserFromContext(r)
	name := chi.URLParam(r, "id")
	result, err := s.providerMgr.ValidateStoredProvider(r.Context(), name)
	if err != nil {
		if errors.Is(err, provider.ErrProviderNotFound) {
			writeAPIError(w, http.StatusNotFound, "provider not found")
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, "provider configuration could not be validated")
		}
		return
	}
	success := result.ConfigurationValid && result.AuthorizationEndpointValid
	auditResult := "failure"
	if success {
		auditResult = "success"
	}
	riskLevel := "low"
	if auditResult == "failure" {
		riskLevel = "medium"
	}
	s.enqueueAuditTargetResult(r.Context(), models.AuditProviderTested, &actor.ID, actor.Username, "provider", name, auditResult, riskLevel, requestIP(r), truncateAuditValue(r.UserAgent(), maxAuditUserAgentLength), nil)
	writeJSON(w, http.StatusOK, result)
}
