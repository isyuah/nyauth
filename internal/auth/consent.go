package auth

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/client"
	"github.com/nyasharp/nyauth/internal/config"
	"github.com/nyasharp/nyauth/internal/session"
)

// ConsentHandler handles OAuth consent flow.
type ConsentHandler struct {
	sessionStore *session.Store
	tokenService *TokenService
	clientStore  *client.Store
	config       *config.Config
}

// NewConsentHandler creates a new consent handler.
func NewConsentHandler(sessionStore *session.Store, tokenService *TokenService, clientStore *client.Store, cfg *config.Config) *ConsentHandler {
	return &ConsentHandler{
		sessionStore: sessionStore,
		tokenService: tokenService,
		clientStore:  clientStore,
		config:       cfg,
	}
}

// GetConsent returns consent challenge data for the frontend to display.
func (h *ConsentHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
	challenge := r.URL.Query().Get("challenge")
	if challenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing challenge"})
		return
	}

	data, err := h.sessionStore.GetConsent(r.Context(), challenge)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired challenge"})
		return
	}

	// Get client info
	cl, err := h.clientStore.GetByID(r.Context(), data.ClientID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "client not found"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge":    challenge,
		"client_name":  cl.Name,
		"client_id":    cl.ID,
		"scopes":       data.Scopes,
		"redirect_uri": data.RedirectURI,
	})
}

// AcceptConsent processes the user's consent acceptance.
func (h *ConsentHandler) AcceptConsent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	data, err := h.sessionStore.ConsumeConsent(r.Context(), req.Challenge)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired challenge"})
		return
	}

	// Generate authorization code
	authCode := uuid.New().String()
	authData := &session.AuthorizationData{
		ClientID:        data.ClientID,
		UserID:          data.UserID,
		RedirectURI:     data.RedirectURI,
		Scopes:          data.Scopes,
		CodeChallenge:   data.CodeChallenge,
		ChallengeMethod: data.ChallengeMethod,
	}

	if err := h.sessionStore.SaveAuthorizationCode(r.Context(), authCode, authData, 5*time.Minute); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate code"})
		return
	}

	// Build redirect URL
	redirectURL := data.RedirectURI + "?code=" + authCode
	if data.State != "" {
		redirectURL += "&state=" + data.State
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	})
}

// DenyConsent processes the user's consent denial.
func (h *ConsentHandler) DenyConsent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}

	data, err := h.sessionStore.ConsumeConsent(r.Context(), req.Challenge)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or expired challenge"})
		return
	}

	redirectURL := data.RedirectURI + "?error=access_denied"
	if data.State != "" {
		redirectURL += "&state=" + data.State
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"redirect_url": redirectURL,
	})
}
