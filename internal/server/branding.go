package server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/nyasharp/nyauth/internal/settings"
)

const (
	brandingTitleMaxLength   = 64
	brandingLogoURLMaxLength = 512
)

type brandingUpdateRequest struct {
	Title   string `json:"title"`
	LogoURL string `json:"logo_url"`
}

func (s *Server) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsMgr.Branding())
}

func (s *Server) handleUpdateBranding(w http.ResponseWriter, r *http.Request) {
	current := currentUserFromContext(r)
	if current == nil {
		writeAPIError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var request brandingUpdateRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeAPIError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	branding, err := validateBranding(request.Title, request.LogoURL)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.settingsMgr.SetBranding(r.Context(), branding, current.Username); err != nil {
		writeAPIError(w, http.StatusInternalServerError, "failed to store branding settings")
		return
	}
	writeJSON(w, http.StatusOK, branding)
}

func validateBranding(title, logoURL string) (settings.Branding, error) {
	title = strings.TrimSpace(title)
	logoURL = strings.TrimSpace(logoURL)
	if title == "" {
		return settings.Branding{}, fmt.Errorf("title is required")
	}
	if utf8.RuneCountInString(title) > brandingTitleMaxLength {
		return settings.Branding{}, fmt.Errorf("title must be at most %d characters", brandingTitleMaxLength)
	}
	if logoURL != "" {
		if len(logoURL) > brandingLogoURLMaxLength {
			return settings.Branding{}, fmt.Errorf("logo_url must be at most %d characters", brandingLogoURLMaxLength)
		}
		parsed, err := url.Parse(logoURL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil {
			return settings.Branding{}, fmt.Errorf("logo_url must be an absolute HTTP(S) URL without credentials")
		}
	}
	return settings.Branding{Title: title, LogoURL: logoURL}, nil
}
