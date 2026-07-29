package server

import (
	"errors"
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
	ExpectedRevision int64  `json:"expected_revision"`
	Title            string `json:"title"`
	LogoURL          string `json:"logo_url"`
}

type brandingSettingsResponse struct {
	Revision int64 `json:"revision"`
	settings.Branding
}

func (s *Server) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.settingsMgr.Branding())
}

func (s *Server) handleUpdateBranding(w http.ResponseWriter, r *http.Request) {
	current, mutation, ok := s.authorizePolicySettingsMutation(w, r)
	if !ok {
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
	revision, err := s.settingsMgr.SetBranding(
		r.Context(), branding, request.ExpectedRevision, current.Username, mutation,
	)
	if err != nil {
		if errors.Is(err, settings.ErrRevisionConflict) {
			writeAPIError(w, http.StatusConflict, "settings revision conflict")
			return
		}
		writeAPIError(w, http.StatusInternalServerError, "failed to store branding settings")
		return
	}
	writeJSON(w, http.StatusOK, brandingSettingsResponse{Revision: revision, Branding: branding})
}

func (s *Server) handleGetBrandingSettings(w http.ResponseWriter, _ *http.Request) {
	snapshot := s.settingsMgr.BrandingSnapshot()
	writeJSON(w, http.StatusOK, brandingSettingsResponse{Revision: snapshot.Revision, Branding: snapshot.Value})
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
		sameOriginPath := err == nil && parsed.IsAbs() == false && parsed.Host == "" && strings.HasPrefix(parsed.Path, "/") && !strings.HasPrefix(logoURL, "//") && !strings.Contains(logoURL, `\`)
		secureAbsolute := err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil
		if !sameOriginPath && !secureAbsolute {
			return settings.Branding{}, fmt.Errorf("logo_url must be a same-origin path or an absolute HTTPS URL without credentials")
		}
	}
	return settings.Branding{Title: title, LogoURL: logoURL}, nil
}
