package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	brandpalette "github.com/nyasharp/nyauth/internal/branding"
	"github.com/nyasharp/nyauth/internal/settings"
)

type brandingUpdateRequest struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Title            string `json:"title"`
	PrimaryColor     string `json:"primary_color"`
	PrimaryTextColor string `json:"primary_text_color"`
	LightLogoURL     string `json:"light_logo_url"`
	DarkLogoURL      string `json:"dark_logo_url"`
	FaviconURL       string `json:"favicon_url"`
}

type brandingSettingsResponse struct {
	Revision int64 `json:"revision"`
	settings.Branding
}

func (s *Server) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, s.settingsMgr.Branding())
}

func (s *Server) handleGetBrandingStylesheet(w http.ResponseWriter, _ *http.Request) {
	branding := s.settingsMgr.Branding()
	light, lightErr := brandpalette.NewPalette(branding.PrimaryColor, branding.PrimaryTextColor, false)
	dark, darkErr := brandpalette.NewPalette(branding.PrimaryColor, branding.PrimaryTextColor, true)
	if lightErr != nil || darkErr != nil {
		writeAPIError(w, http.StatusInternalServerError, "branding stylesheet is unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = fmt.Fprint(w, brandingStylesheet(light, dark))
}

func brandingStylesheet(light, dark brandpalette.Palette) string {
	var css strings.Builder
	css.WriteString(":root,[data-theme=\"light\"]{")
	writeBrandingCSSVariables(&css, light)
	css.WriteString("}[data-theme=\"dark\"]{")
	writeBrandingCSSVariables(&css, dark)
	css.WriteString("}")
	return css.String()
}

func writeBrandingCSSVariables(css *strings.Builder, palette brandpalette.Palette) {
	_, _ = fmt.Fprintf(css,
		"--nya-primary:%s;--nya-primary-rgb:%s;--nya-primary-hover:%s;--nya-primary-active:%s;"+
			"--nya-primary-soft:%s;--nya-primary-softer:%s;--nya-primary-border:%s;--nya-primary-contrast:%s;",
		palette.Primary, palette.RGB, palette.Hover, palette.Active,
		palette.Soft, palette.Softer, palette.Border, palette.Contrast,
	)
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
	branding, err := validateBranding(
		request.Title, request.PrimaryColor, request.PrimaryTextColor,
		request.LightLogoURL, request.DarkLogoURL, request.FaviconURL,
	)
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

func validateBranding(
	title, primaryColor, primaryTextColor, lightLogoURL, darkLogoURL, faviconURL string,
) (settings.Branding, error) {
	return settings.NormalizeBranding(settings.Branding{
		Title: title, PrimaryColor: primaryColor, PrimaryTextColor: primaryTextColor,
		LightLogoURL: lightLogoURL, DarkLogoURL: darkLogoURL, FaviconURL: faviconURL,
	})
}

func absoluteBrandingAssetURL(issuer, assetURL string) string {
	if assetURL == "" {
		return ""
	}
	asset, err := url.Parse(assetURL)
	if err != nil {
		return ""
	}
	if asset.IsAbs() {
		return asset.String()
	}
	base, err := url.Parse(issuer)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ""
	}
	return base.ResolveReference(asset).String()
}
