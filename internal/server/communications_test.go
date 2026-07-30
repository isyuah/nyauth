package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/nyasharp/nyauth/internal/account"
	"github.com/nyasharp/nyauth/internal/audit"
	"github.com/nyasharp/nyauth/internal/session"
	"github.com/nyasharp/nyauth/internal/settings"
	"github.com/nyasharp/nyauth/pkg/models"
	"github.com/redis/go-redis/v9"
)

func TestEmailTemplatePreviewUsesSafeSampleDataAndFixedLink(t *testing.T) {
	manager := settings.NewManager(nil, settings.Branding{Title: "Example <Identity>"})
	server := &Server{settingsMgr: manager}
	email := account.DefaultEmailTemplateSettings()
	content := email.Templates[account.MessagePasswordReset]
	content.Body = "<strong>{{username}}</strong>"
	email.Templates[account.MessagePasswordReset] = content
	body, err := json.Marshal(emailTemplatePreviewRequest{TemplateID: account.MessagePasswordReset, Email: email})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	server.handlePreviewEmailTemplate(recorder, httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/email/preview", strings.NewReader(string(body))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response emailTemplatePreviewResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if strings.Contains(response.HTMLBody, "<strong>") || !strings.Contains(response.HTMLBody, "&lt;strong&gt;") {
		t.Fatalf("preview did not escape draft markup: %s", response.HTMLBody)
	}
	if !strings.Contains(response.HTMLBody, "https://example.invalid/account-action?token=preview-only") || strings.Contains(response.HTMLBody, "auth.example") {
		t.Fatalf("preview link is not the fixed inert sample: %s", response.HTMLBody)
	}
}

func TestPublicSiteBannerDefaultsToNoSiteBannerAndNoStore(t *testing.T) {
	server := &Server{settingsMgr: settings.NewManager(nil, settings.Branding{Title: "Nya"})}
	recorder := httptest.NewRecorder()
	server.handleSiteBanner(recorder, httptest.NewRequest(http.MethodGet, "/api/site-banner", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q", recorder.Code, recorder.Header().Get("Cache-Control"))
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response["site_banner"] != nil || len(response) != 1 {
		t.Fatalf("public response leaked inactive settings: %#v", response)
	}
}

func TestPublicSiteBannerExposesOnlyActivePublicFields(t *testing.T) {
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	start := now.Add(-time.Hour)
	end := now.Add(time.Hour)
	response := publicSiteBannerAt(settings.SiteBanner{
		Version: 7, Enabled: true, Severity: settings.SiteBannerSeverityWarning,
		Title: "Planned maintenance", Message: "Sign-in remains **available**. [Status](/status)",
		Dismissible: true,
		StartsAt:    &start, EndsAt: &end,
	}, now)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	body := string(encoded)
	for _, forbidden := range []string{"enabled", "starts_at", "revision", "email", "templates"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public site banner leaked %q: %s", forbidden, body)
		}
	}
	if response.SiteBanner == nil || response.SiteBanner.Version != 7 || response.NextChangeAt == nil || !response.NextChangeAt.Equal(end) {
		t.Fatalf("unexpected public site banner: %#v", response)
	}
	if !strings.Contains(response.SiteBanner.MessageHTML, "<strong>available</strong>") || !strings.Contains(response.SiteBanner.MessageHTML, `href="/status"`) {
		t.Fatalf("public site banner was not rendered safely: %#v", response.SiteBanner)
	}
}

func TestSiteBannerMarkdownPreviewRejectsUnsafeMarkup(t *testing.T) {
	server := &Server{settingsMgr: settings.NewManager(nil, settings.Branding{Title: "Nya"})}
	for _, test := range []struct {
		name string
		body string
		want int
	}{
		{name: "safe markdown", body: `{"message":"**planned** [status](/status)"}`, want: http.StatusOK},
		{name: "raw html", body: `{"message":"<script>alert(1)</script>"}`, want: http.StatusBadRequest},
		{name: "unsafe link", body: `{"message":"[open](javascript:alert(1))"}`, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/site-banner/preview", strings.NewReader(test.body))
			server.handlePreviewSiteBannerMarkdown(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestTemplateTestRecipientMustBeCurrentVerifiedAdministratorEmail(t *testing.T) {
	mini := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mini.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	manager := settings.NewManager(nil, settings.Branding{Title: "Nyauth"})
	server := &Server{
		settingsMgr:         manager,
		mailSettingsLimiter: NewMailSettingsLimiter(rdb, manager),
	}
	verifiedAt := time.Now().UTC().Add(-time.Hour)
	email := "admin@example.test"
	admin := &models.User{
		ID: uuid.New(), Username: "admin", Role: "admin",
		Status: models.UserStatusActive, Email: &email, EmailVerifiedAt: &verifiedAt,
	}
	body, err := json.Marshal(emailTemplateTestRequest{
		TemplateID: account.MessagePasswordReset,
		Recipient:  "other@example.test",
		Email:      account.DefaultEmailTemplateSettings(),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/admin/settings/communications/email/test", strings.NewReader(string(body)))
	request.RemoteAddr = "192.0.2.22:42000"
	ctx := context.WithValue(request.Context(), currentUserContextKey, admin)
	ctx = withAuthenticatedSession(ctx, &AuthenticatedSession{Data: &session.SessionData{
		UserID: admin.ID.String(), Username: admin.Username, AuthenticatedAt: time.Now().UTC(),
	}})
	ctx = audit.WithMutationAudit(ctx, audit.MutationAudit{
		Event: models.AuditMailTemplateTested, ActorID: admin.ID, ActorName: admin.Username,
		Result: "success", RiskLevel: "high",
	})
	recorder := httptest.NewRecorder()
	server.handleTestEmailTemplate(recorder, request.WithContext(ctx))
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "must match") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSiteBannerStreamLimitFailsBeforeStartingSSE(t *testing.T) {
	server := &Server{settingsMgr: settings.NewManager(nil, settings.Branding{Title: "Nya"})}
	server.siteBannerStreams.Store(maxSiteBannerEventStreams)
	recorder := httptest.NewRecorder()
	server.handleSiteBannerEvents(recorder, httptest.NewRequest(http.MethodGet, siteBannerEventsPath, nil))
	if recorder.Code != http.StatusTooManyRequests || recorder.Header().Get("Retry-After") != "30" {
		t.Fatalf("status=%d retry=%q body=%s", recorder.Code, recorder.Header().Get("Retry-After"), recorder.Body.String())
	}
}

func TestMailActionPublicURLMustRemainOnIssuerOrigin(t *testing.T) {
	for _, test := range []struct {
		left, right string
		want        bool
	}{
		{"https://auth.example.test/mail/path", "https://auth.example.test", true},
		{"https://AUTH.example.test", "https://auth.example.test/issuer", true},
		{"https://attacker.example.test", "https://auth.example.test", false},
		{"http://auth.example.test", "https://auth.example.test", false},
		{"https://user:secret@auth.example.test", "https://auth.example.test", false},
	} {
		if got := sameHTTPOrigin(test.left, test.right); got != test.want {
			t.Fatalf("sameHTTPOrigin(%q,%q)=%v want %v", test.left, test.right, got, test.want)
		}
	}
}
